[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $EntraTenantId,   # GUID or tenant.onmicrosoft.com
  [Parameter(Mandatory)] [string] $EntraClientId,
  [Parameter(Mandatory)] [string] $Upn,        # expected sign-in (informational)
  [string] $OutFile = ".\delegated_refresh_token.txt"
)


function Get-InvokeRestErrorMessage {
  param([Parameter(Mandatory)] $ErrorRecord)

  if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
    return [string]$ErrorRecord.ErrorDetails.Message
  }

  return [string]$ErrorRecord.Exception.Message
}

$scope = "offline_access https://outlook.office.com/SMTP.Send"

# 1) Request device code
try {
  $dc = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$EntraTenantId/oauth2/v2.0/devicecode" `
    -Body @{
      client_id = $EntraClientId
      scope     = $scope
    }
} catch {
  $detail = Get-InvokeRestErrorMessage -ErrorRecord $_
  throw "Failed to start device-code flow for tenant '$EntraTenantId' and app '$EntraClientId'. API error: $detail"
}

Write-Information "" -InformationAction Continue
Write-Information "Sign in as: $Upn" -InformationAction Continue
Write-Information "Go to: $($dc.verification_uri)" -InformationAction Continue
Write-Information "Enter code: $($dc.user_code)" -InformationAction Continue
Write-Information "" -InformationAction Continue

# 2) Poll token endpoint
$tokenUri = "https://login.microsoftonline.com/$EntraTenantId/oauth2/v2.0/token"
$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)

while ((Get-Date) -lt $deadline) {

  $status = $null
  $tok = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    client_id   = $EntraClientId
    device_code = $dc.device_code
  } -SkipHttpErrorCheck -StatusCodeVariable status -ErrorAction SilentlyContinue

  if ($status -eq 200 -and $tok) {
    if ($tok.refresh_token) {
      try {
        Set-Content -LiteralPath $OutFile -Value $tok.refresh_token -NoNewline -Encoding ascii
      } catch {
        throw "Failed to write delegated refresh token to '$OutFile'. $_"
      }
      Write-Information "Saved refresh token to $OutFile" -InformationAction Continue
      Write-Information "Access token expires_in: $($tok.expires_in)" -InformationAction Continue
      return
    }

    Write-Warning "200 OK but no refresh_token returned:"
    $tok | ConvertTo-Json -Depth 6 | Write-Information -InformationAction Continue
    return
  }

  # When not 200, Invoke-RestMethod returns $null (because we used -ErrorAction SilentlyContinue)
  # So re-run once to fetch the error payload reliably as plain text using Invoke-WebRequest.
  $w = Invoke-WebRequest -Method Post -Uri $tokenUri -Body @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    client_id   = $EntraClientId
    device_code = $dc.device_code
  } -SkipHttpErrorCheck -ErrorAction SilentlyContinue

  if (-not $w) {
    throw "Device-code polling failed with no response."
  }

  $raw = $w.Content
  try {
    $body = $raw | ConvertFrom-Json
    $err  = $body.error
    $desc = $body.error_description
  } catch {
    $err  = "http_error_$($w.StatusCode)"
    $desc = $raw
  }

  Write-Verbose "Device-code poll: $err - $desc"

  switch ($err) {
    "authorization_pending" { Start-Sleep -Seconds ([int]$dc.interval); continue }
    "slow_down"             { Start-Sleep -Seconds ([int]$dc.interval + 5); continue }
    "expired_token"         { throw "Device code expired. Re-run bootstrap." }
    "access_denied"         { throw "Access denied (often admin approval/consent required). Check the browser page text." }
    default                 { throw "Unexpected error: $err - $desc" }
  }
}

throw "Timed out waiting for device authorization."