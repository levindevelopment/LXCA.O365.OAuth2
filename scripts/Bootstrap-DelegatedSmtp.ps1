param(
  [Parameter(Mandatory)] [string] $TenantId,   # GUID or tenant.onmicrosoft.com
  [Parameter(Mandatory)] [string] $ClientId,
  [Parameter(Mandatory)] [string] $Upn,        # expected sign-in (informational)
  [string] $OutFile = ".\delegated_refresh_token.txt"
)

$scope = "offline_access https://outlook.office.com/SMTP.Send"

# 1) Request device code
$dc = Invoke-RestMethod -Method Post `
  -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
  -Body @{
    client_id = $ClientId
    scope     = $scope
  }

Write-Host ""
Write-Host "Sign in as: $Upn"
Write-Host "Go to: $($dc.verification_uri)"
Write-Host "Enter code: $($dc.user_code)"
Write-Host ""

# 2) Poll token endpoint
$tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)

while ((Get-Date) -lt $deadline) {

  $status = $null
  $tok = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    client_id   = $ClientId
    device_code = $dc.device_code
  } -SkipHttpErrorCheck -StatusCodeVariable status -ErrorAction SilentlyContinue

  if ($status -eq 200 -and $tok) {
    if ($tok.refresh_token) {
      Set-Content -Path $OutFile -Value $tok.refresh_token -NoNewline -Encoding ascii
      Write-Host "Saved refresh token to $OutFile"
      Write-Host "Access token expires_in: $($tok.expires_in)"
      return
    }

    Write-Host "200 OK but no refresh_token returned:" -ForegroundColor Yellow
    $tok | ConvertTo-Json -Depth 6 | Write-Host
    return
  }

  # When not 200, Invoke-RestMethod returns $null (because we used -ErrorAction SilentlyContinue)
  # So re-run once to fetch the error payload reliably as plain text using Invoke-WebRequest.
  $w = Invoke-WebRequest -Method Post -Uri $tokenUri -Body @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    client_id   = $ClientId
    device_code = $dc.device_code
  } -SkipHttpErrorCheck -ErrorAction SilentlyContinue

  $raw = $w.Content
  try {
    $body = $raw | ConvertFrom-Json
    $err  = $body.error
    $desc = $body.error_description
  } catch {
    $err  = "http_error_$($w.StatusCode)"
    $desc = $raw
  }

  Write-Host "Device-code poll: $err - $desc" -ForegroundColor DarkGray

  switch ($err) {
    "authorization_pending" { Start-Sleep -Seconds ([int]$dc.interval); continue }
    "slow_down"             { Start-Sleep -Seconds ([int]$dc.interval + 5); continue }
    "expired_token"         { throw "Device code expired. Re-run bootstrap." }
    "access_denied"         { throw "Access denied (often admin approval/consent required). Check the browser page text." }
    default                 { throw "Unexpected error: $err - $desc" }
  }
}

throw "Timed out waiting for device authorization."