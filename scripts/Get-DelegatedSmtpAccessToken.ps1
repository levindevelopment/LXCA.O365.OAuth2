[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $EntraTenantId,
  [Parameter(Mandatory)] [string] $EntraClientId,
  [string] $RefreshTokenPath = ".\delegated_refresh_token.txt",
  [string] $OutTokenPath = (Join-Path $env:TEMP "o365_token.jwt"),
  [switch] $ShowClaims
)

function Get-InvokeRestErrorMessage {
  param([Parameter(Mandatory)] $ErrorRecord)

  if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
    return [string]$ErrorRecord.ErrorDetails.Message
  }

  return [string]$ErrorRecord.Exception.Message
}

try {
  $refresh = (Get-Content -LiteralPath $RefreshTokenPath -Raw).Trim()
} catch {
  throw "Failed to read refresh token from '$RefreshTokenPath'. $_"
}

if ([string]::IsNullOrWhiteSpace($refresh)) {
  throw "Refresh token file '$RefreshTokenPath' is empty."
}

try {
  $tok = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$EntraTenantId/oauth2/v2.0/token" `
    -Body @{
      client_id     = $EntraClientId
      grant_type    = "refresh_token"
      refresh_token = $refresh
      scope         = "offline_access https://outlook.office.com/SMTP.Send"
    }
} catch {
  $detail = Get-InvokeRestErrorMessage -ErrorRecord $_
  throw "Failed to acquire delegated SMTP access token for tenant '$EntraTenantId' and app '$EntraClientId'. API error: $detail"
}

# Write access token to file (no console dump)
try {
  $tok.access_token | Set-Content -LiteralPath $OutTokenPath -NoNewline -Encoding ascii
} catch {
  throw "Failed to write delegated SMTP access token to '$OutTokenPath'. $_"
}

# Print only safe metadata
Write-Information "Wrote access token to: $OutTokenPath" -InformationAction Continue
Write-Verbose "token_type: $($tok.token_type)"
Write-Information "expires_in: $($tok.expires_in) seconds" -InformationAction Continue

if ($ShowClaims) {
  function ConvertFrom-JwtPayload {
    param([Parameter(Mandatory)][string]$Jwt)
    $p = $Jwt.Split('.')[1].Replace('-','+').Replace('_','/')
    switch ($p.Length % 4) { 2 {$p+='=='} 3 {$p+='='} }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
    $json | ConvertFrom-Json
  }

  try {
    $claims = ConvertFrom-JwtPayload $tok.access_token
  } catch {
    throw "Failed to decode JWT claims from delegated SMTP access token. $_"
  }
  $claims | Select-Object aud, iss, tid, scp, roles, exp | Format-List
}
