param(
  [Parameter(Mandatory)] [string] $TenantId,
  [Parameter(Mandatory)] [string] $ClientId,
  [string] $RefreshTokenPath = ".\delegated_refresh_token.txt",
  [string] $OutTokenPath = (Join-Path $env:TEMP "o365_token.jwt"),
  [switch] $ShowClaims
)

$refresh = Get-Content $RefreshTokenPath -Raw

$tok = Invoke-RestMethod -Method Post `
  -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
  -Body @{
    client_id     = $ClientId
    grant_type    = "refresh_token"
    refresh_token = $refresh
    scope         = "offline_access https://outlook.office.com/SMTP.Send"
  }

# Write access token to file (no console dump)
$tok.access_token | Set-Content -NoNewline -Encoding ascii $OutTokenPath

# Print only safe metadata
Write-Host "Wrote access token to: $OutTokenPath"
Write-Host "token_type: $($tok.token_type)"
Write-Host "expires_in: $($tok.expires_in) seconds"

if ($ShowClaims) {
  function Decode-JwtPayload {
    param([Parameter(Mandatory)][string]$Jwt)
    $p = $Jwt.Split('.')[1].Replace('-','+').Replace('_','/')
    switch ($p.Length % 4) { 2 {$p+='=='} 3 {$p+='='} }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
    $json | ConvertFrom-Json
  }

  $claims = Decode-JwtPayload $tok.access_token
  $claims | Select-Object aud, iss, tid, scp, roles, exp | Format-List
}