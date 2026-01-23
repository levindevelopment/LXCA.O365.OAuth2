<# 
.SYNOPSIS
  Creates/updates an encrypted secrets file (DPAPI) for the LXCA→M365 SMTP OAuth2 token rotator.

.DESCRIPTION
  Stores secrets using ConvertFrom-SecureString (DPAPI, CurrentUser). The scheduled task MUST run
  under the same Windows user profile that created this file.

  Secrets supported:
    - LXCA password (required)
    - Entra client secret (AppOnly mode)
    - Delegated refresh token (DelegatedRefresh mode)

.NOTES
  Store output outside source control. Add to .gitignore.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string] $OutFile,

  [switch] $IncludeClientSecret,
  [switch] $IncludeDelegatedRefreshToken,

  # Preferred for delegated: point to the refresh token file produced by scripts/Bootstrap-DelegatedSmtp.ps1
  [string] $DelegatedRefreshTokenPath
)

function Read-SecretSecureString {
  param(
    [Parameter(Mandatory)][string] $Prompt
  )
  return Read-Host -Prompt $Prompt -AsSecureString
}

function SecureStringToDpapiString {
  param([Parameter(Mandatory)][Security.SecureString] $Secure)
  return ConvertFrom-SecureString -SecureString $Secure
}

function PlainTextToSecureString {
  param([Parameter(Mandatory)][string] $Text)
  $sec = New-Object Security.SecureString
  foreach ($c in $Text.ToCharArray()) { $sec.AppendChar($c) }
  $sec.MakeReadOnly()
  return $sec
}

$secrets = [ordered]@{
  SchemaVersion = 1
  CreatedUtc    = (Get-Date).ToUniversalTime().ToString("o")
  # Encrypted payloads (DPAPI CurrentUser)
  LxcaPassDpapi = $null
  ClientSecretDpapi = $null
  DelegatedRefreshTokenDpapi = $null
}

# Always required
$lxcaPass = Read-SecretSecureString -Prompt "Enter LXCA password"
$secrets.LxcaPassDpapi = SecureStringToDpapiString $lxcaPass

if ($IncludeClientSecret) {
  $clientSecret = Read-SecretSecureString -Prompt "Enter Entra client secret VALUE"
  $secrets.ClientSecretDpapi = SecureStringToDpapiString $clientSecret
}

if ($IncludeDelegatedRefreshToken) {
  if ($DelegatedRefreshTokenPath) {
    if (-not (Test-Path -LiteralPath $DelegatedRefreshTokenPath)) {
      throw "DelegatedRefreshTokenPath not found: $DelegatedRefreshTokenPath"
    }
    $raw = (Get-Content -LiteralPath $DelegatedRefreshTokenPath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "DelegatedRefreshTokenPath is empty." }
    $rtSec = PlainTextToSecureString -Text $raw
  } else {
    Write-Host "Paste delegated refresh token (will not echo), then press Enter." -ForegroundColor Yellow
    $rtSec = Read-SecretSecureString -Prompt "Delegated refresh token"
  }
  $secrets.DelegatedRefreshTokenDpapi = SecureStringToDpapiString $rtSec
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

$secrets | Export-Clixml -LiteralPath $OutFile
Write-Host "Wrote secrets to: $OutFile"
Write-Host "DPAPI scope: CurrentUser (scheduled task must run under same user profile)."
