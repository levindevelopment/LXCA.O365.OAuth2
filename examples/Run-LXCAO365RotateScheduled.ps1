<#
.SYNOPSIS
  Task Scheduler-friendly wrapper to rotate the LXCA SMTP OAuth2 token.

.DESCRIPTION
  Reads non-secret configuration from JSON and secrets (SecureString) from an encrypted XML file.
  Invokes scripts/Rotate-LXCA-O365SmtpToken.ps1 without placing secrets directly in a scheduled task argument string.

.PARAMETER ConfigPath
  Path to JSON config (non-secrets).

.PARAMETER SecretsPath
  Path to encrypted secrets XML created by Set-LXCAO365Secrets.ps1.

.PARAMETER ScriptPath
  Path to Rotate-LXCA-O365SmtpToken.ps1 (defaults relative to this wrapper).

.EXAMPLE
  pwsh .\Run-LXCAO365RotateScheduled.ps1 -ConfigPath .\lxca-o365-rotate.config.json -SecretsPath .\lxca-o365-rotate.secrets.xml
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ConfigPath,
  [Parameter(Mandatory)] [string] $SecretsPath,
  [string] $ScriptPath = (Join-Path $PSScriptRoot "..\scripts\Rotate-LXCA-O365SmtpToken.ps1")
)

function Assert-PS7 {
  if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7+ is required. Current: $($PSVersionTable.PSVersion)"
  }
}

function ConvertFrom-SecureStringToPlain {
  param([Parameter(Mandatory)][SecureString]$Secure)
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

Assert-PS7

if (-not (Test-Path $ConfigPath))  { throw "Config not found: $ConfigPath" }
if (-not (Test-Path $SecretsPath)) { throw "Secrets not found: $SecretsPath" }
if (-not (Test-Path $ScriptPath))  { throw "Rotator script not found: $ScriptPath" }

$config  = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$secrets = Import-Clixml -Path $SecretsPath

$lxcaPassPlain     = ConvertFrom-SecureStringToPlain -Secure $secrets.LxcaPass
$clientSecretPlain = ConvertFrom-SecureStringToPlain -Secure $secrets.ClientSecret

foreach ($k in @("LxcaBaseUrl","LxcaUser","MonitorId","TenantId","ClientId","SmtpUser")) {
  if (-not $config.$k) { throw "Missing required config key: $k" }
}

$descPrefix = if ($config.DescriptionPrefix) { $config.DescriptionPrefix } else { "O365 SMTP token rotated" }

& pwsh -NoProfile -ExecutionPolicy Bypass -File $ScriptPath `
  -LxcaBaseUrl $config.LxcaBaseUrl `
  -LxcaUser $config.LxcaUser -LxcaPass $lxcaPassPlain `
  -MonitorId $config.MonitorId `
  -RotateToken `
  -TenantId $config.TenantId `
  -ClientId $config.ClientId `
  -ClientSecret $clientSecretPlain `
  -SmtpUser $config.SmtpUser `
  -DescriptionPrefix $descPrefix

$exit = $LASTEXITCODE
if ($exit -ne 0) { throw "Rotator script failed with exit code $exit" }
