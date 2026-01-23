<#
.SYNOPSIS
  Task Scheduler wrapper to run Rotate-LXCA-O365SmtpToken.ps1 with secrets kept off the command line.

.DESCRIPTION
  Reads:
    - Config JSON (non-secret)
    - Secrets XML (DPAPI-encrypted strings, CurrentUser)
  Then invokes the production script with the right auth mode.

  For DelegatedRefresh:
    - Decrypts the delegated refresh token
    - Writes it to a temp file with restricted ACL
    - Passes -RefreshTokenPath to the production script
    - Deletes the temp file afterwards

.NOTES
  This wrapper is Windows-focused (DPAPI). For Linux, use a vault or strict file ACLs.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string] $ConfigPath,
  [Parameter(Mandatory)][string] $SecretsPath
)

function DpapiStringToSecureString {
  param([Parameter(Mandatory)][string] $Dpapi)
  return ConvertTo-SecureString -String $Dpapi
}

function SecureStringToPlainText {
  param([Parameter(Mandatory)][Security.SecureString] $Secure)
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "ConfigPath not found: $ConfigPath" }
if (-not (Test-Path -LiteralPath $SecretsPath)) { throw "SecretsPath not found: $SecretsPath" }

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$secrets = Import-Clixml -LiteralPath $SecretsPath

$authMode = if ($config.AuthMode) { [string]$config.AuthMode } else { "AppOnly" }

$scriptPath = if ($config.ScriptPath) { [string]$config.ScriptPath } else { "..\scripts\Rotate-LXCA-O365SmtpToken.ps1" }
if (-not (Test-Path -LiteralPath $scriptPath)) {
  # Try relative to the wrapper location
  $scriptPath2 = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath $scriptPath
  if (Test-Path -LiteralPath $scriptPath2) { $scriptPath = $scriptPath2 }
  else { throw "Rotate script not found at ScriptPath '$scriptPath' (or relative '$scriptPath2')." }
}

$lxcaPass = SecureStringToPlainText (DpapiStringToSecureString $secrets.LxcaPassDpapi)

$commonArgs = @(
  "-NoProfile",
  "-ExecutionPolicy","Bypass",
  "-File", $scriptPath,
  "-RotateToken",
  "-AuthMode", $authMode,
  "-LxcaBaseUrl", [string]$config.LxcaBaseUrl,
  "-LxcaUser", [string]$config.LxcaUser,
  "-LxcaPass", $lxcaPass,
  "-MonitorId", [string]$config.MonitorId,
  "-TenantId", [string]$config.TenantId,
  "-ClientId", [string]$config.ClientId,
  "-SmtpUser", [string]$config.SmtpUser
)

if ($config.DescriptionPrefix) {
  $commonArgs += @("-DescriptionPrefix", [string]$config.DescriptionPrefix)
}

$tmpRtPath = $null
try {
  if ($authMode -ieq "AppOnly") {
    if (-not $secrets.ClientSecretDpapi) { throw "Secrets file missing ClientSecretDpapi. Re-run Set-LXCAO365Secrets.ps1 -IncludeClientSecret" }
    $clientSecret = SecureStringToPlainText (DpapiStringToSecureString $secrets.ClientSecretDpapi)
    $commonArgs += @("-ClientSecret", $clientSecret)
  }
  elseif ($authMode -ieq "DelegatedRefresh") {
    if (-not $secrets.DelegatedRefreshTokenDpapi) { throw "Secrets file missing DelegatedRefreshTokenDpapi. Re-run Set-LXCAO365Secrets.ps1 -IncludeDelegatedRefreshToken" }
    $rt = SecureStringToPlainText (DpapiStringToSecureString $secrets.DelegatedRefreshTokenDpapi)

    $tmpRtPath = Join-Path $env:TEMP ("delegated_refresh_token_" + [guid]::NewGuid().ToString("N") + ".txt")
    Set-Content -LiteralPath $tmpRtPath -Value $rt -NoNewline -Encoding ascii

    # lock down ACL (best effort)
    try {
      $acl = Get-Acl -LiteralPath $tmpRtPath
      $acl.SetAccessRuleProtection($true,$false)
      $me = [System.Security.Principal.NTAccount]("$env:USERDOMAIN\$env:USERNAME")
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me,"FullControl","Allow")
      $acl.SetAccessRule($rule)
      Set-Acl -LiteralPath $tmpRtPath -AclObject $acl
    } catch { }

    $commonArgs += @("-RefreshTokenPath", $tmpRtPath)
  }
  else {
    throw "Unsupported AuthMode '$authMode'. Use 'AppOnly' or 'DelegatedRefresh'."
  }

  & pwsh @commonArgs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

} finally {
  if ($tmpRtPath -and (Test-Path -LiteralPath $tmpRtPath)) {
    Remove-Item -LiteralPath $tmpRtPath -Force -ErrorAction SilentlyContinue
  }
}
