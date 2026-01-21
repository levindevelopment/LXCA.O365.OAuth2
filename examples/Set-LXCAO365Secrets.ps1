<#
.SYNOPSIS
  Creates an encrypted secrets file for LXCA + Entra client secret (Windows DPAPI).

.DESCRIPTION
  Prompts for the LXCA password and Entra client secret and writes them to an XML file
  using Export-Clixml with SecureString.

  IMPORTANT:
  - This encryption is tied to the *current Windows user account*.
  - The Scheduled Task must run as the same account that created the file.

.PARAMETER OutFile
  Output path for the encrypted secrets file (XML).

.EXAMPLE
  pwsh .\Set-LXCAO365Secrets.ps1 -OutFile .\lxca-o365-rotate.secrets.xml
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string] $OutFile
)

$lxcaPass     = Read-Host "Enter LXCA password" -AsSecureString
$clientSecret = Read-Host "Enter Entra Client Secret VALUE" -AsSecureString

$payload = [pscustomobject]@{
  LxcaPass     = $lxcaPass
  ClientSecret = $clientSecret
  CreatedUtc   = (Get-Date).ToUniversalTime().ToString("s") + "Z"
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

$payload | Export-Clixml -Path $OutFile -Force
Write-Host "Wrote encrypted secrets to: $OutFile"
Write-Host "NOTE: File can only be decrypted by the same Windows user account."
