# NOTE: This is a SANITIZED template version. Replace placeholders (<...>) with your values.
<#
.SYNOPSIS
Lists Lenovo XClarity Administrator (LXCA) event monitors (forwarders) and rotates Microsoft 365 OAuth2 SMTP tokens for an email forwarder.

.DESCRIPTION
This script uses the LXCA REST API (session cookie + CSRF header) to:
  - List event monitors: GET /events/monitors
  - Rotate an OAuth2 token for a specific email_alert forwarder:
      * GET /events/monitors/{id}
      * Update ONLY: authenticationEmail, usernameEmail, passwordEmail, description
      * PUT /events/monitors/{id}

Notes on LXCA secrets:
  - When you GET a monitor, LXCA returns passwordEmail as an internal secret reference (GUID/UUID).
  - When you PUT a new token into passwordEmail, LXCA overwrites the stored secret value behind that reference.
    The GUID may remain stable across updates (this is normal).

DEPENDENCIES
  - PowerShell 7.2.24+ (PSEdition "Core")
  - Network access to:
      * LXCA REST API ($LxcaBaseUrl)
      * Microsoft Entra ID token endpoint (login.microsoftonline.com)

NOTES
  - This script intentionally uses raw LXCA REST endpoints (Invoke-RestMethod) instead of the LXCAPSTool module to keep dependencies minimal and support offline/unattended scheduled execution.

SECURITY
  - Prefer -LxcaCredential (PSCredential) over -LxcaPass.
  - For Task Scheduler, prefer: SecretManagement, Windows Credential Manager, or a DPAPI-encrypted file.

EXAMPLES
  # Get all monitors (preferred)
  .\Rotate-LXCA-O365SmtpToken.ps1 -LxcaBaseUrl "https://<lxca-host-or-ip>" -LxcaCredential (Get-Credential) -ListMonitors

  # Backward-compatibility mode (discouraged)
  .\Rotate-LXCA-O365SmtpToken.ps1 -LxcaBaseUrl "https://<lxca-host-or-ip>" -LxcaUser admin -LxcaPass "*****" -ListMonitors

  # Rotate token for a specific monitor id (updates token fields + description only)
  .\Rotate-LXCA-O365SmtpToken.ps1 `
    -LxcaBaseUrl "https://<lxca-host-or-ip>" -LxcaCredential (Get-Credential) `
    -RotateToken -MonitorId "<monitor-id>" `
    -TenantId "<tenant-guid>" -ClientId "<app-guid>" -ClientSecret "<secret>" `
    -SmtpUser "alerts@yourdomain.com"

  # Scheduled Task invocation (pwsh.exe)
  # pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Rotate-LXCA-O365SmtpToken.ps1" <args...>
#>

[CmdletBinding()]
param(
  # --- LXCA ---
  # NOTE: These are NOT marked Mandatory so the file can be dot-sourced to import functions.
  # When running as a script (not dot-sourced), parameter validation is enforced in Main.
  [string] $LxcaBaseUrl,
  [PSCredential] $LxcaCredential,

  # Backward compatibility (discouraged)
  [string] $LxcaUser,
  [string] $LxcaPass,

  # --- Actions ---
  [switch] $ListMonitors,
  [switch] $EmailOnly,
  [string] $NameLike,

  [switch] $RotateToken,
  [string] $MonitorId,

  # --- O365 / Entra (required only when -RotateToken) ---
  [string] $TenantId,
  [string] $ClientId,
  [string] $ClientSecret,
  [ValidateSet("AppOnly","DelegatedRefresh")] [string] $AuthMode = "AppOnly",
  [string] $RefreshTokenPath,
  [string] $SmtpUser,

  # --- Stamp ---
  [string] $DescriptionPrefix = "O365 token rotated"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Environment {
  $v = $PSVersionTable.PSVersion
  if ($PSVersionTable.PSEdition -ne "Core") {
    throw "This script must run in PowerShell 7+ (pwsh). Current: $($PSVersionTable.PSEdition) $v"
  }
  if ($v -lt [version]"7.2.24") {
    throw "PowerShell 7.2.24+ required. Current: $v"
  }
}

function Get-O365AccessToken_AppOnly {
  param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $ClientId,
    [Parameter(Mandatory)] [string] $ClientSecret
  )

  $body = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
    scope         = "https://outlook.office365.com/.default"
  }

  $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body

  [pscustomobject]@{
    access_token = $resp.access_token
    expires_in   = [int]$resp.expires_in
    expires_at   = (Get-Date).ToUniversalTime().AddSeconds([int]$resp.expires_in)
  }
}

function Get-O365AccessToken_DelegatedRefresh {
  param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $ClientId,
    [Parameter(Mandatory)] [string] $RefreshTokenPath
  )

  if (-not (Test-Path -LiteralPath $RefreshTokenPath)) {
    throw "Refresh token file not found: $RefreshTokenPath"
  }

  $refresh = Get-Content -LiteralPath $RefreshTokenPath -Raw

  $body = @{
    client_id     = $ClientId
    grant_type    = "refresh_token"
    refresh_token = $refresh
    scope         = "offline_access https://outlook.office.com/SMTP.Send"
  }

  $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body

  [pscustomobject]@{
    access_token = $resp.access_token
    expires_in   = [int]$resp.expires_in
    expires_at   = (Get-Date).ToUniversalTime().AddSeconds([int]$resp.expires_in)
  }
}

function ConvertTo-PlainText {
  param([Parameter(Mandatory)] [Security.SecureString] $Secure)
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Connect-Lxca {
  <#
    .SYNOPSIS
    Logs into LXCA and returns a connection object (session cookies + CSRF header + baseUrl).

    .NOTES
    This is safe to use in scheduled tasks (pair with Disconnect-Lxca in finally).
  #>
  param(
    [Parameter(Mandatory)] [string] $BaseUrl,
    [Parameter(Mandatory)] [PSCredential] $Credential
  )

  $passwordPlain = ConvertTo-PlainText -Secure $Credential.Password
  try {
    $loginBody = @{ UserId = $Credential.UserName; password = $passwordPlain } | ConvertTo-Json
    $null = Invoke-RestMethod -Method Post -Uri ($BaseUrl.TrimEnd("/") + "/sessions") `
      -ContentType "application/json; charset=UTF-8" -Body $loginBody -SessionVariable s -SkipCertificateCheck
  }
  finally {
    $passwordPlain = $null
  }

  $cookieHeader = $s.Cookies.GetCookieHeader($BaseUrl)
  if ($cookieHeader -match 'csrf=([^;]+)') { $csrf = $Matches[1] } else { throw "No csrf cookie in: $cookieHeader" }

  $headers = @{
    "Accept"           = "application/json"
    "Content-Type"     = "application/json; charset=UTF-8"
    "X-Csrf-token"     = $csrf
    "X-NOT-USER-INPUT" = "checkSession"
  }

  return [pscustomobject]@{ BaseUrl = $BaseUrl; Session = $s; Headers = $headers }
}

function Invoke-LxcaJson {
  param(
    [Parameter(Mandatory)] [pscustomobject] $Conn,
    [Parameter(Mandatory)] [ValidateSet("GET","POST","PUT","DELETE")] [string] $Method,
    [Parameter(Mandatory)] [string] $Path,
    $Body = $null
  )

  if (-not $Conn.BaseUrl -or -not $Conn.Session -or -not $Conn.Headers) {
    throw "Not connected. Call Connect-Lxca first and pass the returned object as -Conn."
  }

  $uri = ($Conn.BaseUrl.TrimEnd("/")) + $Path

  $p = @{
    Method               = $Method
    Uri                  = $uri
    WebSession           = $Conn.Session
    Headers              = $Conn.Headers
    SkipCertificateCheck = $true
    ErrorAction          = "Stop"
  }

  if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 30) }

  Invoke-RestMethod @p
}

function Get-LxcaMonitor {
  param(
    [Parameter(Mandatory)] [pscustomobject] $Conn,
    [switch] $EmailOnly,
    [string] $NameLike
  )

  $monitors = Invoke-LxcaJson -Conn $Conn -Method GET -Path "/events/monitors"

  if ($EmailOnly) { $monitors = $monitors | Where-Object { $_.protocol -eq "email_alert" } }
  if ($NameLike)  { $monitors = $monitors | Where-Object { $_.name -like "*$NameLike*" } }

  $monitors |
    Sort-Object protocol, name |
    Select-Object id, name, protocol, enable, ipAddress, port, authenticationEmail, usernameEmail, description |
    Format-Table -AutoSize
}

function Disconnect-Lxca {
  <#
    .SYNOPSIS
    Logs out of LXCA (closes the session) to avoid session exhaustion.
  #>
  param([Parameter(Mandatory)] [pscustomobject] $Conn)
  try {
    # Some LXCA builds accept DELETE /sessions; others ignore it.
    Invoke-LxcaJson -Conn $Conn -Method DELETE -Path "/sessions" | Out-Null
  } catch {
    # Best effort.
    Write-Warning ("Best-effort LXCA logout failed for {0}: {1}" -f $Conn.BaseUrl, $_.Exception.Message)
  }
}

function Update-LxcaToken {
  [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
  param(
    [Parameter(Mandatory)] [pscustomobject] $Conn,
    [Parameter(Mandatory)] [string] $MonitorId,
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $ClientId,
    [string] $ClientSecret,
    [ValidateSet("AppOnly","DelegatedRefresh")] [string] $AuthMode = "AppOnly",
    [string] $RefreshTokenPath,
    [Parameter(Mandatory)] [string] $SmtpUser,
    [string] $DescriptionPrefix = "O365 token rotated"
  )

  # Validate required params for token rotation
  foreach ($pair in @(
    @{Name="MonitorId"; Val=$MonitorId},
    @{Name="TenantId";  Val=$TenantId},
    @{Name="ClientId";  Val=$ClientId},
    @{Name="SmtpUser";  Val=$SmtpUser}
  )) {
    if ([string]::IsNullOrWhiteSpace([string]$pair.Val)) { throw "Missing -$($pair.Name) (required for -RotateToken)." }
  }

  if ($AuthMode -eq "AppOnly") {
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { throw "Missing -ClientSecret (required for -RotateToken -AuthMode AppOnly)." }
  } elseif ($AuthMode -eq "DelegatedRefresh") {
    if ([string]::IsNullOrWhiteSpace($RefreshTokenPath)) { throw "Missing -RefreshTokenPath (required for -RotateToken -AuthMode DelegatedRefresh)." }
  } else {
    throw "Unsupported AuthMode: $AuthMode"
  }

  $tok = if ($AuthMode -eq "DelegatedRefresh") {
    Get-O365AccessToken_DelegatedRefresh -TenantId $TenantId -ClientId $ClientId -RefreshTokenPath $RefreshTokenPath
  } else {
    Get-O365AccessToken_AppOnly -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
  }
  Write-Information ("Minted O365 token ({0}); expires UTC: {1}" -f $AuthMode, $tok.expires_at) -InformationAction Continue

  $m = Invoke-LxcaJson -Conn $Conn -Method GET -Path "/events/monitors/$MonitorId"

  # Only touch OAuth fields + description stamp (do NOT touch other forwarder settings)
  $m.authenticationEmail = "oauth2"
  $m.usernameEmail       = $SmtpUser
  $m.passwordEmail       = $tok.access_token

  $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $m.description = "$DescriptionPrefix $stamp"

  if (-not $PSCmdlet.ShouldProcess("LXCA monitor $MonitorId", "Rotate O365 SMTP OAuth2 token and update monitor fields")) {
    Write-Verbose "Skipped monitor update due to WhatIf/Confirm response."
    return
  }

  Invoke-LxcaJson -Conn $Conn -Method PUT -Path "/events/monitors/$MonitorId" -Body $m | Out-Null

  $after = Invoke-LxcaJson -Conn $Conn -Method GET -Path "/events/monitors/$MonitorId"
  [pscustomobject]@{
    Id            = $after.id
    Name          = $after.name
    Protocol      = $after.protocol
    Enabled       = $after.enable
    Auth          = $after.authenticationEmail
    UsernameEmail = $after.usernameEmail
    PasswordEmail = $after.passwordEmail   # GUID ref (secret id)
    Description   = $after.description
  } | Format-List
}

function ConvertTo-SecureStringFromPlainText {
  param([Parameter(Mandatory)] [string] $PlainText)

  $secure = [Security.SecureString]::new()
  foreach ($char in $PlainText.ToCharArray()) {
    $secure.AppendChar($char)
  }
  $secure.MakeReadOnly()
  return $secure
}

function Get-LxcaCredential {
  param(
    [PSCredential] $LxcaCredential,
    [string] $LxcaUser,
    [string] $LxcaPass
  )

  if ($null -ne $LxcaCredential) { return $LxcaCredential }

  if ([string]::IsNullOrWhiteSpace($LxcaUser) -or [string]::IsNullOrWhiteSpace($LxcaPass)) {
    throw "Missing LXCA credentials. Provide -LxcaCredential (preferred), or legacy -LxcaUser and -LxcaPass."
  }

  Write-Warning "Using legacy -LxcaUser/-LxcaPass plaintext parameters. Prefer -LxcaCredential."
  $securePass = ConvertTo-SecureStringFromPlainText -PlainText $LxcaPass
  return [PSCredential]::new($LxcaUser, $securePass)
}

function Main {
  Assert-Environment

  if ([string]::IsNullOrWhiteSpace($LxcaBaseUrl)) {
    throw "Missing LXCA base URL. Provide -LxcaBaseUrl."
  }
  if (-not $ListMonitors -and -not $RotateToken) {
    throw "No action specified. Use -ListMonitors or -RotateToken."
  }

  $conn = $null
  $credential = Get-LxcaCredential -LxcaCredential $LxcaCredential -LxcaUser $LxcaUser -LxcaPass $LxcaPass
  try {
    $conn = Connect-Lxca -BaseUrl $LxcaBaseUrl -Credential $credential

    if ($ListMonitors) {
      Get-LxcaMonitor -Conn $conn -EmailOnly:$EmailOnly -NameLike $NameLike
      return
    }
    if ($RotateToken) {
      Update-LxcaToken -Conn $conn -MonitorId $MonitorId -TenantId $TenantId -ClientId $ClientId `
        -ClientSecret $ClientSecret -AuthMode $AuthMode -RefreshTokenPath $RefreshTokenPath `
        -SmtpUser $SmtpUser -DescriptionPrefix $DescriptionPrefix
      return
    }
  } finally {
    if ($null -ne $conn) { Disconnect-Lxca -Conn $conn }
  }
}

# If dot-sourced, only load functions (no execution).
if ($MyInvocation.InvocationName -ne '.') {
  Main
}
