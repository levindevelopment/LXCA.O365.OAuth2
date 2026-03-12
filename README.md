# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repository provides PowerShell 7 automation to rotate OAuth2 bearer tokens used by Lenovo XClarity Administrator (LXCA) email alert forwarders configured for SMTP OAuth2 (XOAUTH2).

## Architecture (current)

There are now **three production scripts**:

- `scripts/Rotate-LXCA-O365SmtpToken.ps1`  
  Core engine: lists monitors and rotates tokens through LXCA REST APIs.
- `scripts/Set-LXCAO365Secrets.ps1`  
  Creates a DPAPI-protected secrets file for unattended runs.
- `scripts/Run-LXCAO365RotateScheduled.ps1`  
  Wrapper for scheduled execution; loads secrets/config and invokes the rotate script.

`examples/lxca-o365-rotate.config.json` is a non-secret config template used by the wrapper.

## Security model

- Preferred LXCA auth input is `-LxcaCredential` (`PSCredential`) on `Rotate-LXCA-O365SmtpToken.ps1`.
- Legacy `-LxcaUser/-LxcaPass` is still accepted for backward compatibility, but discouraged.
- For unattended production, use the wrapper + DPAPI secrets workflow so LXCA password is not passed as a plaintext command-line argument.

## Requirements

- PowerShell 7.2.24+
- Network access from the automation host to:
  - LXCA HTTPS endpoint
  - `https://login.microsoftonline.com`
  - `smtp.office365.com:587` (for SMTP validation/use)

## Manual validation workflow (non-scheduled)

Use this first to validate connectivity and monitor selection.

### Discover monitor IDs

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential (Get-Credential) `
  -ListMonitors
```

### Rotate token (AppOnly)

```powershell
$cred = Get-Credential

pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -AuthMode AppOnly `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential $cred `
  -RotateToken `
  -MonitorId "<monitor-id>" `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-guid>" `
  -ClientSecret "<secret>" `
  -SmtpUser "alerts@yourdomain.com" `
  -DescriptionPrefix "O365 SMTP token rotated"
```

## Unattended production workflow (scheduled)

### 1) Create encrypted secrets (run once as task identity)

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeClientSecret
```

For delegated refresh mode, include:

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeDelegatedRefreshToken `
  -DelegatedRefreshTokenPath ./delegated_refresh_token.txt
```

### 2) Create config file (non-secret)

Start from `examples/lxca-o365-rotate.config.json` and fill in your values.

### 3) Test wrapper interactively

```powershell
pwsh ./scripts/Run-LXCAO365RotateScheduled.ps1 `
  -ConfigPath ./examples/lxca-o365-rotate.config.json `
  -SecretsPath ./secrets/lxca-o365-rotate.secrets.xml
```

### 4) Task Scheduler action

Program/script:
- `C:\Program Files\PowerShell\7\pwsh.exe`

Arguments example:

```text
-NoProfile -ExecutionPolicy Bypass -File "C:\Path\scripts\Run-LXCAO365RotateScheduled.ps1" -ConfigPath "C:\Path\examples\lxca-o365-rotate.config.json" -SecretsPath "C:\Path\secrets\lxca-o365-rotate.secrets.xml"
```

Recommended cadence: every 45–55 minutes.

## Delegated bootstrap helper

If you are using delegated refresh mode, use:

- `scripts/Bootstrap-DelegatedSmtp.ps1`
- `scripts/Get-DelegatedSmtpAccessToken.ps1`

The bootstrap script obtains a delegated refresh token via device code flow.

## Notes

- LXCA returns `passwordEmail` as a secret reference/GUID when reading monitors.
- Updating `passwordEmail` with a new bearer token rotates the secret value behind that reference.
- Keep secrets files out of source control.
