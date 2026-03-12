# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repository provides PowerShell 7 automation to rotate OAuth2 bearer tokens used by Lenovo XClarity Administrator (LXCA) email alert forwarders configured with SMTP OAuth2 (XOAUTH2).

The intent is safe, repeatable token rotation without manual LXCA GUI changes.

There are now **three production scripts**:

## Production architecture

This implementation now has three first-class operational scripts:

- `scripts/Rotate-LXCA-O365SmtpToken.ps1`  
  Core engine (LXCA API login, monitor list/get/put, token update).
- `scripts/Set-LXCAO365Secrets.ps1`  
  Creates DPAPI-encrypted secrets XML for unattended execution.
- `scripts/Run-LXCAO365RotateScheduled.ps1`  
  Scheduled-task wrapper that reads config + secrets and invokes the core engine.

Template config:

- `examples/lxca-o365-rotate.config.json` (non-secret)

---

## What the core script does

`Rotate-LXCA-O365SmtpToken.ps1` can:

1. Authenticate to LXCA (`POST /sessions`)
2. List monitors (`GET /events/monitors`)
3. Rotate one email monitor token (`GET /events/monitors/{id}` + `PUT /events/monitors/{id}`)
4. Update only OAuth-related monitor fields:
   - `authenticationEmail`
   - `usernameEmail`
   - `passwordEmail`
   - `description`
5. Log out of LXCA (`DELETE /sessions`, best effort)

No other monitor settings are intentionally modified.

---

## Security model

### LXCA credentials

- **Preferred:** pass `-LxcaCredential` (`PSCredential`) to `Rotate-LXCA-O365SmtpToken.ps1`.
- **Legacy fallback:** `-LxcaUser` + `-LxcaPass` is still accepted for backward compatibility, but discouraged.

### Unattended execution

For scheduled production runs, use:

- `Set-LXCAO365Secrets.ps1` to create DPAPI-protected secrets
- `Run-LXCAO365RotateScheduled.ps1` to pass a `PSCredential` object into the core script

This avoids passing LXCA password as a plain-text command-line argument to the core rotation script.

---

## Requirements

### PowerShell

- PowerShell **7.2.24+**

### LXCA

- LXCA reachable over HTTPS
- Existing email alert forwarder configured for OAuth2
- LXCA account with rights to monitor settings

### Microsoft 365 / Entra ID

For AppOnly rotation:

- Tenant ID
- Client ID
- Client secret
- SMTP mailbox/user identity (`SmtpUser`) valid for your flow

For DelegatedRefresh rotation:

- Tenant ID
- Client ID (public client flow enabled)
- Delegated refresh token

---

## Connectivity requirements (important)

The system executing the scripts **must have network access to all of the following**:

- LXCA appliance (HTTPS)
- Microsoft Entra token endpoints  
  (`https://login.microsoftonline.com`)
- Microsoft 365 SMTP endpoint  
  (`smtp.office365.com:587`)

This system **is not the LXCA appliance**.

Typical placements:

- Admin workstation
- Management VM
- Secure jump host

## Manual validation workflow (non-scheduled)

## Manual validation workflow (non-scheduled)

Use this first to prove connectivity and functional rotation before scheduler rollout.

### 1) Discover monitor IDs

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential (Get-Credential) `
  -ListMonitors
```

### 2) Rotate using AppOnly

```powershell
$cred = Get-Credential

pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential $cred `
  -RotateToken `
  -AuthMode AppOnly `
  -MonitorId "<monitor-id>" `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-guid>" `
  -ClientSecret "<secret-value>" `
  -SmtpUser "alerts@yourdomain.com" `
  -DescriptionPrefix "O365 SMTP token rotated"
```

### 3) Rotate using DelegatedRefresh

```powershell
$cred = Get-Credential

pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential $cred `
  -RotateToken `
  -AuthMode DelegatedRefresh `
  -MonitorId "<monitor-id>" `
  -TenantId "<tenant-guid-or-name>" `
  -ClientId "<app-guid>" `
  -RefreshTokenPath "./delegated_refresh_token.txt" `
  -SmtpUser "alerts@yourdomain.com"
```

---

## Unattended production workflow (scheduled)

### 1) Create secrets file (run once as scheduled task identity)

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeClientSecret
```

Delegated mode variant:

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeDelegatedRefreshToken `
  -DelegatedRefreshTokenPath ./delegated_refresh_token.txt
```

### 2) Build non-secret config JSON

Start from `examples/lxca-o365-rotate.config.json`.

Important keys:

- `AuthMode` (`AppOnly` or `DelegatedRefresh`)
- `LxcaBaseUrl`
- `LxcaUser`
- `MonitorId`
- `TenantId`
- `ClientId`
- `SmtpUser`
- `DescriptionPrefix` (optional)
- `ScriptPath` (optional; defaults to `..\scripts\Rotate-LXCA-O365SmtpToken.ps1`)

### 3) Test wrapper interactively

```powershell
pwsh ./scripts/Run-LXCAO365RotateScheduled.ps1 `
  -ConfigPath ./examples/lxca-o365-rotate.config.json `
  -SecretsPath ./secrets/lxca-o365-rotate.secrets.xml
```

### 4) Configure Task Scheduler action

Program/script:

- `C:\Program Files\PowerShell\7\pwsh.exe`

Arguments example:

```text
-NoProfile -ExecutionPolicy Bypass -File "C:\Path\scripts\Run-LXCAO365RotateScheduled.ps1" -ConfigPath "C:\Path\examples\lxca-o365-rotate.config.json" -SecretsPath "C:\Path\secrets\lxca-o365-rotate.secrets.xml"
```

Recommended task settings:

- Run whether user is logged on or not
- Do not allow overlapping runs
- Run task as soon as possible after missed start
- Retry on failure (example: every 5 minutes, 3 attempts)

---

## Token lifetime & rotation cadence

Microsoft 365 OAuth2 access tokens are typically ~60 minutes.

Recommended cadence:

- Rotate every **45–55 minutes**
- Avoid exactly 60 minutes (clock skew / delays risk)

---

## Delegated bootstrap helper scripts

For delegated token bootstrap and troubleshooting:

- `scripts/Bootstrap-DelegatedSmtp.ps1`
- `scripts/Get-DelegatedSmtpAccessToken.ps1`

Suggested delegated bootstrap flow:

1. Enable public client flow on Entra app.
2. Run `Bootstrap-DelegatedSmtp.ps1` as the mailbox identity.
3. Store refresh token via `Set-LXCAO365Secrets.ps1`.
4. Run wrapper in `AuthMode: DelegatedRefresh`.
5. Move to `AppOnly` when tenant/org prerequisites permit.

---

## Operational notes

- On read, LXCA may return `passwordEmail` as a secret reference/GUID.
- On update, writing a new bearer token updates secret value behind that reference.
- Keep secrets and generated token files out of source control.

