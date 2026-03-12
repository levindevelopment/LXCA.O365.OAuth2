# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repository provides PowerShell 7 automation to rotate OAuth2 bearer tokens used by Lenovo XClarity Administrator (LXCA) email alert forwarders configured with SMTP OAuth2 (XOAUTH2).

The goal is safe, repeatable token rotation without manual LXCA GUI changes.

---

## Audience and reading order

If you are an operator implementing this end-to-end, read in this order:

1. [Authentication modes (AppOnly vs DelegatedRefresh)](#authentication-modes-apponly-vs-delegatedrefresh)
2. [Requirements](#requirements)
3. [Connectivity requirements (important)](#connectivity-requirements-important)
4. [Production architecture](#production-architecture)
5. [Config JSON reference (with redacted examples)](#config-json-reference-with-redacted-examples)
6. [Manual validation workflow (non-scheduled)](#manual-validation-workflow-non-scheduled)
7. [Unattended production workflow (scheduled)](#unattended-production-workflow-scheduled)

---

## Authentication modes (AppOnly vs DelegatedRefresh)

This solution supports two OAuth token acquisition modes:

### AppOnly (preferred long-term)

- Uses Entra app credentials (`TenantId`, `ClientId`, `ClientSecret`)
- No user refresh token required
- Better fit for unattended service automation

### DelegatedRefresh (bootstrap/compatibility path)

- Uses a delegated **refresh token** obtained through device-code sign-in
- Tied to a user/mailbox context
- Useful when AppOnly permissions/tenant prerequisites are not yet complete

> If you use DelegatedRefresh, first see [Delegated bootstrap helpers](#delegated-bootstrap-helpers) to obtain and store the refresh token.

---

## Requirements

### PowerShell

- PowerShell **7.2.24+**

### LXCA

- LXCA reachable over HTTPS
- Existing email alert forwarder configured for OAuth2
- LXCA account with rights to monitor settings

### Microsoft 365 / Entra ID

For **AppOnly**:

- Tenant ID
- Client ID
- Client secret
- SMTP mailbox/user identity (`SmtpUser`) valid for your flow

For **DelegatedRefresh**:

- Tenant ID
- Client ID with public client flow enabled
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

## Production architecture

This implementation uses three first-class operational scripts:

- `scripts/Rotate-LXCA-O365SmtpToken.ps1`  
  Core engine (LXCA API login, monitor list/get/put, token update).
- `scripts/Set-LXCAO365Secrets.ps1`  
  Creates DPAPI-encrypted secrets XML for unattended execution.
- `scripts/Run-LXCAO365RotateScheduled.ps1`  
  Scheduled-task wrapper that reads config + secrets and invokes the core engine.

Template config:

- `examples/lxca-o365-rotate.config.json` (non-secret)

### What the core script updates

`Rotate-LXCA-O365SmtpToken.ps1` updates only:

- `authenticationEmail`
- `usernameEmail`
- `passwordEmail`
- `description`

No other monitor fields are intentionally modified.

### Credential handling model

- **Preferred:** pass `-LxcaCredential` (`PSCredential`) to core script.
- **Legacy fallback:** `-LxcaUser` + `-LxcaPass` remains accepted for backward compatibility, but discouraged.

---

## Config JSON reference (with redacted examples)

The wrapper script (`Run-LXCAO365RotateScheduled.ps1`) consumes a **non-secret JSON config**.

### Field reference

- `AuthMode` *(required)*: `AppOnly` or `DelegatedRefresh`
- `LxcaBaseUrl` *(required)*: LXCA base URL, e.g. `https://lxca01.example.local`
- `LxcaUser` *(required)*: LXCA username used to build `PSCredential`
- `MonitorId` *(required)*: target email monitor ID
- `TenantId` *(required)*: tenant GUID or domain form
- `ClientId` *(required)*: app/client ID
- `SmtpUser` *(required)*: mailbox identity used by LXCA SMTP OAuth2
- `DescriptionPrefix` *(optional)*: stamp prefix in monitor description
- `ScriptPath` *(optional)*: override path to rotate script

### AppOnly config example (redacted)

```json
{
  "AuthMode": "AppOnly",
  "LxcaBaseUrl": "https://lxca01.example.local",
  "LxcaUser": "svc_lxca_rotate",
  "MonitorId": "<monitor-id>",
  "TenantId": "00000000-0000-0000-0000-000000000000",
  "ClientId": "11111111-1111-1111-1111-111111111111",
  "SmtpUser": "alerts@contoso.com",
  "DescriptionPrefix": "O365 SMTP token rotated",
  "ScriptPath": "..\\scripts\\Rotate-LXCA-O365SmtpToken.ps1"
}
```

### DelegatedRefresh config example (redacted)

```json
{
  "AuthMode": "DelegatedRefresh",
  "LxcaBaseUrl": "https://lxca01.example.local",
  "LxcaUser": "svc_lxca_rotate",
  "MonitorId": "<monitor-id>",
  "TenantId": "00000000-0000-0000-0000-000000000000",
  "ClientId": "11111111-1111-1111-1111-111111111111",
  "SmtpUser": "alerts@contoso.com",
  "DescriptionPrefix": "O365 SMTP token rotated",
  "ScriptPath": "..\\scripts\\Rotate-LXCA-O365SmtpToken.ps1"
}
```

> Do **not** store client secrets, LXCA password, or refresh token in this JSON. Those belong in the encrypted secrets file.

---

## Manual validation workflow (non-scheduled)

Use this workflow first to prove connectivity and functional rotation before scheduler rollout.

Step 1 (discover monitor IDs) is common.
Step 2 is **mode selection**: run **either AppOnly or DelegatedRefresh**, not both in sequence.

### 1) Discover monitor IDs

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaCredential (Get-Credential) `
  -ListMonitors
```

### 2A) Validate AppOnly rotation (choose this OR 2B)

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

### 2B) Validate DelegatedRefresh rotation (choose this OR 2A)

Before this step, complete [Delegated bootstrap helpers](#delegated-bootstrap-helpers) to create `delegated_refresh_token.txt`.

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

### 1) Create encrypted secrets (run once as scheduled task identity)

AppOnly secrets file:

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeClientSecret
```

DelegatedRefresh secrets file:

```powershell
pwsh ./scripts/Set-LXCAO365Secrets.ps1 `
  -OutFile ./secrets/lxca-o365-rotate.secrets.xml `
  -IncludeDelegatedRefreshToken `
  -DelegatedRefreshTokenPath ./delegated_refresh_token.txt
```

### 2) Create config JSON

- Start from `examples/lxca-o365-rotate.config.json`
- Populate fields using [Config JSON reference (with redacted examples)](#config-json-reference-with-redacted-examples)

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

## Delegated bootstrap helpers

Use these scripts when operating in `DelegatedRefresh` mode:

- `scripts/Bootstrap-DelegatedSmtp.ps1`  
  Requests device code, guides user sign-in, and saves refresh token.
- `scripts/Get-DelegatedSmtpAccessToken.ps1`  
  Tests delegated refresh token exchange and optionally shows JWT claims.

### Typical delegated bootstrap flow

1. In Entra app registration, enable public client flows.
2. Run bootstrap as the mailbox identity used for SMTP send-as.
3. Save resulting refresh token to a secure path.
4. Import token into DPAPI secrets with `Set-LXCAO365Secrets.ps1`.
5. Configure wrapper with `AuthMode: DelegatedRefresh`.
6. When possible, migrate to AppOnly.

---

## Operational notes

- On read, LXCA may return `passwordEmail` as a secret reference/GUID.
- On update, writing a new bearer token updates the secret value behind that reference.
- Keep secrets and generated token files out of source control.

---

## TODO

Potential future hardening (optional enhancements):

- Add a lightweight preflight mode that validates DNS/TCP reachability before attempting rotation.
- Add structured log output (JSON lines) for SIEM ingestion.
- Add Pester tests around argument validation and payload field constraints.

---

## External references (authoritative docs)

Use these sources to validate implementation assumptions and tenant-specific prerequisites:

- Microsoft: OAuth for SMTP/IMAP/POP (including SMTP.Send scope)
  - <https://learn.microsoft.com/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth>
- Microsoft identity platform: client credentials grant
  - <https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow>
- Microsoft identity platform: refresh tokens and lifecycle behavior
  - <https://learn.microsoft.com/entra/identity-platform/refresh-tokens>
- Exchange Online SMTP AUTH overview and tenant/mailbox controls
  - <https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission>
- Lenovo XClarity Administrator documentation portal (use your installed LXCA version selector)
  - <https://pubs.lenovo.com/lxca/>
- Lenovo XClarity Administrator REST API reference (version-specific)
  - <https://pubs.lenovo.com/lxca_restapi/>

> Note: Always align to your exact LXCA firmware/doc version and your tenant’s Entra/Exchange security policies, as behavior and prerequisites can differ by version and policy baseline.
