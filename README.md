# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repository provides a **production-ready PowerShell 7 script** to rotate OAuth2 bearer tokens used by **Lenovo XClarity Administrator (LXCA)** email alert forwarders configured with **SMTP OAuth2 (XOAUTH2)**.

The primary intent of this project is to enable **safe, automated token rotation** without manual GUI interaction, ensuring uninterrupted alert delivery via Microsoft 365.

---

## Primary script

**`scripts/Rotate-LXCA-O365SmtpToken.ps1`**

This is the **only file required for production use**.

---

## What the script does

1. Authenticates to LXCA via REST (`POST /sessions`)
2. Retrieves a specific Email Alert monitor (`GET /events/monitors/{id}`)
3. Mints (or accepts) a fresh OAuth2 access token
4. Updates **only**:
   - `passwordEmail` (OAuth2 bearer token)
   - `description` (timestamp marker for audit/traceability)
5. Writes the update using `PUT /events/monitors/{id}`
6. Logs out of LXCA to avoid session exhaustion

No other monitor configuration is modified.

---

## Requirements

### PowerShell
- **PowerShell 7+** (mandatory)
- Windows, Linux, or macOS supported

### LXCA
- LXCA reachable over HTTPS
- Existing **Email Alert forwarder**
- Forwarder configured for:
  - STARTTLS or SSL
  - OAuth2 authentication
- LXCA administrative credentials

### Microsoft 365 / Entra ID (for real tokens)
Required only when rotating **real** tokens:

- Tenant ID
- Client ID
- Client Secret
- SMTP AUTH enabled for the mailbox (e.g. `alerts@yourdomain.com`)

---

## Connectivity requirements (important)

The system executing the script **must have network access to all of the following**:

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

---

## Usage

### Discover monitor IDs

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaUser "admin" -LxcaPass "********" `
  -ListMonitors
```

---

### Rotate using a supplied token (testing / validation)

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://lxca-ip-or-hostname" `
  -LxcaUser "admin" -LxcaPass "********" `
  -MonitorId "<monitor-id>" `
  -RotateToken `
  -TokenValue ("DUMMYTOKEN_" + ([guid]::NewGuid().ToString("N"))) `
  -DescriptionPrefix "TOKEN-ROTATE TEST"
```

---

### Rotate using Entra OAuth2 (production)

> **Production tip:** Avoid passing `-LxcaPass` or `-ClientSecret` in clear text on the command line long-term.
> Use SecretManagement, Windows Credential Manager, or an encrypted secrets file protected by the scheduled task account.
> A Task Scheduler wrapper is provided below.

```powershell
# Production example: mint a fresh Entra OAuth2 access token and apply it to a specific LXCA Email Alert monitor
#
# Prereqs (document these in your environment runbook):
# - The machine running this command can reach:
#     * LXCA: https://<lxca-host-or-ip>
#     * Entra token endpoint: https://login.microsoftonline.com
#     * (Optional validation) smtp.office365.com:587
# - Entra App Registration is created and client secret is available (do NOT hardcode secrets in source control)
# - The SMTP mailbox (SmtpUser) is licensed/valid and SMTP AUTH is enabled per your org policy
# - The LXCA Email Alert forwarder (monitor) already exists and is configured to OAuth2 in LXCA GUI

# REPLACE THESE VALUES:
$LxcaBaseUrl   = "https://<lxca-host-or-ip>"     # <-- LXCA base URL (HTTPS)
$LxcaUser      = "admin"                       # <-- LXCA API user
$LxcaPass      = "********"                    # <-- LXCA password (store securely)
$MonitorId     = "<monitor-id>"               # <-- LXCA monitor ID (from -ListMonitors)

$TenantId      = "00000000-0000-0000-0000-000000000000" # <-- Entra tenant GUID
$ClientId      = "00000000-0000-0000-0000-000000000000" # <-- App (client) ID GUID
$ClientSecret  = "********"                               # <-- Client secret VALUE (store securely)

$SmtpUser      = "alerts@yourdomain.com"        # <-- Mailbox UPN used by LXCA for SMTP AUTH XOAUTH2

# Suggested marker (shows in LXCA forwarder description for audit/traceability):
$DescriptionPrefix = "O365 SMTP token rotated"
```
Production (AppOnly)
```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -AuthMode AppOnly `
  -LxcaBaseUrl $LxcaBaseUrl `
  -LxcaUser $LxcaUser -LxcaPass $LxcaPass `
  -MonitorId $MonitorId `
  -RotateToken `
  -TenantId $TenantId `
  -ClientId $ClientId `
  -ClientSecret $ClientSecret `
  -SmtpUser $SmtpUser `
  -DescriptionPrefix $DescriptionPrefix
```
(DelegatedRefresh)
```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -AuthMode DelegatedRefresh `
  -LxcaBaseUrl $LxcaBaseUrl `
  -LxcaUser $LxcaUser -LxcaPass $LxcaPass `
  -MonitorId $MonitorId `
  -RotateToken `
  -TenantId $TenantId `
  -ClientId $ClientId `
  -RefreshTokenPath $RefreshTokenPath `
  -SmtpUser $SmtpUser `
  -DescriptionPrefix $DescriptionPrefix
```

---

## Delegated OAuth2 bootstrap (DelegatedRefresh mode)

Delegated mode uses an **interactive device-code sign-in once** to obtain a **refresh token** for the mailbox account (e.g. `alerts@yourdomain.com`). The rotator then uses that refresh token to mint new access tokens automatically.

> The delegated refresh token is long-lived and does not have a fixed expiry, but it may be invalidated by normal security operations (password reset, account changes, policy updates).
> If invalidated, re-run the bootstrap process to generate a new refresh token.

### Files
- `scripts/Bootstrap-DelegatedSmtp.ps1` (one-time / break-glass)
- `scripts/Get-DelegatedSmtpAccessToken.ps1` (optional helper)

### Step 1 — enable Public client flows on the Entra app
In the App Registration: **Authentication** → enable **Allow public client flows**.

### Step 2 — run bootstrap as the mailbox user
Sign in as the mailbox identity you will send as (e.g. `smtpuser@tenant.onmicrosoft.com`).

> Run bootstrap as the mailbox user (smtpuser@...), not an admin, because the refresh token is user-bound.

```powershell
pwsh .\scripts\Bootstrap-DelegatedSmtp.ps1 `
  -TenantId "tenant.onmicrosoft.com" `
  -ClientId "<app-client-id-guid>" `
  -Upn "alerts@yourdomain.com"
```

This writes `delegated_refresh_token.txt` in the current directory.

### Step 3 — store the refresh token securely (recommended)
For Windows Task Scheduler deployments, store the refresh token in the DPAPI secrets file:

> Recommended workflow:
> 1. Decide the “run-as” identity for the scheduled task (service account).
> 2. Run Set-LXCAO365Secrets.ps1 as that same identity to generate the DPAPI secrets XML.
> 3. Configure Task Scheduler to run the wrapper under the same identity.

```powershell
pwsh .\examples\Set-LXCAO365Secrets.ps1 `
  -OutFile .\examples\lxca-o365-rotate.secrets.xml `
  -IncludeDelegatedRefreshToken `
  -DelegatedRefreshTokenPath .\delegated_refresh_token.txt
```

> Keep the refresh token secret.

> After importing the refresh token into the encrypted secrets store,
> you may delete the plaintext delegated_refresh_token.txt. 
> Do not delete the stored/encrypted copy unless you are switching to AppOnly.

### Step 4 — run the wrapper in DelegatedRefresh mode
Set `AuthMode` to `DelegatedRefresh` in the config JSON and run the wrapper.

### Phase 2 — switch to AppOnly when available (best-practice target)
Once your tenant supports Exchange Online Application RBAC for `SMTP.SendAsApp` (and `Enable-OrganizationCustomization` succeeds),
you can switch to `AuthMode: AppOnly` and remove the delegated refresh token from your secrets store.

Set `AuthMode` to `DelegatedRefresh` in the config JSON and run the wrapper.

---

## Token lifetime & rotation timing

Microsoft 365 OAuth2 access tokens typically have a **60-minute lifetime**.

### Recommended strategy

- Schedule rotation **5–10 minutes before token expiry**
- Typical cadence: **every 45–55 minutes**

### Rotation flow

1. Script requests a fresh access token from Entra
2. Script updates the LXCA Email Alert monitor with the new token
3. LXCA immediately begins using the new token for `AUTH XOAUTH2`
4. Previous token expires naturally in Entra

This ensures:
- No SMTP authentication failures
- No alert delivery gaps
- No manual intervention

---

## Windows Task Scheduler integration (wrapper included)

For production, use the wrapper in `examples/` to keep secrets off the command line.

### Included files

- `examples/Set-LXCAO365Secrets.ps1`  
  Creates an **encrypted secrets file** using DPAPI (tied to the creating Windows user account).

- `examples/Run-LXCAO365RotateScheduled.ps1`  
  Loads secrets + config and invokes `scripts/Rotate-LXCA-O365SmtpToken.ps1` safely.

- `examples/lxca-o365-rotate.config.json (template)`  
  Non-secret configuration (LXCA URL, MonitorId, TenantId, etc.).

### Step 1 — create secrets (run once as the scheduled task account)

```powershell
pwsh .\examples\Set-LXCAO365Secrets.ps1 `
  -OutFile .\examples\lxca-o365-rotate.secrets.xml
```

You’ll be prompted for:
- LXCA password
- Entra client secret

### Step 2 — create config (non-secret)

Edit:
- `examples/lxca-o365-rotate.config.json (template)`

### Step 3 — test wrapper interactively

```powershell
pwsh .\examples\Run-LXCAO365RotateScheduled.ps1 `
  -ConfigPath .\examples\lxca-o365-rotate.config.json `
  -SecretsPath .\examples\lxca-o365-rotate.secrets.xml
```

### Step 4 — Task Scheduler action

Program/script:
- `C:\Program Files\PowerShell\7\pwsh.exe`

Arguments (example):
```text
-NoProfile -ExecutionPolicy Bypass -File "C:\Path\Run-LXCAO365RotateScheduled.ps1" -ConfigPath "C:\Path\lxca-o365-rotate.config.json" -SecretsPath "C:\Path\lxca-o365-rotate.secrets.xml"
```

Recommended task settings:
- Run whether user is logged on or not
- Do not allow overlapping runs
- Disable “Stop the task if it runs longer than…”

### Step 4a — Task Scheduler trigger (recommended)

Microsoft 365 SMTP OAuth2 access tokens typically have a ~60 minute lifetime.

**Recommended rotation cadence:**
- Run **every 45 minutes** (safe default)
- Or run **every 50–55 minutes** if you want fewer refreshes
- Avoid **60 minutes exactly** (clock drift + delays can cause expiry gaps)

**Task Scheduler trigger:**
- Trigger: **Daily**
- Repeat task every: **45 minutes**
- For a duration of: **Indefinitely** (or 1 day with “Stop at end of duration” unchecked)
- Start time: pick a time that makes sense for your environment (e.g. `00:05`)

**Reliability options (recommended):**
- ✅ “Run task as soon as possible after a scheduled start is missed”
- ✅ “If the task fails, restart every: 5 minutes (attempt 3 times)”
- ❌ Do not allow overlapping runs

Example elevated Powershell to create task:
```powershell
$TaskName  = "LXCA O365 SMTP Token Rotate"
$User      = "DOMAIN\UserOrLocalUser"   # <-- change
$Pwsh      = "C:\Program Files\PowerShell\7\pwsh.exe"

$Wrapper   = "C:\Path\Run-LXCAO365RotateScheduled.ps1"        # <-- change
$Config    = "C:\Path\lxca-o365-rotate.config.json"           # <-- change
$Secrets   = "C:\Path\lxca-o365-rotate.secrets.xml"           # <-- change

$Args = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-File", "`"$Wrapper`"",
  "-ConfigPath", "`"$Config`"",
  "-SecretsPath", "`"$Secrets`""
) -join " "

$action  = New-ScheduledTaskAction -Execute $Pwsh -Argument $Args

# Start now, then repeat every 45 minutes indefinitely
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
  -RepetitionInterval (New-TimeSpan -Minutes 45) `
  -RepetitionDuration ([TimeSpan]::MaxValue)

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew

# You will be prompted for the password securely
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User $User -RunLevel Highest
```

**Note:** Whatever account runs the task must be the same account that created the lxca-o365-rotate.secrets.xml (because DPAPI ties it to the user profile).

---

## Security considerations

- Do **not** commit secrets (client secrets, tokens)
- Tokens are never written to disk by the rotator script
- Session cleanup is enforced even on failure
- Principle of least privilege is recommended for LXCA API accounts

---

## Optional: SMTP capture & wire validation (lab only)

Included **only for engineering validation**, not production use.

Located in `smtp-capture/`.

Purpose:
- Verify `AUTH XOAUTH2` is used
- Confirm token changes after rotation
- Confirm token stability between rotations

The capture server logs **hashes and lengths only**, not raw tokens.

This section can be omitted entirely in production deployments.

---

## Troubleshooting

### DelegatedRefresh: `invalid_grant` when refreshing
This usually means the delegated refresh token was revoked/invalidated (password reset, account disabled, sign-out/revoke sessions, policy change, etc.).

Fix:
1. Re-run `scripts/Bootstrap-DelegatedSmtp.ps1` as the mailbox user.
2. Re-store the new refresh token using `examples/Set-LXCAO365Secrets.ps1` (DPAPI secrets file).
3. Re-run the scheduled wrapper.

### Wrapper cannot decrypt secrets (DPAPI)
The scheduled task must run under the **same Windows identity** that created the DPAPI secrets file.

Fix:
- Re-run `examples/Set-LXCAO365Secrets.ps1` as the scheduled task account and regenerate the secrets XML.


---

## License

MIT

---

## Disclaimer

> This project is provided in a personal capacity and is not an official or
> supported product of Lenovo or Microsoft.
