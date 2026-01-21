# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repository provides a **PowerShell 7 script** to rotate OAuth2 bearer tokens used by **Lenovo XClarity Administrator (LXCA)** email alert forwarders configured with **SMTP OAuth2 (XOAUTH2)**.

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
  -LxcaBaseUrl "https://192.168.183.130" `
  -LxcaUser "admin" -LxcaPass "********" `
  -ListMonitors
```

---

### Rotate using a supplied token (testing / validation)

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://192.168.183.130" `
  -LxcaUser "admin" -LxcaPass "********" `
  -MonitorId "1768960044290" `
  -RotateToken `
  -TokenValue ("DUMMYTOKEN_" + ([guid]::NewGuid().ToString("N"))) `
  -DescriptionPrefix "TOKEN-ROTATE TEST"
```

---

### Rotate using Entra OAuth2 (production)

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://192.168.183.130" `
  -LxcaUser "admin" -LxcaPass "********" `
  -MonitorId "1768960044290" `
  -RotateToken `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-guid>" `
  -ClientSecret "<secret>" `
  -SmtpUser "alerts@yourdomain.com"
```

---

## Token lifetime & rotation timing

Microsoft 365 OAuth2 access tokens typically have a **60-minute lifetime**.

### Recommended strategy

- Schedule rotation **5–10 minutes before token expiry**
- Typical cadence: **every 45–55 minutes**

### Rotation flow

1. Script requests a fresh OAuth2 access token from Entra
2. Script updates the LXCA Email Alert monitor with the new token
3. LXCA immediately begins using the new token for `AUTH XOAUTH2`
4. Previous token expires naturally in Entra

This ensures:
- No SMTP authentication failures
- No alert delivery gaps
- No manual intervention

---

## Windows Task Scheduler integration

The script is explicitly designed for **non-interactive scheduled execution**.

### Recommended task settings

- Program: `pwsh.exe`
- Run whether user is logged on or not
- Run with highest privileges (if required)
- Do **not** allow overlapping runs
- Disable “Stop task if it runs longer than…”

Examples provided in:
- `examples/example-task.ps1`
- `examples/example-schtasks.txt`

---

## Security considerations

- Do **not** commit secrets (client secrets, tokens)
- Tokens are never written to disk by the script
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

## License

MIT

---

## Disclaimer

> This project is provided in a personal capacity and is not an official or
> supported product of Lenovo or Microsoft.
