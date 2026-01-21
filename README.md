# LXCA → Microsoft 365 SMTP OAuth2 Token Rotation

This repo contains a PowerShell 7 script that updates the **OAuth2 bearer token** used by a Lenovo XClarity Administrator (LXCA) **Email Alert** forwarder (SMTP AUTH XOAUTH2).

Primary intent:
- Run on a schedule (Task Scheduler / cron)
- Rotate the bearer token stored in a specific LXCA monitor
- Avoid leaving LXCA sessions open (prevents “maximum active sessions exceeded”)

**Production file:** `scripts/Rotate-LXCA-O365SmtpToken.ps1`

---

## What the rotator script does

1. Logs into LXCA (`POST /sessions`)
2. Retrieves the target monitor (`GET /events/monitors/{id}`)
3. Updates **only** the token field and description timestamp marker
4. Writes the monitor back (`PUT /events/monitors/{id}`)
5. Logs out (session cleanup in `finally`)

The script is designed to be safe for scheduled execution (no interactive prompts, closes sessions).

---

## Requirements

### PowerShell
- **PowerShell 7+** (recommended/expected)

### LXCA
- LXCA reachable over HTTPS
- An existing **Email Alert** monitor configured for OAuth2 (or at least created and then set in GUI)
- LXCA admin credentials for API calls

### Microsoft 365 / Entra (for real tokens)
To rotate real tokens you’ll need an Entra App Registration and SMTP AUTH enabled for the mailbox.
Inputs commonly required:
- Tenant ID
- Client ID
- Client Secret
- SMTP mailbox UPN (e.g. `alerts@yourdomain.com`)

---

## Script usage

### List monitors (discover monitor IDs)

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://192.168.183.130" `
  -LxcaUser "admin" -LxcaPass "********" `
  -ListMonitors
```

### Rotate using a supplied token (lab/testing)

```powershell
pwsh ./scripts/Rotate-LXCA-O365SmtpToken.ps1 `
  -LxcaBaseUrl "https://192.168.183.130" `
  -LxcaUser "admin" -LxcaPass "********" `
  -MonitorId "1768960044290" `
  -RotateToken `
  -TokenValue ("DUMMYTOKEN_" + ([guid]::NewGuid().ToString("N"))) `
  -DescriptionPrefix "TOKEN-ROTATE TEST"
```

### Rotate by minting a token (production pattern)

If your script version supports minting, use:

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

> Tip: In early phases you can rotate **dummy tokens** and validate that LXCA presents them on the wire (see SMTP capture section below).

---

## Scheduling

See `examples/` for a starting point.

Recommendation:
- Run slightly **shorter than your access token lifetime** (e.g. every 30–45 minutes depending on org policy).

---

## Security notes

- Do not commit secrets (client secrets, tokens).
- Avoid logging full tokens.
- Prefer least-privilege credentials for the LXCA API account where possible.

---

## Optional lab validation: SMTP capture (wire inspection)

Folder: `smtp-capture/`

Purpose:
- Confirm LXCA sends `AUTH XOAUTH2`
- Confirm the **bearer token changes** after rotation and stays stable between rotations

### Run capture server (STARTTLS on port 5870)

1) Create a self-signed cert (lab only):
```bash
sudo mkdir -p /opt/smtp-capture
cd /opt/smtp-capture
sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
  -keyout smtp.key -out smtp.crt \
  -subj "/CN=lxca-smtp-capture.local"
sudo chmod 600 smtp.key
```

2) Copy and run:
```bash
sudo cp smtp-capture/smtp_capture.py /opt/smtp-capture/smtp_capture.py
sudo python3 /opt/smtp-capture/smtp_capture.py
```

3) Point the LXCA email alert forwarder to your capture host:
- Host: your capture server IP
- Port: 5870
- Connection: STARTTLS
- Authentication: OAuth2

The capture server logs **hash-only** token fingerprints by default:
- XOAUTH2_B64_META (len + sha256 snippet)
- XOAUTH2_USER
- TOKEN_META (len + sha256 snippet)
- TOKEN_SNIP (optional short prefix/suffix)

---

## Included file fingerprints

- `scripts/Rotate-LXCA-O365SmtpToken.ps1` sha256: `89505d721fca591417bd162833f7a1f99a2b5279d67b9045fee8b8375e60a10f`
- `smtp-capture/smtp_capture.py` sha256: `162deb4c6aabf7cf358b23fc4cde15bfbe2bf3a388712f3a72e06e7e07fba918`
