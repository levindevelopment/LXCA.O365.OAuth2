# SMTP Capture (Lab Only)

This is an optional validation tool to prove LXCA is presenting the rotated bearer token in SMTP `AUTH XOAUTH2`.

- STARTTLS listener (default: 0.0.0.0:5870)
- Logs token fingerprints (length + sha256 snippet) rather than raw tokens
- Useful for validating token rotation without relying on Microsoft 365 connectivity

## Notes
- Keep this isolated to a lab network.
- Do not store raw tokens in logs.
