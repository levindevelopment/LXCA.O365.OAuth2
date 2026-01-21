# Certificates (Lab Only)

LXCA may require the SMTP server certificate to be trusted.

## Generate a self-signed cert
```bash
sudo mkdir -p /opt/smtp-capture
cd /opt/smtp-capture

sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
  -keyout smtp.key -out smtp.crt \
  -subj "/CN=lxca-smtp-capture.local"

sudo chmod 600 smtp.key
```

## Import into LXCA
Administration → Security → Trusted Certificates
- Import `smtp.crt`
