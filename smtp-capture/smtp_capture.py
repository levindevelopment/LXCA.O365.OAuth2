#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import ssl
from datetime import datetime

# SMTP sink server for observing LXCA's AUTH XOAUTH2 over SMTP (for token rotation validation).
# Default behavior avoids logging secrets (bearer tokens) verbatim.

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5870  # pick a free port

CERT_FILE = "/opt/smtp-capture/smtp.crt"
KEY_FILE  = "/opt/smtp-capture/smtp.key"

# Safety/logging controls
LOG_XOAUTH2_B64 = False          # WARNING: base64 can contain the bearer token
LOG_XOAUTH2_DECODED_REPR = False # WARNING: decoded string can contain the bearer token
FAIL_AUTH_IF_EMPTY_TOKEN = False # If True, respond 535 when token is empty (useful for proving rotation)

SOH = "\x01".encode("utf-8").decode("unicode_escape")  # -> actual \x01 control char

def now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    print(f"[{now()}] CONNECT {peer}")

    # Greet
    writer.write(b"220 lxca-smtp-capture ESMTP\r\n")
    await writer.drain()

    tls_active = False

    async def send(line: str):
        writer.write(line.encode("utf-8") + b"\r\n")
        await writer.drain()

    while True:
        line = await reader.readline()
        if not line:
            break

        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        upper = text.upper()

        print(f"[{now()}] C: {text}")

        if upper.startswith("EHLO") or upper.startswith("HELO"):
            # Advertise STARTTLS and AUTH XOAUTH2
            await send("250-lxca-smtp-capture")
            if not tls_active:
                await send("250-STARTTLS")
            await send("250-AUTH XOAUTH2")
            await send("250 SIZE 10485760")
            continue

        if upper == "STARTTLS":
            await send("220 Ready to start TLS")

            sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            sslctx.load_cert_chain(CERT_FILE, KEY_FILE)

            loop = asyncio.get_running_loop()
            transport = writer.transport
            protocol = transport.get_protocol()   # StreamReaderProtocol

            new_transport = await loop.start_tls(
                transport, protocol, sslctx, server_side=True
            )

            # IMPORTANT: rebuild writer for the new TLS transport.
            writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)

            tls_active = True
            print(f"[{now()}] TLS established with {peer}")
            continue

        if upper.startswith("AUTH XOAUTH2"):
            # AUTH XOAUTH2 <base64>
            parts = text.split(" ", 2)
            b64 = parts[2] if len(parts) >= 3 else ""

            # Avoid printing b64 by default (it may include the bearer token).
            if LOG_XOAUTH2_B64:
                print(f"[{now()}] XOAUTH2_B64: {b64}")
            else:
                h = sha256_hex(b64)
                print(f"[{now()}] XOAUTH2_B64_META: len={len(b64)} sha256={h[:12]}...{h[-12:]}")

            token = ""
            user = ""

            try:
                decoded = base64.b64decode(b64 + "===", validate=False).decode("utf-8", errors="replace")

                if LOG_XOAUTH2_DECODED_REPR:
                    # This may contain the token - leave disabled by default.
                    print(f"[{now()}] XOAUTH2_DEC_REPR: {decoded!r}")

                # Typical format: "user=<upn>\x01auth=Bearer <token>\x01\x01"
                if "user=" in decoded:
                    user = decoded.split("user=", 1)[1].split(SOH, 1)[0]

                marker = "auth=Bearer "
                if marker in decoded:
                    token = decoded.split(marker, 1)[1].split(SOH, 1)[0]

            except Exception as e:
                print(f"[{now()}] XOAUTH2 decode failed: {e}")

            # Safe token logging
            if user:
                print(f"[{now()}] XOAUTH2_USER: {user}")

            if token:
                th = sha256_hex(token)
                print(f"[{now()}] TOKEN_META: len={len(token)} sha256={th[:12]}...{th[-12:]}")
                if len(token) >= 40:
                    print(f"[{now()}] TOKEN_SNIP: {token[:16]}...{token[-16:]}")
                else:
                    print(f"[{now()}] TOKEN_SNIP: {token[:8]}...{token[-8:]}")
            else:
                print(f"[{now()}] TOKEN_META: len=0")

            if FAIL_AUTH_IF_EMPTY_TOKEN and not token:
                await send("535 5.7.8 Authentication credentials invalid")
            else:
                # Accept auth (sink behavior)
                await send("235 2.7.0 Authentication successful")
            continue

        if upper.startswith("MAIL FROM:") or upper.startswith("RCPT TO:") or upper == "DATA":
            if upper == "DATA":
                await send("354 End data with <CR><LF>.<CR><LF>")
            else:
                await send("250 OK")
            continue

        if text == ".":
            await send("250 OK (message accepted)")
            continue

        if upper == "QUIT":
            await send("221 Bye")
            break

        await send("250 OK")

    print(f"[{now()}] DISCONNECT {peer}")
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[{now()}] Listening on {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
