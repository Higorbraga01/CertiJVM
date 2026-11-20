from __future__ import annotations

import hashlib
import re
import select
import socket
import ssl
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from OpenSSL import SSL, crypto

from .models import Certificate

PEM_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.DOTALL)


def _alias(source: str, index: int) -> str:
    stem = Path(urlparse(source).path).stem if source.startswith("https://") and Path(urlparse(source).path).suffix.lower() in (".crt", ".cer", ".pem") else (urlparse(source).hostname if source.startswith("https://") else Path(source).stem)
    slug = re.sub(r"[^a-z0-9]+", "-", (stem or "certificado").lower()).strip("-")[:38]
    token = hashlib.sha256(source.encode("utf-8")).hexdigest()[:10]
    return f"jvmcert-{slug}-{token}" + (f"-{index + 1}" if index else "")


def _certificate(der: bytes, source: str, index: int, test_url: str = "") -> Certificate:
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    before = cert.not_valid_before_utc
    after = cert.not_valid_after_utc
    return Certificate(der, cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(), before.strftime("%Y-%m-%d %H:%M UTC"), after.strftime("%Y-%m-%d %H:%M UTC"), cert.fingerprint(hashes.SHA256()).hex().upper(), source, _alias(source, index), test_url, before <= now <= after, index == 0)


def parse_certificates(data: bytes, source: str, test_url: str = "") -> list[Certificate]:
    blocks = PEM_PATTERN.findall(data)
    if blocks:
        ders = [x509.load_pem_x509_certificate(block).public_bytes(serialization.Encoding.DER) for block in blocks]
    else:
        ders = [x509.load_der_x509_certificate(data).public_bytes(serialization.Encoding.DER)]
    return [_certificate(der, source, index, test_url) for index, der in enumerate(ders)]


def load_file(path: Path) -> list[Certificate]:
    if path.suffix.lower() not in (".crt", ".cer", ".pem"):
        raise ValueError("Use arquivos .crt, .cer ou .pem")
    return parse_certificates(path.read_bytes(), str(path.resolve()))


def load_url(url: str, cancelled: Callable[[], bool] | None = None) -> list[Certificate]:
    if cancelled and cancelled():
        raise RuntimeError("Busca cancelada")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Informe uma URL HTTPS válida, sem credenciais")
    if Path(parsed.path).suffix.lower() in (".crt", ".cer", ".pem"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Certificate downloads may be the very endpoint whose TLS trust is being repaired.
        with urlopen(Request(url, headers={"User-Agent": "JVM-Cert-Manager/0.1"}), timeout=15, context=context) as response:
            if urlparse(response.geturl()).scheme != "https":
                raise ValueError("Redirecionamento para endereço não HTTPS recusado")
            chunks = []
            size = 0
            while True:
                if cancelled and cancelled():
                    raise RuntimeError("Busca cancelada")
                chunk = response.read(min(65_536, 2_000_001 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 2_000_000:
                    raise ValueError("O arquivo de certificado excede 2 MB")
            data = b"".join(chunks)
        return parse_certificates(data, url)
    raw = socket.create_connection((parsed.hostname, parsed.port or 443), timeout=15)
    connection = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD), raw)
    try:
        connection.set_tlsext_host_name(parsed.hostname.encode("idna"))
        connection.set_connect_state()
        deadline = time.monotonic() + 15
        while True:
            if cancelled and cancelled():
                raise RuntimeError("Busca cancelada")
            try:
                connection.do_handshake()
                break
            except (SSL.WantReadError, SSL.WantWriteError) as pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Tempo esgotado durante o handshake TLS") from pending
                if isinstance(pending, SSL.WantReadError):
                    select.select([raw], [], [], min(0.2, remaining))
                else:
                    select.select([], [raw], [], min(0.2, remaining))
        chain = connection.get_peer_cert_chain() or []
        if not chain:
            raise ValueError("O servidor não apresentou certificados")
        return [_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert), url, i, url) for i, cert in enumerate(chain)]
    finally:
        try:
            connection.close()
        finally:
            raw.close()
