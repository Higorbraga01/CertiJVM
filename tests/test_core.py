from __future__ import annotations

import hashlib
import base64
import json
import ssl
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from jvmcert.certificates import load_file, load_url, parse_certificates
from jvmcert.discovery import discover_jvms, inspect_jvm
from jvmcert.store import StoreError, entry_fingerprint, mutate
from jvmcert.tls import test_tls as probe_tls


def make_cert(tmp_path: Path, expired: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = tmp_path / "localhost.crt"
    key_path = tmp_path / "localhost.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture
def test_jvm(tmp_path):
    found = discover_jvms()
    if not found:
        pytest.skip("Nenhuma JVM instalada")
    jvm = found[0]
    copy = tmp_path / "cacerts"
    copy.write_bytes(jvm.cacerts.read_bytes())
    return replace(jvm, cacerts=copy, writable=True)


def test_discovery_finds_valid_jvms():
    for jvm in discover_jvms():
        assert inspect_jvm(jvm.home).cacerts == jvm.cacerts
        assert jvm.java.is_file() and jvm.keytool.is_file()


def test_parse_multi_pem_and_expired(tmp_path):
    cert_path, _ = make_cert(tmp_path)
    cert = load_file(cert_path)[0]
    assert cert.valid and len(cert.sha256) == 64
    assert len(parse_certificates(cert_path.read_bytes() * 2, str(cert_path))) == 2
    expired, _ = make_cert(tmp_path, expired=True)
    assert not load_file(expired)[0].valid


def test_add_update_remove_collision_and_password(test_jvm, tmp_path):
    cert_path, _ = make_cert(tmp_path)
    cert = load_file(cert_path)[0]
    alias = "jvmcert-test-localhost"
    first = mutate(test_jvm, alias, "changeit", "install", cert)
    assert first.status == "sucesso"
    assert entry_fingerprint(test_jvm, alias, "changeit") == cert.sha256
    assert mutate(test_jvm, alias, "changeit", "install", cert).status == "sem alteração"
    other_path = tmp_path / "second"
    other_path.mkdir()
    second_cert = load_file(make_cert(other_path)[0])[0]
    with pytest.raises(StoreError, match="já existe"):
        mutate(test_jvm, alias, "changeit", "install", second_cert)
    assert mutate(test_jvm, alias, "changeit", "install", second_cert, True).status == "sucesso"
    assert entry_fingerprint(test_jvm, alias, "changeit") == second_cert.sha256
    with pytest.raises(StoreError, match="senha"):
        mutate(test_jvm, alias, "senha-errada", "remove")
    assert mutate(test_jvm, alias, "changeit", "remove").status == "sucesso"
    assert entry_fingerprint(test_jvm, alias, "changeit") is None


def test_invalid_and_failed_import_restore(test_jvm, tmp_path, monkeypatch):
    import jvmcert.store as store

    cert_path, _ = make_cert(tmp_path)
    cert = load_file(cert_path)[0]
    alias = "jvmcert-rollback-test"
    mutate(test_jvm, alias, "changeit", "install", cert)
    before = hashlib.sha256(test_jvm.cacerts.read_bytes()).digest()
    other = tmp_path / "other"
    other.mkdir()
    new_cert = load_file(make_cert(other)[0])[0]
    original = store._keytool
    def failing_import(jvm, password, *args):
        if "-importcert" in args:
            from subprocess import CompletedProcess
            return CompletedProcess([], 1, "", "falha simulada")
        return original(jvm, password, *args)
    monkeypatch.setattr(store, "_keytool", failing_import)
    with pytest.raises(StoreError, match="falha simulada"):
        mutate(test_jvm, alias, "changeit", "install", new_cert, True)
    assert hashlib.sha256(test_jvm.cacerts.read_bytes()).digest() == before
    expired = replace(cert, valid=False)
    with pytest.raises(StoreError, match="validade"):
        mutate(test_jvm, "jvmcert-expired", "changeit", "install", expired)


class Unauthorized(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/localhost.crt":
            data = self.server.cert_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(401)
        self.end_headers()
    def log_message(self, *_):
        pass


@pytest.mark.parametrize("home", [jvm.home for jvm in discover_jvms()], ids=lambda p: p.parent.name if p.name == "jre" else p.name)
def test_java_tls_and_remote_chain(home, tmp_path):
    original = inspect_jvm(home)
    cacerts = tmp_path / "cacerts"
    cacerts.write_bytes(original.cacerts.read_bytes())
    test_jvm = replace(original, cacerts=cacerts, writable=True)
    cert_path, key_path = make_cert(tmp_path)
    server = HTTPServer(("127.0.0.1", 0), Unauthorized)
    server.cert_bytes = cert_path.read_bytes()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://localhost:{server.server_port}/protected"
    try:
        remote = load_url(url)
        assert len(remote) == 1 and remote[0].test_url == url
        assert remote[0].selected_by_default
        direct = load_url(f"https://localhost:{server.server_port}/localhost.crt")
        assert direct[0].sha256 == remote[0].sha256
        ok, detail = probe_tls(test_jvm, url, "changeit")
        assert not ok
        mutate(test_jvm, "jvmcert-https-test", "changeit", "install", remote[0])
        ok, detail = probe_tls(test_jvm, url, "changeit")
        assert ok and "HTTP_STATUS=401" in detail
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_url():
    with pytest.raises(Exception):
        load_url("https://127.0.0.1:1/unreachable")


def test_privileged_batch_reports_independent_results(test_jvm, tmp_path, monkeypatch):
    import jvmcert.elevation as elevation

    cert = load_file(make_cert(tmp_path)[0])[0]
    monkeypatch.setattr(elevation, "inspect_jvm", lambda _home: test_jvm)
    response = tmp_path / "response.json"
    request = tmp_path / "request.json"
    request.write_text(json.dumps({
        "password": "changeit", "response": str(response),
        "jobs": [
            {"home": str(test_jvm.home), "alias": "jvmcert-batch-good", "operation": "install", "der": base64.b64encode(cert.der).decode(), "source": cert.source, "test_url": "", "replace_existing": False},
            {"home": str(test_jvm.home), "alias": "jvmcert-batch-missing", "operation": "remove", "der": None, "source": "", "test_url": "", "replace_existing": False},
        ],
    }), encoding="utf-8")
    assert elevation.privileged_request(request) == 0
    results = json.loads(response.read_text(encoding="utf-8"))["results"]
    assert [item["status"] for item in results] == ["sucesso", "sem alteração"]
    assert entry_fingerprint(test_jvm, "jvmcert-batch-good", "changeit") == cert.sha256
