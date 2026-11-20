from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .certificates import PEM_PATTERN
from .models import Certificate, Jvm, Result
from .process import run_silent


class StoreError(RuntimeError):
    pass


def _keytool(jvm: Jvm, password: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["JVMCERT_STOREPASS"] = password
    command = [str(jvm.keytool), *args, "-keystore", str(jvm.cacerts), "-storepass:env", "JVMCERT_STOREPASS"]
    try:
        return run_silent(command, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoreError(f"Falha ao executar keytool: {exc}") from exc


def _check_password(jvm: Jvm, password: str) -> None:
    result = _keytool(jvm, password, "-list")
    if result.returncode:
        raise StoreError("Não foi possível abrir o cacerts. Verifique a senha e o arquivo. " + (result.stderr or result.stdout).strip()[-350:])


def entry_fingerprint(jvm: Jvm, alias: str, password: str) -> str | None:
    _check_password(jvm, password)
    result = _keytool(jvm, password, "-list", "-rfc", "-alias", alias)
    if result.returncode:
        return None
    blocks = PEM_PATTERN.findall(result.stdout.encode("utf-8"))
    if not blocks:
        raise StoreError(f"A entrada {alias} não é um certificado X.509 legível")
    cert = x509.load_pem_x509_certificate(blocks[0])
    return cert.fingerprint(hashes.SHA256()).hex().upper()


def _backup(jvm: Jvm) -> Path:
    handle, name = tempfile.mkstemp(prefix="jvmcert-backup-", suffix=".cacerts")
    os.close(handle)
    path = Path(name)
    try:
        shutil.copy2(jvm.cacerts, path)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _restore(backup: Path, target: Path) -> None:
    shutil.copy2(backup, target)


def mutate(jvm: Jvm, alias: str, password: str, operation: str, certificate: Certificate | None = None, replace_existing: bool = False) -> Result:
    if operation not in ("install", "remove"):
        raise ValueError("Operação desconhecida")
    if not alias or any(ch in alias for ch in ("\n", "\r", "\x00")):
        raise ValueError("Alias inválido")
    if operation == "install" and (certificate is None or not certificate.valid):
        raise StoreError("Certificado ausente ou fora da validade")
    current = entry_fingerprint(jvm, alias, password)
    if operation == "install" and current == certificate.sha256:
        return Result(str(jvm.home), alias, operation, "sem alteração", "A impressão digital já coincide com o cacerts.")
    if operation == "remove" and current is None:
        return Result(str(jvm.home), alias, operation, "sem alteração", "O alias não existe neste cacerts.")
    if operation == "install" and current and not replace_existing:
        raise StoreError(f"O alias {alias} já existe com outra impressão digital. Confirme a substituição.")
    backup = _backup(jvm)
    preserve_backup = False
    try:
        if current:
            deleted = _keytool(jvm, password, "-delete", "-alias", alias)
            if deleted.returncode:
                raise StoreError("Falha ao remover entrada anterior: " + (deleted.stderr or deleted.stdout).strip()[-350:])
        if operation == "install":
            from cryptography.hazmat.primitives import serialization

            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as handle:
                cert_file = Path(handle.name)
                handle.write(x509.load_der_x509_certificate(certificate.der).public_bytes(serialization.Encoding.PEM))
            try:
                imported = _keytool(jvm, password, "-importcert", "-noprompt", "-alias", alias, "-file", str(cert_file))
                if imported.returncode:
                    raise StoreError("Falha na importação: " + (imported.stderr or imported.stdout).strip()[-350:])
            finally:
                cert_file.unlink(missing_ok=True)
        actual = entry_fingerprint(jvm, alias, password)
        expected = certificate.sha256 if certificate else None
        if actual != expected:
            raise StoreError("A conferência da impressão digital após a operação falhou")
        action = "atualizado" if current else "adicionado"
        if operation == "remove":
            action = "removido"
        return Result(str(jvm.home), alias, operation, "sucesso", f"Certificado {action}; impressão digital conferida.")
    except Exception as exc:
        try:
            _restore(backup, jvm.cacerts)
        except Exception as restore_exc:
            preserve_backup = True
            raise StoreError(f"{exc}. ATENÇÃO: restauração falhou; cópia de segurança em {backup}: {restore_exc}") from exc
        raise
    finally:
        if not preserve_backup:
            backup.unlink(missing_ok=True)
