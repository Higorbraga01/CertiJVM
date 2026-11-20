from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .models import Jvm
from .process import run_silent


def test_tls(jvm: Jvm, url: str, password: str) -> tuple[bool, str]:
    classes = Path(__file__).parent / "java"
    if not (classes / "TlsProbe.class").is_file():
        return False, "Módulo de teste Java não foi incluído no aplicativo."
    env = os.environ.copy()
    env["JVMCERT_STOREPASS"] = password
    # The Java helper gets the password through an environment variable, never argv.
    command = [str(jvm.java), f"-Djavax.net.ssl.trustStore={jvm.cacerts}", "-cp", str(classes), "TlsProbe", url]
    try:
        result = run_silent(command, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=35)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Falha ao executar teste com a JVM: {exc}"
    output = (result.stdout or result.stderr).strip()
    return result.returncode == 0 and output.startswith("TLS_OK"), output[-500:]
