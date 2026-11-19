from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from .certificates import _certificate
from .discovery import inspect_jvm
from .models import Certificate, Jvm, Result
from .store import mutate


def _command(request: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--privileged-request", str(request)]
    return [sys.executable, "-m", "jvmcert.app", "--privileged-request", str(request)]


def run_elevated_batch(jobs: list[tuple[Jvm, str, str, Certificate | None, bool]], password: str) -> list[Result]:
    with tempfile.TemporaryDirectory(prefix="jvmcert-") as directory:
        root = Path(directory)
        if os.name == "nt":
            # A standard user may authenticate UAC with a different admin account.
            subprocess.run(["icacls", str(root), "/grant", "*S-1-5-32-544:(OI)(CI)F"], capture_output=True, check=True)
        request, response = root / "request.json", root / "response.json"
        payload = {"password": password, "response": str(response), "jobs": [
            {"home": str(jvm.home), "alias": alias, "operation": operation,
             "der": base64.b64encode(certificate.der).decode() if certificate else None,
             "source": certificate.source if certificate else "", "test_url": certificate.test_url if certificate else "",
             "replace_existing": replace_existing}
            for jvm, alias, operation, certificate, replace_existing in jobs
        ]}
        request.write_text(json.dumps(payload), encoding="utf-8")
        command = _command(request)
        if os.name == "nt":
            # Paths are PowerShell single-quoted, with embedded apostrophes doubled.
            quote = lambda value: "'" + value.replace("'", "''") + "'"
            arguments = " ".join('"' + value.replace('"', '\\"') + '"' for value in command[1:])
            script = "$p = Start-Process -FilePath " + quote(command[0]) + " -ArgumentList " + quote(arguments) + " -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode"
            process = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=600)
        else:
            process = subprocess.run(["pkexec", *command], capture_output=True, text=True, timeout=600)
        try:
            answer = json.loads(response.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError("Elevação cancelada ou falhou: " + (process.stderr or process.stdout).strip()[-300:]) from exc
        if "error" in answer:
            raise RuntimeError(answer["error"])
        return [Result(**item) for item in answer["results"]]


def run_elevated(jvm: Jvm, alias: str, password: str, operation: str, certificate: Certificate | None, replace_existing: bool) -> Result:
    return run_elevated_batch([(jvm, alias, operation, certificate, replace_existing)], password)[0]


def privileged_request(path: Path) -> int:
    data = None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        results = []
        for job in data["jobs"]:
            try:
                jvm = inspect_jvm(Path(job["home"]))
                certificate = None
                if job.get("der"):
                    certificate = _certificate(base64.b64decode(job["der"]), job["source"], 0, job.get("test_url", ""))
                result = mutate(jvm, job["alias"], data["password"], job["operation"], certificate, job.get("replace_existing", False))
            except Exception as exc:
                result = Result(job["home"], job["alias"], job["operation"], "falha", str(exc))
            results.append(asdict(result))
        answer = {"results": results}
        code = 0
    except Exception as exc:
        answer = {"error": str(exc)}
        code = 1
    try:
        output = Path(data["response"])
        output.write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")
        if os.name != "nt":
            output.chmod(0o644)
    except Exception:
        return 1
    return code
