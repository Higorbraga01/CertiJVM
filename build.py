"""Build a portable folder on the current operating system."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "src" / "jvmcert" / "java"
APP_NAME = "CertiJVM"


def main() -> None:
    source, compiled = JAVA / "TlsProbe.java", JAVA / "TlsProbe.class"
    if not compiled.exists() or source.stat().st_mtime > compiled.stat().st_mtime:
        subprocess.run(["javac", "--release", "8", "-d", str(JAVA), str(source)], check=True)
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--windowed",
        "--name", APP_NAME, "--specpath", str(ROOT / "build"), "--paths", str(ROOT / "src"),
        "--add-data", str(JAVA / "TlsProbe.class") + os.pathsep + "jvmcert/java",
        str(ROOT / "launcher.py"),
    ]
    if os.environ.get("JVMCERT_CLEAN") == "1":
        command.insert(4, "--clean")
    subprocess.run(command, cwd=ROOT, check=True)
    bundle = ROOT / "dist" / APP_NAME
    if os.name == "nt":
        # PyInstaller can accidentally collect a third-party ICU DLL from PATH.
        # Qt6Core on Windows is linked to the OS ICU DLL in System32.
        for name in ("icuuc.dll", "icudt78.dll"):
            (bundle / "_internal" / name).unlink(missing_ok=True)
    executable = bundle / (APP_NAME + (".exe" if os.name == "nt" else ""))
    subprocess.run([str(executable), "--check-qt"], check=True, timeout=20)
    shutil.make_archive(str(ROOT / "dist" / f"{APP_NAME}-{platform.system()}"), "zip", bundle.parent, bundle.name)


if __name__ == "__main__":
    main()
