from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .models import Jvm


def _candidate_homes() -> set[Path]:
    homes: set[Path] = set()
    for name in ("JAVA_HOME", "JDK_HOME", "JRE_HOME"):
        if os.environ.get(name):
            homes.add(Path(os.environ[name]))
    for executable in ("java", "keytool"):
        found = shutil.which(executable)
        if found:
            homes.add(Path(found).resolve().parent.parent)
    user = Path.home()
    roots = [user / ".jdks", user / ".sdkman" / "candidates" / "java", user / ".jabba" / "jdk", user / ".asdf" / "installs" / "java"]
    if os.name == "nt":
        roots += [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / p for p in ("Java", "Eclipse Adoptium", "Amazon Corretto", "Microsoft", "Zulu")]
        roots += [Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Java"]
        roots += [user / "AppData" / "Local" / "Programs" / "Eclipse Adoptium"]
    else:
        roots += [Path("/usr/lib/jvm"), Path("/opt/java"), Path("/opt/jdk"), Path("/opt"), Path("/usr/local/lib/jvm")]
    for root in roots:
        if root.is_dir():
            homes.add(root)
            try:
                homes.update(p for p in root.iterdir() if p.is_dir())
            except OSError:
                pass
    if os.name == "nt":
        try:
            import winreg

            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for key_name in (r"SOFTWARE\JavaSoft\JDK", r"SOFTWARE\JavaSoft\Java Development Kit", r"SOFTWARE\JavaSoft\Java Runtime Environment"):
                    try:
                        with winreg.OpenKey(hive, key_name) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                sub = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, sub) as entry:
                                    homes.add(Path(winreg.QueryValueEx(entry, "JavaHome")[0]))
                    except OSError:
                        continue
        except ImportError:
            pass
    return homes


def inspect_jvm(home: Path) -> Jvm:
    home = home.expanduser().resolve()
    suffix = ".exe" if os.name == "nt" else ""
    layouts = (home, home / "jre")
    for base in layouts:
        java, keytool = base / "bin" / ("java" + suffix), base / "bin" / ("keytool" + suffix)
        cacerts = base / "lib" / "security" / "cacerts"
        if java.is_file() and keytool.is_file() and cacerts.is_file():
            try:
                run = subprocess.run([str(java), "-version"], capture_output=True, text=True, timeout=8)
                version = (run.stderr or run.stdout).splitlines()[0]
                match = re.search(r'version "(?:1\.)?(\d+)', version)
                if match and int(match.group(1)) < 8:
                    raise ValueError("Java anterior à versão 8 não é suportado")
            except (OSError, subprocess.TimeoutExpired, IndexError) as exc:
                raise ValueError(f"Não foi possível identificar a JVM: {exc}") from exc
            try:
                with cacerts.open("r+b"):
                    writable = True
            except OSError:
                writable = False
            return Jvm(home=base, java=java, keytool=keytool, cacerts=cacerts.resolve(), version=version, writable=writable)
    raise ValueError(f"JVM com java, keytool e cacerts não encontrada em {home}")


def discover_jvms() -> list[Jvm]:
    found: dict[Path, Jvm] = {}
    for home in _candidate_homes():
        try:
            jvm = inspect_jvm(home)
            found[jvm.cacerts] = jvm
        except (ValueError, OSError):
            continue
    return sorted(found.values(), key=lambda item: str(item.home).lower())
