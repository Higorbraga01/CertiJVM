from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Jvm:
    home: Path
    java: Path
    keytool: Path
    cacerts: Path
    version: str
    writable: bool


@dataclass(frozen=True)
class Certificate:
    der: bytes
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sha256: str
    source: str
    alias: str
    test_url: str = ""
    valid: bool = True
    selected_by_default: bool = True


@dataclass(frozen=True)
class Result:
    jvm: str
    alias: str
    operation: str
    status: str
    detail: str
