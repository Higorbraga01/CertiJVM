from __future__ import annotations

import json
import os
from pathlib import Path


def config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "certijvm" / "config.json"


def legacy_config_path() -> Path:
    return config_path().parent.parent / "jvmcert-manager" / "config.json"


def load_config() -> dict:
    for path in (config_path(), legacy_config_path()):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            return {key: data.get(key, [] if key in ("files", "urls", "manual_jvms") else {}) for key in ("files", "urls", "manual_jvms", "aliases", "test_urls")}
        except (OSError, ValueError, TypeError):
            continue
    return {"files": [], "urls": [], "manual_jvms": [], "aliases": {}, "test_urls": {}}


def save_config(data: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
