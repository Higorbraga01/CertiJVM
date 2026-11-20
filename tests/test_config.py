import json

from jvmcert.config import config_path, legacy_config_path, load_config, save_config


def test_legacy_settings_survive_rename(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    old = legacy_config_path()
    old.parent.mkdir(parents=True)
    old.write_text(json.dumps({"files": ["example.crt"], "urls": ["https://example.test"], "manual_jvms": [], "aliases": {"old": "kept"}, "test_urls": {}}), encoding="utf-8")
    data = load_config()
    assert data["files"] == ["example.crt"]
    assert data["aliases"]["old"] == "kept"
    save_config(data)
    assert config_path().is_file()
    assert old.is_file()
    data["urls"] = []
    save_config(data)
    assert load_config()["urls"] == []
