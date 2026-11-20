from __future__ import annotations

import os
import subprocess
import time
from threading import Event
from pathlib import Path

import pytest

_APP = None


def _qt_app():
    global _APP
    from PySide6.QtWidgets import QApplication
    if _APP is None:
        _APP = QApplication.instance() or QApplication([])
    return _APP


def _pump(app, condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert condition()


def test_discovery_requires_click_and_cancel_discards_results(monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import jvmcert.ui as ui

    monkeypatch.setattr(ui, "load_config", lambda: {"files": [], "urls": [], "manual_jvms": [], "aliases": {}, "test_urls": {}})
    started, release = Event(), Event()
    calls = []

    def fake_discovery(progress, cancelled, extra_homes):
        calls.append(True)
        progress(0, 1, "Verificando JVM")
        started.set()
        release.wait(3)
        return [object()]

    monkeypatch.setattr(ui, "discover_jvms", fake_discovery)
    app = _qt_app()
    window = ui.MainWindow()
    window.show()
    try:
        app.processEvents()
        assert window.windowTitle().startswith("CertiJVM")
        assert calls == [] and window.jvm_table.rowCount() == 0
        window.refresh_button.click()
        _pump(app, started.is_set)
        assert window.progress_panel.isVisible()
        assert not window.refresh_button.isEnabled()
        window.cancel_button.click()
        release.set()
        _pump(app, lambda: window._active_worker is None)
        assert window.jvm_table.rowCount() == 0
        assert window.refresh_button.isEnabled()
        assert window.statusBar().currentMessage() == "Busca cancelada"
    finally:
        release.set()
        window.close()
        _pump(app, lambda: not window._threads)
        window.deleteLater()
        app.processEvents()


def test_runtime_subprocess_is_hidden_on_windows(monkeypatch):
    import jvmcert.process as process

    observed = {}
    def fake_run(command, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(process.subprocess, "run", fake_run)
    process.run_silent(["java", "-version"], capture_output=True)
    if os.name == "nt":
        assert observed["creationflags"] & subprocess.CREATE_NO_WINDOW
    else:
        assert "creationflags" not in observed


def test_review_and_apply_show_progress(monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QMessageBox
    import jvmcert.ui as ui
    from jvmcert.models import Certificate, Jvm, Result

    monkeypatch.setattr(ui, "load_config", lambda: {"files": [], "urls": [], "manual_jvms": [], "aliases": {}, "test_urls": {}})
    monkeypatch.setattr(ui, "save_config", lambda _data: None)
    monkeypatch.setattr(ui, "entry_fingerprint", lambda *_args: None)
    monkeypatch.setattr(ui, "mutate", lambda jvm, alias, *_args: Result(str(jvm.home), alias, "install", "sucesso", "conferido"))
    monkeypatch.setattr(QMessageBox, "question", lambda *_args: QMessageBox.StandardButton.Yes)
    app = _qt_app()
    window = ui.MainWindow()
    window.show()
    try:
        jvm = Jvm(Path("/fake"), Path("/fake/java"), Path("/fake/keytool"), Path("/fake/cacerts"), "17", True)
        cert = Certificate(b"x", "CN=teste", "CN=teste", "2026", "2027", "AA", "teste.crt", "cert")
        window.jvms = [jvm]
        window._render_jvms({str(jvm.cacerts)})
        window._append_certs([cert])
        window.prepare("install")
        assert window.progress_panel.isVisible()
        _pump(app, lambda: window._active_worker is None)
        assert window.review_table.rowCount() == 1
        window.execute()
        assert window.progress_panel.isVisible()
        _pump(app, lambda: window._active_worker is None)
        assert window.result_table.item(0, 3).text() == "sucesso"
    finally:
        window.close()
        _pump(app, lambda: not window._threads)
        window.deleteLater()
        app.processEvents()
