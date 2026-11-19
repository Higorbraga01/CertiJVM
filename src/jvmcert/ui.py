from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QTabWidget, QComboBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .certificates import load_file, load_url
from .config import load_config, save_config
from .discovery import discover_jvms, inspect_jvm
from .elevation import run_elevated_batch
from .models import Certificate, Jvm, Result
from .store import entry_fingerprint, mutate
from .tls import test_tls


class Worker(QObject):
    done = Signal(object, object)

    def __init__(self, function):
        super().__init__()
        self.function = function

    def run(self):
        try:
            self.done.emit(self.function(), None)
        except Exception as exc:
            self.done.emit(None, str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Certificados JVM")
        self.resize(1260, 780)
        self.config = load_config()
        self.jvms: list[Jvm] = []
        self.certs: list[Certificate] = []
        self.plan: list[tuple[Jvm, Certificate, str, str]] = []
        self.operation = "install"
        self._threads: list[QThread] = []
        self._workers: list[Worker] = []
        self._build()
        self.refresh_jvms()
        self._load_saved_files()

    def _build(self):
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        title = QLabel("Gerenciador de certificados JVM")
        title.setObjectName("title")
        main.addWidget(title)
        main.addWidget(QLabel("Selecione JVMs e certificados, revise cada alteração e execute com conferência automática."))
        self.tabs = QTabWidget()
        main.addWidget(self.tabs)
        self.statusBar().showMessage("Pronto")

        jvm_page = QWidget(); jvm_layout = QVBoxLayout(jvm_page)
        jvm_layout.addWidget(QLabel("Instalações Java encontradas neste computador"))
        self.jvm_table = self._table(["Selecionar", "Versão", "JVM", "cacerts", "Gravação"])
        jvm_layout.addWidget(self.jvm_table)
        row = QHBoxLayout()
        self.refresh_button = QPushButton("Buscar JVMs novamente")
        self.refresh_button.clicked.connect(self.refresh_jvms)
        row.addWidget(self.refresh_button)
        manual = QPushButton("Adicionar JVM manualmente")
        manual.clicked.connect(self.add_jvm)
        row.addWidget(manual); row.addStretch()
        jvm_layout.addLayout(row)
        self.tabs.addTab(jvm_page, "1. JVMs")

        cert_page = QWidget(); cert_layout = QVBoxLayout(cert_page)
        cert_layout.addWidget(QLabel("Arquivos locais e certificados apresentados por servidores HTTPS"))
        row = QHBoxLayout()
        add_files = QPushButton("Escolher arquivos…"); add_files.clicked.connect(self.add_files)
        row.addWidget(add_files)
        self.url_input = QComboBox(); self.url_input.setEditable(True)
        self.url_input.addItems(self.config["urls"])
        self.url_input.lineEdit().setPlaceholderText("https://servidor.exemplo/caminho ou https://servidor/certificado.crt")
        row.addWidget(self.url_input, 1)
        fetch = QPushButton("Buscar URL"); fetch.clicked.connect(self.fetch_url)
        row.addWidget(fetch)
        forget = QPushButton("Excluir URL"); forget.clicked.connect(self.forget_url)
        row.addWidget(forget)
        cert_layout.addLayout(row)
        self.cert_table = self._table(["Selecionar", "Alias (editável)", "Origem", "Assunto", "Emissor", "Válido de", "Válido até", "SHA-256", "URL de teste (editável)"])
        cert_layout.addWidget(self.cert_table)
        row = QHBoxLayout()
        remove = QPushButton("Remover itens da lista"); remove.clicked.connect(self.remove_items)
        row.addWidget(remove)
        row.addWidget(QLabel("Certificados inválidos podem ser selecionados apenas para remoção.")); row.addStretch()
        cert_layout.addLayout(row)
        self.tabs.addTab(cert_page, "2. Certificados")

        review_page = QWidget(); review_layout = QVBoxLayout(review_page)
        row = QHBoxLayout()
        row.addWidget(QLabel("Senha do cacerts:"))
        self.password = QLineEdit("changeit"); self.password.setEchoMode(QLineEdit.EchoMode.Password)
        row.addWidget(self.password)
        self.remove_alias = QLineEdit(); self.remove_alias.setPlaceholderText("Alias avulso para remover (opcional)")
        row.addWidget(self.remove_alias)
        prepare_install = QPushButton("Revisar adição / atualização"); prepare_install.clicked.connect(lambda: self.prepare("install"))
        row.addWidget(prepare_install)
        prepare_remove = QPushButton("Revisar remoção"); prepare_remove.clicked.connect(lambda: self.prepare("remove"))
        row.addWidget(prepare_remove)
        review_layout.addLayout(row)
        self.review_table = self._table(["JVM", "Alias", "Operação", "Estado atual", "Novo estado"])
        review_layout.addWidget(self.review_table)
        self.run_button = QPushButton("Executar alterações revisadas")
        self.run_button.setEnabled(False); self.run_button.clicked.connect(self.execute)
        review_layout.addWidget(self.run_button)
        self.tabs.addTab(review_page, "3. Revisão")

        result_page = QWidget(); result_layout = QVBoxLayout(result_page)
        result_layout.addWidget(QLabel("Resultado por certificado e JVM"))
        self.result_table = self._table(["JVM", "Alias", "Operação", "Estado", "Detalhe"])
        result_layout.addWidget(self.result_table)
        self.tabs.addTab(result_page, "4. Resultados")

        self.setStyleSheet("""
            QMainWindow, QWidget { background: #f6f8fb; color: #172033; font-size: 13px; }
            QLabel#title { font-size: 25px; font-weight: 700; padding: 8px 0; }
            QTabWidget::pane { border: 1px solid #d8e0e9; background: white; }
            QTabBar::tab { padding: 11px 20px; background: #e8edf4; margin-right: 3px; }
            QTabBar::tab:selected { background: white; color: #1453a3; font-weight: 700; }
            QPushButton { background: #175fac; color: white; border: 0; border-radius: 5px; padding: 9px 14px; }
            QPushButton:hover { background: #0f4d91; }
            QPushButton:disabled { background: #aeb8c5; }
            QLineEdit { background: white; border: 1px solid #bac6d5; border-radius: 4px; padding: 7px; }
            QTableWidget { background: white; gridline-color: #e6ebf0; alternate-background-color: #f7faff; }
        """)

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        return table

    @staticmethod
    def _item(text: str, editable: bool = False, checked: bool | None = None) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if editable:
            flags |= Qt.ItemFlag.ItemIsEditable
        if checked is not None:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
            item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        item.setFlags(flags)
        item.setToolTip(text)
        return item

    def _background(self, function, callback):
        thread = QThread(self)
        worker = Worker(function)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.done.connect(callback)
        worker.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        worker.done.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self._threads.remove(thread) if thread in self._threads else None)
        thread.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        self._threads.append(thread)
        self._workers.append(worker)
        thread.start()

    def closeEvent(self, event):
        for thread in list(self._threads):
            thread.quit()
            if not thread.wait(20000):
                event.ignore()
                self.statusBar().showMessage("Aguarde a operação em andamento terminar antes de fechar")
                return
        super().closeEvent(event)

    def refresh_jvms(self):
        self.statusBar().showMessage("Buscando JVMs…")
        self._background(discover_jvms, self._jvms_ready)

    def _jvms_ready(self, found, error):
        if error:
            self._error(error); return
        selected = {str(self.jvms[i].cacerts) for i in range(len(self.jvms)) if i < self.jvm_table.rowCount() and self.jvm_table.item(i, 0).checkState() == Qt.CheckState.Checked}
        by_store = {str(j.cacerts): j for j in found}
        for path in self.config["manual_jvms"]:
            try:
                jvm = inspect_jvm(Path(path)); by_store[str(jvm.cacerts)] = jvm
            except (OSError, ValueError):
                pass
        self.jvms = list(by_store.values())
        self.jvm_table.setRowCount(len(self.jvms))
        for i, jvm in enumerate(self.jvms):
            values = ["", jvm.version, str(jvm.home), str(jvm.cacerts), "Direta" if jvm.writable else "Elevação necessária"]
            for col, value in enumerate(values):
                self.jvm_table.setItem(i, col, self._item(value, checked=str(jvm.cacerts) in selected if col == 0 else None))
        self.statusBar().showMessage(f"{len(self.jvms)} JVM(s) encontrada(s)")

    def add_jvm(self):
        path = QFileDialog.getExistingDirectory(self, "Selecione a pasta da JDK/JRE")
        if not path:
            return
        try:
            jvm = inspect_jvm(Path(path))
        except (OSError, ValueError) as exc:
            self._error(str(exc)); return
        if str(jvm.home) not in self.config["manual_jvms"]:
            self.config["manual_jvms"].append(str(jvm.home)); save_config(self.config)
        self._jvms_ready(self.jvms, None)
        for i, item in enumerate(self.jvms):
            if item.cacerts == jvm.cacerts:
                self.jvm_table.item(i, 0).setCheckState(Qt.CheckState.Checked)

    def _load_saved_files(self):
        for path in self.config["files"]:
            try:
                self._append_certs(load_file(Path(path)))
            except Exception:
                continue

    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Selecione certificados", "", "Certificados (*.crt *.cer *.pem)")
        for path in paths:
            try:
                self._append_certs(load_file(Path(path)))
                if path not in self.config["files"]:
                    self.config["files"].append(path)
            except Exception as exc:
                self._error(f"{path}: {exc}")
        save_config(self.config)

    def fetch_url(self):
        url = self.url_input.currentText().strip()
        if not url:
            return
        self.statusBar().showMessage("Obtendo certificados da URL…")
        self._background(lambda: load_url(url), lambda certs, error: self._url_ready(url, certs, error))

    def _url_ready(self, url, certs, error):
        if error:
            self._error(error); return
        self._append_certs(certs)
        if url not in self.config["urls"]:
            self.config["urls"].append(url); self.url_input.addItem(url); save_config(self.config)
        self.statusBar().showMessage(f"{len(certs)} certificado(s) obtido(s) da URL")

    def forget_url(self):
        url = self.url_input.currentText().strip()
        if url in self.config["urls"]:
            self.config["urls"].remove(url)
            index = self.url_input.findText(url)
            if index >= 0:
                self.url_input.removeItem(index)
            save_config(self.config)
        self.url_input.setEditText("")

    def _append_certs(self, certs: list[Certificate]):
        existing = {(c.source, c.sha256) for c in self.certs}
        for cert in certs:
            if (cert.source, cert.sha256) in existing:
                continue
            row = len(self.certs)
            self.certs.append(cert)
            self.cert_table.insertRow(row)
            values = ["", self.config["aliases"].get(cert.alias, cert.alias), cert.source, cert.subject, cert.issuer, cert.not_before, cert.not_after + (" ⚠ VENCIDO / INVÁLIDO" if not cert.valid else ""), cert.sha256, self.config["test_urls"].get(cert.alias, cert.test_url)]
            for col, value in enumerate(values):
                self.cert_table.setItem(row, col, self._item(value, editable=col in (1, 8), checked=cert.valid and cert.selected_by_default if col == 0 else None))
            if not cert.valid:
                self.cert_table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
            existing.add((cert.source, cert.sha256))

    def remove_items(self):
        selected = set(self.cert_table.selectionModel().selectedRows())
        indexes = sorted((index.row() for index in selected), reverse=True)
        for row in indexes:
            self.certs.pop(row); self.cert_table.removeRow(row)
        sources = {c.source for c in self.certs}
        self.config["files"] = [x for x in self.config["files"] if x in sources]
        self.config["urls"] = [x for x in self.config["urls"] if x in sources]
        self.url_input.clear(); self.url_input.addItems(self.config["urls"])
        save_config(self.config)

    def _selected(self):
        jvms = [j for i, j in enumerate(self.jvms) if self.jvm_table.item(i, 0).checkState() == Qt.CheckState.Checked]
        certs = []
        for i, cert in enumerate(self.certs):
            if self.cert_table.item(i, 0).checkState() == Qt.CheckState.Checked:
                alias = self.cert_table.item(i, 1).text().strip()
                url = self.cert_table.item(i, 8).text().strip()
                self.config["aliases"][cert.alias] = alias
                self.config["test_urls"][cert.alias] = url
                certs.append(replace(cert, alias=alias, test_url=url))
        save_config(self.config)
        return jvms, certs

    def prepare(self, operation: str):
        jvms, certs = self._selected()
        if operation == "remove" and self.remove_alias.text().strip():
            alias = self.remove_alias.text().strip()
            certs.append(Certificate(b"", "", "", "", "", "", "Manual", alias))
        if not jvms or not certs:
            self._error("Selecione ao menos uma JVM e um certificado válido."); return
        if not self.password.text():
            self._error("Informe a senha do cacerts."); return
        if any(not c.alias or "\n" in c.alias for c in certs):
            self._error("Corrija os aliases vazios ou inválidos."); return
        if len({c.alias.lower() for c in certs}) != len(certs):
            self._error("Há aliases repetidos na seleção. Use um alias diferente para cada certificado."); return
        if any("\r" in c.alias or "\x00" in c.alias for c in certs):
            self._error("Corrija os aliases inválidos."); return
        if operation == "install" and any(not c.valid for c in certs):
            self._error("Certificados vencidos ou ainda não válidos não podem ser importados."); return
        if operation == "install" and any(c.test_url and (urlparse(c.test_url).scheme != "https" or not urlparse(c.test_url).hostname) for c in certs):
            self._error("As URLs de teste devem começar com https:// e informar um servidor."); return
        self.operation = operation
        password = self.password.text()
        self.statusBar().showMessage("Conferindo entradas existentes…")
        def work():
            return [(j, c, entry_fingerprint(j, c.alias, password)) for j in jvms for c in certs]
        self._background(work, self._review_ready)

    def _review_ready(self, rows, error):
        if error:
            self._error(error); return
        self.plan = []
        self.review_table.setRowCount(len(rows))
        for i, (jvm, cert, existing) in enumerate(rows):
            if self.operation == "remove":
                action = "Remover" if existing else "Sem alteração"
            else:
                action = "Adicionar" if not existing else ("Sem alteração" if existing == cert.sha256 else "Substituir")
            self.plan.append((jvm, cert, existing or "", action))
            values = [str(jvm.home), cert.alias, action, existing or "Ausente", "Ausente" if self.operation == "remove" else cert.sha256]
            for col, value in enumerate(values):
                self.review_table.setItem(i, col, self._item(value))
        self.run_button.setEnabled(bool(self.plan))
        self.tabs.setCurrentIndex(2)
        self.statusBar().showMessage(f"{len(self.plan)} operação(ões) revisada(s)")

    def execute(self):
        replacements = sum(action == "Substituir" for _, _, _, action in self.plan)
        message = f"Executar {len(self.plan)} operação(ões) nas JVMs selecionadas?"
        if replacements:
            message += f"\n{replacements} alias(es) existente(s) serão substituídos após cópia de segurança."
        if QMessageBox.question(self, "Confirmar alterações", message) != QMessageBox.StandardButton.Yes:
            return
        plan = list(self.plan); operation = self.operation; password = self.password.text()
        self.run_button.setEnabled(False)
        self.statusBar().showMessage("Aplicando alterações e testando…")
        def work():
            results: list[Result | None] = [None] * len(plan)
            protected = [(i, jvm, cert, action) for i, (jvm, cert, _, action) in enumerate(plan) if not jvm.writable]
            if protected:
                try:
                    jobs = [(jvm, cert.alias, operation, cert if operation == "install" else None, action == "Substituir") for _, jvm, cert, action in protected]
                    elevated = run_elevated_batch(jobs, password)
                    for (i, _, _, _), item in zip(protected, elevated):
                        results[i] = item
                except Exception as exc:
                    for i, jvm, cert, _ in protected:
                        results[i] = Result(str(jvm.home), cert.alias, operation, "falha", str(exc))
            for i, (jvm, cert, _, action) in enumerate(plan):
                if results[i] is None:
                    try:
                        results[i] = mutate(jvm, cert.alias, password, operation, cert if operation == "install" else None, action == "Substituir")
                    except Exception as exc:
                        results[i] = Result(str(jvm.home), cert.alias, operation, "falha", str(exc))
                result = results[i]
                if operation == "install" and result.status in ("sucesso", "sem alteração"):
                    if cert.test_url:
                        ok, detail = test_tls(jvm, cert.test_url, password)
                        results[i] = Result(result.jvm, result.alias, result.operation, "sucesso" if ok else "TLS falhou", result.detail + " Teste Java: " + detail)
                    else:
                        results[i] = Result(result.jvm, result.alias, result.operation, result.status, result.detail + " Sem URL: verificação do truststore apenas.")
            return results
        self._background(work, self._results_ready)

    def _results_ready(self, results, error):
        self.run_button.setEnabled(True)
        if error:
            self._error(error); return
        self.result_table.setRowCount(len(results))
        for i, result in enumerate(results):
            for col, value in enumerate((result.jvm, result.alias, result.operation, result.status, result.detail)):
                self.result_table.setItem(i, col, self._item(value))
        self.tabs.setCurrentIndex(3)
        success = sum(r.status in ("sucesso", "sem alteração") for r in results)
        self.statusBar().showMessage(f"Concluído: {success}/{len(results)} sem falha")

    def _error(self, message: str):
        self.statusBar().showMessage("Erro")
        QMessageBox.warning(self, "Certificados JVM", message)
