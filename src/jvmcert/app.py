from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--privileged-request":
        from .elevation import privileged_request

        return privileged_request(Path(sys.argv[2]))
    if len(sys.argv) == 2 and sys.argv[1] == "--check-qt":
        from PySide6.QtWidgets import QWidget  # noqa: F401

        return 0
    from PySide6.QtWidgets import QApplication
    from .ui import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("CertiJVM")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
