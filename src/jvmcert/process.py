"""Run command-line helpers without flashing a console beside the GUI."""
from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence


def run_silent(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NO_WINDOW
    return subprocess.run(command, **kwargs)
