from __future__ import annotations

import os


def process_is_alive(process_id: int) -> bool:
    if os.name == "nt":
        from codex_plugin_scanner.guard.windows_paths import windows_process_is_running

        return windows_process_is_running(process_id)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True
