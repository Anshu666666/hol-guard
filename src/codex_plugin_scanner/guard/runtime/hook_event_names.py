"""Normalize hook event identity without command-dispatch dependencies."""

from __future__ import annotations

_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
}


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(normalized.lower(), normalized)
    return None
