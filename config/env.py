"""Tiny environment-variable helpers (no external dependency)."""
from __future__ import annotations

import os


def env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value if value is not None else default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_list(name: str, default: list[str] | None = None, sep: str = ",") -> list[str]:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return list(default or [])
    return [item.strip() for item in value.split(sep) if item.strip()]
