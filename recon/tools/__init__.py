"""Tool plugin registry."""
from __future__ import annotations

from .base import ParseResult, ToolPlugin
from .dirsearch import DirsearchPlugin
from .http_probe import HttpProbePlugin
from .nmap import NmapPortsPlugin, NmapServicesPlugin
from .nuclei import NucleiPlugin
from .subdomains import SubdomainsPlugin
from .tls import TlsPlugin
from .whatweb import WhatWebPlugin

_PLUGIN_CLASSES = [
    NmapPortsPlugin,
    NmapServicesPlugin,
    SubdomainsPlugin,
    HttpProbePlugin,
    WhatWebPlugin,
    TlsPlugin,
    DirsearchPlugin,
    NucleiPlugin,
]

REGISTRY: dict[str, ToolPlugin] = {cls.name: cls() for cls in _PLUGIN_CLASSES}


def get_plugin(name: str) -> ToolPlugin:
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"未知的工具外掛：{name}") from exc


def all_plugins() -> list[ToolPlugin]:
    return list(REGISTRY.values())


__all__ = ["ParseResult", "ToolPlugin", "REGISTRY", "get_plugin", "all_plugins"]
