"""WhatWeb fingerprinting plugin."""
from __future__ import annotations

import json

from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin
from .http_probe import context_url

_UA = "KaliRecon/1.0"
_BANNED = {"-i", "--input-file", "--proxy", "--proxy-user", "--cookie",
           "--log-errors"}
_STRIP_PREFIX = ("--log-",)


class WhatWebPlugin(ToolPlugin):
    name = "whatweb"
    title = "WhatWeb 指紋辨識"
    executable = "whatweb"
    dependencies = ["http_probe"]
    web_required = True
    default_timeout = 180

    def output_files(self, task, step) -> dict[str, str]:
        return {"json": "result.json"}

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        return [
            "whatweb", "-a", "3", "--user-agent", _UA,
            f"--log-json={context.out_path('result.json')}",
            context.target.canonical_url,
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        cleaned: list[str] = []
        url = context.target.canonical_url
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _BANNED:
                raise ExpertCommandError(f"不允許的 whatweb 參數：{tok}")
            if any(tok.startswith(p) for p in _STRIP_PREFIX):
                # strip user log flags (=form or space form) and re-inject
                if "=" not in tok:
                    i += 2
                    continue
                i += 1
                continue
            if not tok.startswith("-"):
                if tok.lower().startswith(("http://", "https://")) or "." in tok:
                    self._check_url(tok, context)
                    url = tok
                else:
                    cleaned.append(tok)  # value of the preceding flag
                i += 1
                continue
            cleaned.append(tok)
            i += 1
        return [
            "whatweb", *cleaned, "--user-agent", _UA,
            f"--log-json={context.out_path('result.json')}", url,
        ]

    @staticmethod
    def _check_url(url: str, context: RunContext) -> None:
        from ..services.target import normalize_url

        try:
            _s, hostname, _p, _pa = normalize_url(url)
        except Exception as exc:  # noqa: BLE001
            raise ExpertCommandError(f"URL 無效：{exc}") from exc
        if hostname != context.target.hostname:
            raise ExpertCommandError(
                f"URL 主機必須是授權目標 {context.target.hostname}。"
            )

    def parse(self, task, step, workspace) -> ParseResult:
        text = workspace.read_step_text(step, "result.json")
        findings: list[dict] = []
        endpoints: list[dict] = []
        if not text.strip():
            return ParseResult()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ParseResult()
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            if not isinstance(entry, dict):
                continue
            plugins = entry.get("plugins", {}) or {}
            title = ""
            status = entry.get("http_status")
            if isinstance(plugins.get("Title"), dict):
                strings = plugins["Title"].get("string") or []
                if strings:
                    title = str(strings[0])[:500]
            techs = []
            for pname, pdata in plugins.items():
                if pname in {"Title", "HTTPServer", "IP", "Country"}:
                    continue
                version = ""
                if isinstance(pdata, dict) and pdata.get("version"):
                    version = ",".join(str(v) for v in pdata["version"])
                techs.append(f"{pname} {version}".strip())
            endpoints.append(
                {
                    "url": entry.get("target") or context_url(task),
                    "method": "GET",
                    "status_code": status,
                    "title": title,
                    "in_scope": True,
                    "source_tools": [self.name],
                }
            )
            if techs:
                findings.append(
                    {
                        "severity": "info",
                        "confidence": "medium",
                        "category": "technology",
                        "title": "偵測到的網站技術",
                        "description": "WhatWeb 指紋辨識結果（僅供參考）。",
                        "evidence": "; ".join(sorted(techs))[:2000],
                        "source_tool": self.name,
                    }
                )
        return ParseResult(endpoints=endpoints, findings=findings)
