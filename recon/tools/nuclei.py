"""Nuclei conservative reconnaissance plugin."""
from __future__ import annotations

from ..parsers.nuclei import parse_nuclei_jsonl
from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

_ALLOWED_TAGS = {"tech", "technologies", "exposure", "exposures",
                 "misconfiguration", "misconfig", "ssl", "http"}
_BANNED_TAGS = {"dos", "fuzz", "fuzzing", "intrusive", "brute-force",
                "bruteforce", "sqli", "rce", "xss", "lfi"}
_BANNED_FLAGS = {
    "-headless", "-code", "-w", "-workflows", "-workflow-list",
    "-l", "-list", "-target-list", "-resume", "-irr", "-passive",
    "-interactsh-server", "-iserver", "-t", "-templates",
    "-tl", "-template-url", "-cc", "-code-templates",
}
_STRIP = {"-o", "-output", "-json", "-jsonl", "-je", "-jexport",
          "-u", "-target", "-tags", "-severity", "-rl", "-rate-limit"}
_TEMPLATE_DIR = "/opt/nuclei-templates"


class NucleiPlugin(ToolPlugin):
    name = "nuclei"
    title = "Nuclei 偵察檢查"
    executable = "nuclei"
    dependencies = ["http_probe"]
    web_required = True
    default_timeout = 900

    def output_files(self, task, step) -> dict[str, str]:
        return {"jsonl": "result.jsonl"}

    def _base_flags(self, context: RunContext) -> list[str]:
        rate = min(context.rate_limit, context.limits.get("max_rate", 200))
        return [
            "-tags", "tech,exposure,misconfiguration",
            "-exclude-tags", "dos,fuzz,intrusive,brute-force",
            "-severity", "info,low,medium,high,critical",
            "-rl", str(rate),
            "-timeout", "10",
            "-disable-update-check",
            "-no-interactsh",
            "-templates", _TEMPLATE_DIR,
        ]

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        return [
            "nuclei", "-u", context.target.canonical_url,
            *self._base_flags(context),
            "-jsonl", "-o", context.out_path("result.jsonl"),
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        cleaned: list[str] = []
        url = context.target.canonical_url
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _BANNED_FLAGS:
                raise ExpertCommandError(f"不允許的 nuclei 參數：{tok}")
            if tok in {"-u", "-target"}:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                self._check_url(value, context)
                url = value
                i += 2
                continue
            if tok == "-tags":
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                self._check_tags(value)
                i += 2
                continue
            if tok in _STRIP:
                i += 2
                continue
            # nuclei targets via -u; bare tokens are values for the preceding
            # flag and are preserved in order.
            cleaned.append(tok)
            i += 1
        return [
            "nuclei", "-u", url,
            *self._base_flags(context),
            *cleaned,
            "-jsonl", "-o", context.out_path("result.jsonl"),
        ]

    @staticmethod
    def _check_tags(value: str) -> None:
        for tag in value.split(","):
            tag = tag.strip().lower()
            if not tag:
                continue
            if tag in _BANNED_TAGS:
                raise ExpertCommandError(f"不允許的 nuclei 標籤：{tag}")
            if tag not in _ALLOWED_TAGS:
                raise ExpertCommandError(f"nuclei 標籤 {tag} 不在允許清單內。")

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
        text = workspace.read_step_text(step, "result.jsonl")
        findings = []
        for item in parse_nuclei_jsonl(text) if text else []:
            findings.append(
                {
                    "severity": item["severity"],
                    "confidence": "medium",
                    "category": item.get("category", "nuclei"),
                    "title": item["title"],
                    "description": item.get("description", ""),
                    "evidence": str(item.get("evidence", ""))[:2000],
                    "remediation": item.get("remediation", ""),
                    "source_tool": self.name,
                }
            )
        return ParseResult(findings=findings)
