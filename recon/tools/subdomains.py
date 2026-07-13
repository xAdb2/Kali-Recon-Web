"""Passive subdomain enumeration (subfinder).

This is OSINT only: it lists subdomains of the target hostname's domain but does
NOT automatically scan them (scope stays on the authorized target). Results are
recorded as an informational finding for manual review.
"""
from __future__ import annotations

from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

_BANNED = {"-dL", "--list", "-config", "-pc", "-provider-config", "-cp",
           "-r", "-rL", "-rlist"}
_STRIP = {"-d", "--domain", "-o", "-output", "-oJ", "-json", "-silent"}


class SubdomainsPlugin(ToolPlugin):
    name = "subdomains"
    title = "子網域列舉"
    executable = "subfinder"
    dependencies: list[str] = []
    web_required = True  # needs a hostname (from the target URL)
    default_timeout = 300

    def output_files(self, task, step) -> dict[str, str]:
        return {"txt": "result.txt"}

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        return [
            "subfinder", "-d", context.target.hostname,
            "-silent", "-o", context.out_path("result.txt"),
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        cleaned: list[str] = []
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _BANNED:
                raise ExpertCommandError(f"不允許的 subfinder 參數：{tok}")
            if tok in {"-d", "--domain", "-o", "-output"}:
                i += 2  # value stripped; enforced below
                continue
            if tok in {"-oJ", "-json", "-silent"}:
                i += 1
                continue
            if not tok.startswith("-"):
                # only the enforced domain is allowed as a target
                i += 1
                continue
            cleaned.append(tok)
            i += 1
        return [
            "subfinder", "-d", context.target.hostname, "-silent",
            *cleaned,
            "-o", context.out_path("result.txt"),
        ]

    def parse(self, task, step, workspace) -> ParseResult:
        text = workspace.read_step_text(step, "result.txt")
        subs = sorted(
            {line.strip().lower() for line in text.splitlines() if line.strip()}
        )
        findings = []
        if subs:
            findings.append(
                {
                    "severity": "info",
                    "confidence": "medium",
                    "category": "subdomain",
                    "title": f"發現 {len(subs)} 個子網域（{task.url_hostname}）",
                    "description": (
                        "被動 OSINT 子網域列舉結果，僅供參考；系統不會自動對這些"
                        "子網域進行掃描（維持在授權目標範圍內）。"
                    ),
                    "evidence": "\n".join(subs)[:4000],
                    "source_tool": self.name,
                }
            )
        return ParseResult(findings=findings)
