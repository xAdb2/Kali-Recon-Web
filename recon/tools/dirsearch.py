"""Dirsearch content discovery plugin."""
from __future__ import annotations

from ..constants import Profile
from ..parsers.dirsearch import parse_dirsearch_json
from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

# Wordlists baked into the scanner image (see docker/scanner.Dockerfile).
_WORDLIST_DIRS = ("/opt/wordlists/", "/workspace/")
_WORDLISTS = {
    Profile.SAFE: "/opt/wordlists/common.txt",
    Profile.STANDARD: "/opt/wordlists/medium.txt",
}
_BANNED = {"-l", "--urls-file", "--stdin", "--raw", "-r", "--recursive-all",
           "--proxy", "--replay-proxy"}
_STRIP = {"-o", "--output", "--format", "-u", "--url", "-w", "--wordlists"}


class DirsearchPlugin(ToolPlugin):
    name = "dirsearch"
    title = "Dirsearch 內容探索"
    executable = "dirsearch"
    dependencies = ["http_probe"]
    web_required = True
    default_timeout = 600

    def output_files(self, task, step) -> dict[str, str]:
        return {"json": "result.json"}

    def _threads(self, context: RunContext) -> int:
        base = 5 if context.profile == Profile.SAFE else 15
        return min(base, context.limits.get("max_threads", 20))

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        wordlist = _WORDLISTS.get(context.profile, _WORDLISTS[Profile.SAFE])
        return [
            "dirsearch", "-u", context.target.canonical_url,
            "-w", wordlist,
            "-t", str(self._threads(context)),
            "--format=json",
            "-o", context.out_path("result.json"),
            "-q",
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        cleaned: list[str] = []
        url = context.target.canonical_url
        wordlist = _WORDLISTS.get(context.profile, _WORDLISTS[Profile.SAFE])
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _BANNED:
                raise ExpertCommandError(f"不允許的 dirsearch 參數：{tok}")
            if tok in {"-u", "--url"}:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                self._check_url(value, context)
                url = value
                i += 2
                continue
            if tok in {"-w", "--wordlists"}:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                self._check_wordlist(value)
                wordlist = value
                i += 2
                continue
            if tok in _STRIP:
                i += 2
                continue
            if tok.startswith("--format="):
                i += 1
                continue
            # dirsearch has no positional target (URL via -u); bare tokens are
            # values for the preceding flag and are kept in order.
            cleaned.append(tok)
            i += 1
        return [
            "dirsearch", "-u", url, "-w", wordlist,
            *cleaned,
            "--format=json", "-o", context.out_path("result.json"), "-q",
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

    @staticmethod
    def _check_wordlist(path: str) -> None:
        if ".." in path or not path.startswith("/"):
            raise ExpertCommandError("字典檔路徑不合法。")
        if not any(path.startswith(d) for d in _WORDLIST_DIRS):
            raise ExpertCommandError("字典檔僅能來自允許的目錄。")

    def parse(self, task, step, workspace) -> ParseResult:
        text = workspace.read_step_text(step, "result.json")
        endpoints = []
        for item in parse_dirsearch_json(text) if text.strip() else []:
            item["method"] = "GET"
            item["in_scope"] = True
            item["source_tools"] = [self.name]
            endpoints.append(item)
        return ParseResult(endpoints=endpoints)
