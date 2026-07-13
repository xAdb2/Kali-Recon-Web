"""HTTP baseline probe using curl.

The scanner container receives an ``extra_hosts`` mapping (hostname -> task IP),
so the TCP connection reaches the user-supplied IP while SNI and the Host header
use the user-supplied hostname. Redirects are NOT followed automatically.
"""
from __future__ import annotations

import json
import re

from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

_USER_AGENT = "KaliRecon/1.0 (+authorized-recon)"
_WRITEOUT = (
    '{"status":%{http_code},"content_type":"%{content_type}",'
    '"size_download":%{size_download},"redirect_url":"%{redirect_url}",'
    '"url_effective":"%{url_effective}","ssl_verify":%{ssl_verify_result},'
    '"num_redirects":%{num_redirects}}'
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_CURL_BANNED_EXACT = {
    "-F", "--form", "-T", "--upload-file", "-x", "--proxy", "--preproxy",
    "--unix-socket", "--abstract-unix-socket", "-K", "--config",
    "--cert", "--key", "--cacert", "--netrc", "--netrc-file",
}
_CURL_STRIP = {"-o", "--output", "-D", "--dump-header", "-w", "--write-out",
               "-A", "--user-agent", "--url"}


class HttpProbePlugin(ToolPlugin):
    name = "http_probe"
    title = "HTTP 基線探測"
    executable = "curl"
    dependencies: list[str] = []
    web_required = True
    default_timeout = 120

    def output_files(self, task, step) -> dict[str, str]:
        return {"headers": "headers.txt", "body": "body.bin"}

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        return [
            "curl", "-sS", "-A", _USER_AGENT,
            "--connect-timeout", "10", "--max-time", "45",
            "-o", context.out_path("body.bin"),
            "-D", context.out_path("headers.txt"),
            "-w", _WRITEOUT,
            context.target.canonical_url,
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        cleaned: list[str] = []
        url_seen = False
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in _CURL_BANNED_EXACT:
                raise ExpertCommandError(f"不允許的 curl 參數：{tok}")
            if tok in _CURL_STRIP:
                i += 2
                continue
            if tok.startswith("@") or tok.startswith("--data") and "@" in tok:
                raise ExpertCommandError("不允許從檔案讀取請求內容。")
            if tok in {"-d", "--data", "--data-binary", "--data-raw",
                       "--data-urlencode"}:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                if value.startswith("@"):
                    raise ExpertCommandError("不允許 --data @file。")
                cleaned.extend([tok, value])
                i += 2
                continue
            if not tok.startswith("-"):
                if "://" in tok or tok.lower().startswith(("http://", "https://")) \
                        or "." in tok:
                    self._check_url(tok, context)
                    url_seen = True
                    url = tok
                else:
                    cleaned.append(tok)  # value of the preceding flag
                i += 1
                continue
            cleaned.append(tok)
            i += 1
        if not url_seen:
            url = context.target.canonical_url
        return [
            "curl", "-sS", "-A", _USER_AGENT,
            "--connect-timeout", "10", "--max-time", "45",
            *cleaned,
            "-o", context.out_path("body.bin"),
            "-D", context.out_path("headers.txt"),
            "-w", _WRITEOUT,
            url,
        ]

    @staticmethod
    def _check_url(url: str, context: RunContext) -> None:
        low = url.lower()
        if low.startswith(("file:", "ftp:", "gopher:", "dict:", "scp:", "telnet:")):
            raise ExpertCommandError("僅允許 http/https URL。")
        if not low.startswith(("http://", "https://")):
            raise ExpertCommandError("僅允許 http/https URL。")
        from ..services.target import normalize_url

        try:
            _scheme, hostname, _port, _path = normalize_url(url)
        except Exception as exc:  # noqa: BLE001
            raise ExpertCommandError(f"URL 無效：{exc}") from exc
        if hostname != context.target.hostname:
            raise ExpertCommandError(
                f"URL 主機必須是授權目標 {context.target.hostname}。"
            )

    def parse(self, task, step, workspace) -> ParseResult:
        stdout = workspace.read_step_text(step, "stdout.log")
        meta = {}
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    meta = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        headers_text = workspace.read_step_text(step, "headers.txt")
        content_type = meta.get("content_type", "")
        redirect = meta.get("redirect_url", "") or ""
        # Extract a title from the (possibly binary) body, best-effort.
        title = ""
        body = workspace.read_step_text(step, "body.bin")
        if body:
            match = _TITLE_RE.search(body)
            if match:
                title = re.sub(r"\s+", " ", match.group(1)).strip()[:500]

        endpoint = {
            "url": meta.get("url_effective") or context_url(task),
            "method": "GET",
            "status_code": meta.get("status"),
            "title": title,
            "content_length": meta.get("size_download"),
            "content_type": content_type,
            "redirect_location": redirect,
            "in_scope": True,
            "source_tools": [self.name],
        }
        findings: list[dict] = []
        # Out-of-scope redirect is recorded as an informational finding, not
        # followed automatically.
        if redirect:
            from ..services.target import normalize_url

            try:
                _s, rhost, _p, _pa = normalize_url(redirect)
                if rhost != task.url_hostname:
                    findings.append(
                        {
                            "severity": "info",
                            "confidence": "high",
                            "category": "redirect",
                            "title": f"重新導向至範圍外主機 {rhost}",
                            "description": (
                                "目標回應了指向授權範圍外主機的重新導向，"
                                "已記錄但未自動跟隨。"
                            ),
                            "evidence": redirect,
                            "source_tool": self.name,
                        }
                    )
            except Exception:  # noqa: BLE001
                pass
        _ = headers_text
        return ParseResult(endpoints=[endpoint], findings=findings)


def context_url(task) -> str:
    if task.url_scheme and task.url_hostname:
        netloc = task.url_hostname
        if task.url_port:
            netloc = f"{task.url_hostname}:{task.url_port}"
        return f"{task.url_scheme}://{netloc}{task.url_base_path or '/'}"
    return ""
