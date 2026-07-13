"""TLS / certificate inspection plugin using openssl s_client."""
from __future__ import annotations

import re
import ssl
import tempfile

from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)
_ALLOWED_SUBCMDS = {"s_client"}
# openssl s_client flags that read local files / broaden reach -> rejected.
_OPENSSL_BANNED = {
    "-cert", "-key", "-CAfile", "-CApath", "-cert_chain", "-key_chain",
    "-ssl_config", "-config", "-rand", "-writerand", "-sess_out", "-sess_in",
    "-proxy", "-unix", "-preload", "-keylogfile",
}
_STRIP = {"-connect", "-servername", "-showcerts"}


class TlsPlugin(ToolPlugin):
    name = "tls"
    title = "TLS 憑證檢查"
    executable = "openssl"
    dependencies: list[str] = []
    web_required = True
    https_only = True
    default_timeout = 60

    def _connect_target(self, context: RunContext) -> str:
        port = context.target.effective_port or 443
        return f"{context.target.ip}:{port}"

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        return [
            "openssl", "s_client",
            "-connect", self._connect_target(context),
            "-servername", context.target.hostname,
            "-verify_hostname", context.target.hostname,
            "-showcerts",
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        if len(tokens) < 2 or tokens[1] not in _ALLOWED_SUBCMDS:
            raise ExpertCommandError("openssl 僅支援 s_client 子指令。")
        cleaned: list[str] = []
        i = 2
        while i < len(tokens):
            tok = tokens[i]
            if tok in _OPENSSL_BANNED:
                raise ExpertCommandError(f"不允許的 openssl 參數：{tok}")
            if tok in _STRIP:
                # -connect/-servername take a value; -showcerts does not
                if tok in {"-connect", "-servername"}:
                    i += 2
                else:
                    i += 1
                continue
            if not tok.startswith("-"):
                raise ExpertCommandError("openssl s_client 不接受額外位置參數。")
            cleaned.append(tok)
            i += 1
        return [
            "openssl", "s_client",
            "-connect", self._connect_target(context),
            "-servername", context.target.hostname,
            "-verify_hostname", context.target.hostname,
            "-showcerts",
            *cleaned,
        ]

    def parse(self, task, step, workspace) -> ParseResult:
        text = workspace.read_step_text(step, "stdout.log")
        if not text.strip():
            return ParseResult()
        findings: list[dict] = []
        subject = _search(r"subject=([^\n]+)", text)
        issuer = _search(r"issuer=([^\n]+)", text)
        protocol = _search(r"Protocol\s*:\s*([^\n]+)", text)
        cipher = _search(r"Cipher\s*:\s*([^\n]+)", text)
        verify_code = _search(r"Verify return code:\s*([^\n]+)", text)

        not_before = not_after = ""
        sans: list[str] = []
        match = _PEM_RE.search(text)
        if match:
            decoded = _decode_cert(match.group(0))
            if decoded:
                not_before = decoded.get("notBefore", "")
                not_after = decoded.get("notAfter", "")
                for typ, val in decoded.get("subjectAltName", ()):
                    if typ == "DNS":
                        sans.append(val)
                if not subject and decoded.get("subject"):
                    subject = _rdn(decoded["subject"])
                if not issuer and decoded.get("issuer"):
                    issuer = _rdn(decoded["issuer"])

        verified_ok = bool(verify_code and verify_code.strip().startswith("0"))
        evidence_lines = [
            f"Subject: {subject}",
            f"Issuer: {issuer}",
            f"Valid: {not_before} -> {not_after}",
            f"SAN: {', '.join(sans)}",
            f"Protocol: {protocol}",
            f"Cipher: {cipher}",
            f"Verify: {verify_code}",
        ]
        findings.append(
            {
                "severity": "info",
                "confidence": "high",
                "category": "tls",
                "title": f"TLS 憑證資訊（{task.url_hostname}）",
                "description": "目標 HTTPS 憑證與連線參數摘要。",
                "evidence": "\n".join(evidence_lines),
                "source_tool": self.name,
            }
        )
        hostname = task.url_hostname
        host_matches = _hostname_matches(hostname, sans, subject)
        if not verified_ok or not host_matches:
            findings.append(
                {
                    "severity": "low",
                    "confidence": "medium" if verify_code else "low",
                    "category": "tls",
                    "title": "TLS 憑證驗證問題",
                    "description": (
                        "對指定主機名稱的憑證驗證未通過（可能為自簽、過期、"
                        "或主機名稱不符）。請人工確認。"
                    ),
                    "evidence": f"verify={verify_code}; host_match={host_matches}",
                    "source_tool": self.name,
                }
            )
        return ParseResult(findings=findings)


def _search(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ""


def _rdn(rdn_seq) -> str:
    parts = []
    for rdn in rdn_seq:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _hostname_matches(hostname: str, sans: list[str], subject: str) -> bool:
    if not hostname:
        return True
    candidates = list(sans)
    cn = re.search(r"CN\s*=\s*([^,/\n]+)", subject)
    if cn:
        candidates.append(cn.group(1).strip())
    for cand in candidates:
        cand = cand.lower().strip()
        if cand == hostname:
            return True
        if cand.startswith("*.") and hostname.endswith(cand[1:]):
            return True
    return False


def _decode_cert(pem: str) -> dict | None:
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".pem", delete=False, encoding="ascii"
        ) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None
