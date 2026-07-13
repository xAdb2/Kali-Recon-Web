"""Target IP and URL validation / normalization.

The parser is intentionally strict: it rejects anything that could smuggle a
second target, shell syntax, or an out-of-scope host into a scanner command.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class TargetValidationError(ValueError):
    """Raised when a target IP or URL is invalid or out of scope."""


@dataclass(frozen=True)
class ParsedTarget:
    ip: str
    scheme: str = ""
    hostname: str = ""
    port: int | None = None
    base_path: str = "/"
    original_url: str = ""

    @property
    def has_url(self) -> bool:
        return bool(self.scheme and self.hostname)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def effective_port(self) -> int | None:
        if self.port is not None:
            return self.port
        return DEFAULT_PORTS.get(self.scheme)

    @property
    def canonical_url(self) -> str:
        if not self.has_url:
            return ""
        netloc = self.hostname
        if self.port is not None and self.port != DEFAULT_PORTS.get(self.scheme):
            netloc = f"{self.hostname}:{self.port}"
        return f"{self.scheme}://{netloc}{self.base_path}"

    @property
    def host_for_header(self) -> str:
        if self.port is not None and self.port != DEFAULT_PORTS.get(self.scheme):
            return f"{self.hostname}:{self.port}"
        return self.hostname


def normalize_ip(raw: str) -> str:
    """Validate a single IPv4/IPv6 literal and return its normalized form."""
    if raw is None:
        raise TargetValidationError("目標 IP 不可為空。")
    if _CONTROL_CHARS.search(raw):
        raise TargetValidationError("目標 IP 含有非法控制字元。")
    value = raw.strip()
    if not value:
        raise TargetValidationError("目標 IP 不可為空。")
    if "/" in value:
        raise TargetValidationError("MVP 不接受 CIDR 範圍，請輸入單一 IP。")
    if any(c.isspace() for c in value):
        raise TargetValidationError("目標 IP 不可包含空白或多個目標。")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetValidationError(f"無效的 IP 位址：{value}") from exc
    return str(addr)


def _validate_hostname(hostname: str) -> str:
    if not hostname:
        raise TargetValidationError("目標 URL 缺少主機名稱。")
    # Reject an IP-literal-looking bracket host inconsistencies handled by urlsplit.
    try:
        idna = hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Hostnames that are already ASCII (or plain) fall through.
        idna = hostname
    idna = idna.lower().rstrip(".")
    if not idna:
        raise TargetValidationError("目標 URL 主機名稱無效。")
    if _CONTROL_CHARS.search(idna):
        raise TargetValidationError("主機名稱含有非法字元。")
    if not re.fullmatch(r"[a-z0-9._\-\[\]:]+", idna):
        raise TargetValidationError("主機名稱含有不支援的字元。")
    return idna


def normalize_url(raw: str) -> tuple[str, str, int | None, str]:
    """Return (scheme, hostname, port, base_path) for a validated http(s) URL."""
    if raw is None:
        raise TargetValidationError("目標 URL 不可為空。")
    value = raw.strip()
    if not value:
        raise TargetValidationError("目標 URL 不可為空。")
    if _CONTROL_CHARS.search(value):
        raise TargetValidationError("目標 URL 含有非法控制字元。")
    if _BAD_PERCENT.search(value):
        raise TargetValidationError("目標 URL 含有格式錯誤的百分比編碼。")

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("僅支援 http 與 https。")
    if parts.username or parts.password or "@" in parts.netloc:
        raise TargetValidationError("目標 URL 不可包含帳號密碼 (userinfo)。")

    hostname = _validate_hostname(parts.hostname or "")

    port = parts.port  # urlsplit raises ValueError itself on a bad port
    if port is not None and not (1 <= port <= 65535):
        raise TargetValidationError("目標 URL 連接埠超出範圍。")

    base_path = parts.path or "/"
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    # Fragments stripped; query intentionally dropped for the baseline target.
    return scheme, hostname, port, base_path


def parse_target(target_ip: str, target_url: str = "") -> ParsedTarget:
    """Validate an IP (mandatory) and optional URL into a ParsedTarget."""
    ip = normalize_ip(target_ip)
    if not target_url or not target_url.strip():
        return ParsedTarget(ip=ip)
    scheme, hostname, port, base_path = normalize_url(target_url)
    return ParsedTarget(
        ip=ip,
        scheme=scheme,
        hostname=hostname,
        port=port,
        base_path=base_path,
        original_url=target_url.strip(),
    )
