"""Nmap port discovery and service detection plugins."""
from __future__ import annotations

from ..constants import Profile
from ..parsers.nmap import parse_nmap_xml
from .base import ExpertCommandError, ParseResult, RunContext, ToolPlugin

# Output flags we always strip from expert input and re-inject ourselves.
_NMAP_OUTPUT_FLAGS = {"-oX", "-oN", "-oG", "-oA", "-oS", "-oJ"}
# Flags that broaden scope or spoof; always rejected in expert mode.
_NMAP_BANNED = {
    "-iL", "-iR", "-D", "-S", "--spoof-mac", "--data", "--data-string",
    "--data-length", "--interactive", "--resume", "--script-args-file",
    "--script-help", "-e",
}
_NMAP_SCRIPT_ALLOW = {
    "default", "banner", "http-title", "http-headers", "http-methods",
    "ssl-cert", "ssl-enum-ciphers", "http-server-header",
}


def _validate_scripts(value: str) -> None:
    for name in value.split(","):
        name = name.strip()
        if not name:
            continue
        if "/" in name or name.endswith(".nse") or name.startswith("."):
            raise ExpertCommandError(f"不允許的 --script 路徑：{name}")
        if name not in _NMAP_SCRIPT_ALLOW:
            raise ExpertCommandError(f"--script {name} 不在允許清單內。")


class _NmapBase(ToolPlugin):
    executable = "nmap"

    def output_files(self, task, step) -> dict[str, str]:
        return {"xml": "result.xml"}

    def parse(self, task, step, workspace) -> ParseResult:
        xml = workspace.read_step_text(step, "result.xml")
        services = parse_nmap_xml(xml)
        for s in services:
            s["source_tool"] = self.name
            if not s.get("ip"):
                s["ip"] = task.target_ip
        return ParseResult(services=services)

    def _normalize_common(
        self, tokens: list[str], context: RunContext
    ) -> list[str]:
        """Shared expert normalization: strip output flags, enforce target."""
        cleaned: list[str] = []
        i = 1
        toks = tokens
        while i < len(toks):
            tok = toks[i]
            if tok in _NMAP_OUTPUT_FLAGS:
                i += 2  # drop flag + its argument
                continue
            if tok in _NMAP_BANNED:
                raise ExpertCommandError(f"不允許的 nmap 參數：{tok}")
            if tok.startswith("--script"):
                if "=" in tok:
                    _validate_scripts(tok.split("=", 1)[1])
                    cleaned.append(tok)
                    i += 1
                    continue
                value = toks[i + 1] if i + 1 < len(toks) else ""
                _validate_scripts(value)
                cleaned.extend([tok, value])
                i += 2
                continue
            if tok in {"--max-rate", "--min-rate"}:
                value = toks[i + 1] if i + 1 < len(toks) else ""
                try:
                    rate = int(value)
                except ValueError as exc:
                    raise ExpertCommandError("速率必須是整數。") from exc
                rate = min(rate, context.limits.get("max_rate", 200))
                cleaned.extend([tok, str(rate)])
                i += 2
                continue
            if not tok.startswith("-"):
                # A token containing '.'/':' is a host/IP target candidate; a
                # purely numeric/range token is the value of the preceding flag.
                if "." in tok or ":" in tok:
                    if tok != context.target.ip:
                        raise ExpertCommandError(
                            f"目標僅能是任務 IP {context.target.ip}，不可指定 {tok}。"
                        )
                    i += 1  # drop; the enforced IP is re-appended below
                    continue
                cleaned.append(tok)
                i += 1
                continue
            cleaned.append(tok)
            i += 1

        out = context.out_path("result.xml")
        return ["nmap", *cleaned, "-oX", out, context.target.ip]


class NmapPortsPlugin(_NmapBase):
    name = "nmap_ports"
    title = "Nmap 連接埠探索"
    dependencies: list[str] = []
    default_timeout = 1200

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        out = context.out_path("result.xml")
        argv = ["nmap", "-sT", "-Pn", "-n", "--open"]
        if context.profile == Profile.STANDARD:
            argv += ["-p-", "-T3", "--reason"]
        else:
            argv += ["--top-ports", "1000", "-T3", "--reason"]
        argv += ["-oX", out, context.target.ip]
        return argv

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        return self._normalize_common(tokens, context)


class NmapServicesPlugin(_NmapBase):
    name = "nmap_services"
    title = "Nmap 服務辨識"
    dependencies = ["nmap_ports"]
    default_timeout = 1200

    def is_applicable(self, task, context: RunContext) -> bool:
        return bool(context.open_ports)

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        out = context.out_path("result.xml")
        ports = ",".join(str(p) for p in context.open_ports) or "1-1024"
        return [
            "nmap", "-sT", "-Pn", "-sV", "--version-intensity", "5",
            "--script=default,banner", "-p", ports,
            "-oX", out, context.target.ip,
        ]

    def normalize_expert(self, tokens, task, step, context) -> list[str]:
        return self._normalize_common(tokens, context)
