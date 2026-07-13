"""Base plugin abstraction and the expert-command validator.

Security model
--------------
* Every scanner invocation is an argv *list* — never a shell string.
* The first token is pinned to the plugin's allowlisted executable.
* Expert command text is parsed with ``shlex.split(posix=True)`` only after a
  raw scan rejects shell metacharacters, so no shell is ever involved.
* Tool-specific validators reject any flag that would broaden scope or write
  outside the step workspace, and the backend always injects the output path
  and the enforced target argument.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from ..services.target import ParsedTarget


class ExpertCommandError(ValueError):
    """Raised when an expert command fails validation."""


# Characters that would enable shell features. Rejected in the *raw* text
# before tokenizing, so command chaining/redirection/substitution is impossible.
FORBIDDEN_CHARS = [
    ";", "&", "|", "<", ">", "`", "$", "\n", "\r", "\\",
    "(", ")", "{", "}",
]

_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class RunContext:
    """Everything a plugin needs to build/validate a command."""

    target: ParsedTarget
    profile: str
    rate_limit: int
    max_threads: int
    open_ports: list[int] = field(default_factory=list)
    workspace_root: str = "/workspace"
    task_rel: str = ""
    step_rel: str = ""
    limits: dict = field(default_factory=dict)

    @property
    def step_dir(self) -> str:
        return f"{self.workspace_root}/{self.task_rel}/{self.step_rel}".rstrip("/")

    def out_path(self, filename: str) -> str:
        return f"{self.step_dir}/{filename}"


@dataclass
class ParseResult:
    services: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    tool_version: str = ""


def sanitize_display(argv: list[str]) -> str:
    return " ".join(shlex.quote(str(a)) for a in argv)


def tokenize_expert(text: str) -> list[str]:
    """Reject shell syntax, then tokenize with shlex (no shell involved)."""
    if text is None:
        raise ExpertCommandError("指令不可為空。")
    stripped = text.strip()
    if not stripped:
        raise ExpertCommandError("指令不可為空。")
    if "\n" in text or "\r" in text:
        raise ExpertCommandError("不接受多行指令。")
    for ch in FORBIDDEN_CHARS:
        if ch in text:
            raise ExpertCommandError(f"指令含有被禁止的字元：{ch!r}")
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError as exc:
        raise ExpertCommandError(f"指令無法解析：{exc}") from exc
    if not tokens:
        raise ExpertCommandError("指令為空。")
    if _ENV_ASSIGN.match(tokens[0]):
        raise ExpertCommandError(f"不接受環境變數指派：{tokens[0]}")
    for tok in tokens[1:]:
        if not tok.startswith("-") and _ENV_ASSIGN.match(tok):
            raise ExpertCommandError(f"不接受環境變數指派：{tok}")
    return tokens


class ToolPlugin:
    name: str = ""
    title: str = ""
    executable: str = ""
    dependencies: list[str] = []
    web_required: bool = False
    https_only: bool = False
    default_timeout: int = 900

    # ---- lifecycle ---------------------------------------------------------
    def is_applicable(self, task, context: RunContext) -> bool:
        if self.web_required and not context.target.has_url:
            return False
        if self.https_only and not context.target.is_https:
            return False
        return True

    def build_argv(self, task, step, context: RunContext) -> list[str]:
        """Backend-generated default argv. Must be overridden."""
        raise NotImplementedError

    def output_files(self, task, step) -> dict[str, str]:
        return {}

    def parse(self, task, step, workspace) -> ParseResult:  # pragma: no cover
        return ParseResult()

    # ---- expert mode -------------------------------------------------------
    def validate_expert(self, text: str, task, step, context: RunContext) -> list[str]:
        """Validate expert text and return a normalized, enforced argv."""
        tokens = tokenize_expert(text)
        if tokens[0] != self.executable:
            raise ExpertCommandError(
                f"第一個指令必須是 {self.executable!r}，不可更換執行檔。"
            )
        return self.normalize_expert(tokens, task, step, context)

    def normalize_expert(
        self, tokens: list[str], task, step, context: RunContext
    ) -> list[str]:
        """Tool-specific validation + backend enforcement. Override me."""
        raise ExpertCommandError("此工具不支援進階自訂指令。")

    # ---- helpers -----------------------------------------------------------
    def get_timeout(self, task) -> int:
        return self.default_timeout
