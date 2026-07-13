"""Shared enums, choices and tool metadata."""
from __future__ import annotations

from django.db import models


class TaskStatus(models.TextChoices):
    CREATED = "CREATED", "已建立"
    QUEUED = "QUEUED", "排隊中"
    RUNNING = "RUNNING", "執行中"
    CANCELLING = "CANCELLING", "取消中"
    CANCELLED = "CANCELLED", "已取消"
    COMPLETED = "COMPLETED", "已完成"
    PARTIAL = "PARTIAL", "部分完成"
    FAILED = "FAILED", "失敗"
    TIMED_OUT = "TIMED_OUT", "逾時"


ACTIVE_TASK_STATUSES = {
    TaskStatus.QUEUED,
    TaskStatus.RUNNING,
    TaskStatus.CANCELLING,
}

TERMINAL_TASK_STATUSES = {
    TaskStatus.CANCELLED,
    TaskStatus.COMPLETED,
    TaskStatus.PARTIAL,
    TaskStatus.FAILED,
    TaskStatus.TIMED_OUT,
}


class StepStatus(models.TextChoices):
    PENDING = "PENDING", "待處理"
    QUEUED = "QUEUED", "排隊中"
    RUNNING = "RUNNING", "執行中"
    COMPLETED = "COMPLETED", "已完成"
    FAILED = "FAILED", "失敗"
    SKIPPED = "SKIPPED", "略過"
    CANCELLED = "CANCELLED", "已取消"
    TIMED_OUT = "TIMED_OUT", "逾時"


class CommandMode(models.TextChoices):
    DEFAULT = "DEFAULT", "預設"
    EXPERT = "EXPERT", "進階自訂"


class Profile(models.TextChoices):
    SAFE = "SAFE", "安全 (Safe)"
    STANDARD = "STANDARD", "標準 (Standard)"


class Severity(models.TextChoices):
    INFO = "info", "資訊"
    LOW = "low", "低"
    MEDIUM = "medium", "中"
    HIGH = "high", "高"
    CRITICAL = "critical", "嚴重"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(models.TextChoices):
    LOW = "low", "低"
    MEDIUM = "medium", "中"
    HIGH = "high", "高"


# Tool identifiers used across plugins, forms and the workflow.
TOOL_NMAP_PORTS = "nmap_ports"
TOOL_NMAP_SERVICES = "nmap_services"
TOOL_HTTP_PROBE = "http_probe"
TOOL_WHATWEB = "whatweb"
TOOL_TLS = "tls"
TOOL_DIRSEARCH = "dirsearch"
TOOL_NUCLEI = "nuclei"
TOOL_SUBDOMAINS = "subdomains"

# Tools the user may explicitly request (prerequisites are auto-inserted).
SELECTABLE_TOOLS = [
    TOOL_NMAP_PORTS,
    TOOL_NMAP_SERVICES,
    TOOL_SUBDOMAINS,
    TOOL_HTTP_PROBE,
    TOOL_WHATWEB,
    TOOL_TLS,
    TOOL_DIRSEARCH,
    TOOL_NUCLEI,
]
