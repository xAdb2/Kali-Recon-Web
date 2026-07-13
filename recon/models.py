"""Domain model for KaliRecon Web."""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse

from .constants import (
    ACTIVE_TASK_STATUSES,
    TERMINAL_TASK_STATUSES,
    CommandMode,
    Confidence,
    Profile,
    Severity,
    StepStatus,
    TaskStatus,
)


class ScanTask(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)

    target_ip = models.GenericIPAddressField()
    target_url = models.URLField(max_length=2000, blank=True, default="")

    # Parsed URL components (populated by the target parser).
    url_scheme = models.CharField(max_length=8, blank=True, default="")
    url_hostname = models.CharField(max_length=255, blank=True, default="")
    url_port = models.PositiveIntegerField(null=True, blank=True)
    url_base_path = models.CharField(max_length=1000, blank=True, default="/")

    profile = models.CharField(
        max_length=16, choices=Profile.choices, default=Profile.SAFE
    )
    requested_tools = models.JSONField(default=list)
    # Per-tool command mode / expert config, keyed by tool name.
    tool_config = models.JSONField(default=dict)

    rate_limit = models.PositiveIntegerField(default=50)
    max_duration = models.PositiveIntegerField(default=3600)

    status = models.CharField(
        max_length=16, choices=TaskStatus.choices, default=TaskStatus.CREATED
    )
    authorized = models.BooleanField(default=False)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="scan_tasks",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    queued_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    cancel_requested_at = models.DateTimeField(null=True, blank=True)

    error_summary = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.target_ip})"

    def get_absolute_url(self) -> str:
        return reverse("task_detail", args=[self.id])

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_TASK_STATUSES

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_TASK_STATUSES

    @property
    def progress(self) -> int:
        steps = list(self.steps.all())
        if not steps:
            return 0
        done = sum(
            1
            for s in steps
            if s.status
            in {
                StepStatus.COMPLETED,
                StepStatus.FAILED,
                StepStatus.SKIPPED,
                StepStatus.CANCELLED,
                StepStatus.TIMED_OUT,
            }
        )
        return int(round(done / len(steps) * 100))

    @property
    def workspace_rel(self) -> str:
        return str(self.id)


class ScanStep(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(
        ScanTask, on_delete=models.CASCADE, related_name="steps"
    )
    tool = models.CharField(max_length=64)
    title = models.CharField(max_length=200)
    order = models.PositiveIntegerField(default=0)

    status = models.CharField(
        max_length=16, choices=StepStatus.choices, default=StepStatus.PENDING
    )
    progress = models.PositiveIntegerField(null=True, blank=True)

    command_mode = models.CharField(
        max_length=8, choices=CommandMode.choices, default=CommandMode.DEFAULT
    )
    expert_command_text = models.TextField(blank=True, default="")
    argv = models.JSONField(default=list)
    display_command = models.CharField(max_length=4000, blank=True, default="")

    container_id = models.CharField(max_length=128, blank=True, default="")
    exit_code = models.IntegerField(null=True, blank=True)
    tool_version = models.CharField(max_length=200, blank=True, default="")

    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_summary = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["order"]
        unique_together = [("task", "order")]

    def __str__(self) -> str:
        return f"{self.order:02d} {self.tool}"

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def workspace_rel(self) -> str:
        return f"steps/{self.order:02d}-{self.tool}"


class Service(models.Model):
    task = models.ForeignKey(
        ScanTask, on_delete=models.CASCADE, related_name="services"
    )
    ip = models.GenericIPAddressField()
    port = models.PositiveIntegerField()
    transport = models.CharField(max_length=8, default="tcp")
    service_name = models.CharField(max_length=128, blank=True, default="")
    product = models.CharField(max_length=256, blank=True, default="")
    version = models.CharField(max_length=128, blank=True, default="")
    extra_info = models.CharField(max_length=512, blank=True, default="")
    source_tool = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        ordering = ["port"]
        unique_together = [("task", "ip", "port", "transport")]

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}/{self.transport}"


class Endpoint(models.Model):
    task = models.ForeignKey(
        ScanTask, on_delete=models.CASCADE, related_name="endpoints"
    )
    url = models.URLField(max_length=2000)
    method = models.CharField(max_length=8, default="GET")
    status_code = models.IntegerField(null=True, blank=True)
    title = models.CharField(max_length=512, blank=True, default="")
    content_length = models.BigIntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=256, blank=True, default="")
    redirect_location = models.CharField(max_length=2000, blank=True, default="")
    in_scope = models.BooleanField(default=True)
    source_tools = models.JSONField(default=list)

    class Meta:
        ordering = ["url"]
        unique_together = [("task", "url", "method")]

    def __str__(self) -> str:
        return f"{self.method} {self.url}"


class Finding(models.Model):
    task = models.ForeignKey(
        ScanTask, on_delete=models.CASCADE, related_name="findings"
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.INFO
    )
    confidence = models.CharField(
        max_length=16, choices=Confidence.choices, default=Confidence.MEDIUM
    )
    category = models.CharField(max_length=128, blank=True, default="")
    title = models.CharField(max_length=512)
    description = models.TextField(blank=True, default="")
    evidence = models.TextField(blank=True, default="")
    remediation = models.TextField(blank=True, default="")
    source_tool = models.CharField(max_length=64, blank=True, default="")
    related_service = models.ForeignKey(
        Service, on_delete=models.SET_NULL, null=True, blank=True
    )
    related_endpoint = models.ForeignKey(
        Endpoint, on_delete=models.SET_NULL, null=True, blank=True
    )
    dedup_key = models.CharField(max_length=64, db_index=True)

    class Meta:
        ordering = ["severity", "title"]
        unique_together = [("task", "dedup_key")]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"


class Artifact(models.Model):
    task = models.ForeignKey(
        ScanTask, on_delete=models.CASCADE, related_name="artifacts"
    )
    step = models.ForeignKey(
        ScanStep,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="artifacts",
    )
    name = models.CharField(max_length=256)
    artifact_type = models.CharField(max_length=64, default="file")
    rel_path = models.CharField(max_length=1000)
    mime_type = models.CharField(max_length=128, blank=True, default="")
    size = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["rel_path"]
        unique_together = [("task", "rel_path")]

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("artifact_download", args=[self.task_id, self.pk])


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(
        ScanTask,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    step = models.ForeignKey(
        ScanStep,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    action = models.CharField(max_length=64)
    detail = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.action} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
