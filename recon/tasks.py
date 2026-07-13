"""Celery task entrypoints."""
from __future__ import annotations

import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from .constants import TaskStatus
from .models import AuditEvent, ScanTask

logger = logging.getLogger("recon.tasks")


@shared_task(name="recon.run_scan_task", bind=True)
def run_scan_task(self, task_id: str) -> str:
    from .services.workflow import run_workflow

    try:
        task = ScanTask.objects.get(pk=task_id)
    except ScanTask.DoesNotExist:
        logger.error("run_scan_task: task %s not found", task_id)
        return "missing"

    if task.status in {TaskStatus.CANCELLED, TaskStatus.CANCELLING}:
        return "cancelled"

    AuditEvent.objects.create(
        task=task, action="task.start", detail={"celery_id": self.request.id}
    )
    try:
        run_workflow(task)
    except Exception as exc:  # noqa: BLE001
        logger.exception("workflow crashed for task %s", task_id)
        with transaction.atomic():
            task.refresh_from_db()
            task.status = TaskStatus.FAILED
            task.finished_at = timezone.now()
            task.error_summary = f"工作流程錯誤：{exc}"
            task.save(update_fields=["status", "finished_at", "error_summary"])
        AuditEvent.objects.create(
            task=task, action="task.error", detail={"error": str(exc)}
        )
        return "failed"

    task.refresh_from_db()
    AuditEvent.objects.create(
        task=task, action="task.finish", detail={"status": task.status}
    )
    return task.status
