"""Views: dashboard, task lifecycle, artifacts, health and status."""
from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db import transaction
from django.db.models import Q
from django.http import (
    FileResponse,
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .constants import (
    ACTIVE_TASK_STATUSES,
    SELECTABLE_TOOLS,
    CommandMode,
    Profile,
    TaskStatus,
)
from .forms import ScanTaskForm
from .models import Artifact, AuditEvent, ScanTask
from .services.artifacts import Workspace, WorkspaceError
from .services.target import TargetValidationError, parse_target
from .services.workflow import (
    create_steps,
    default_command_string,
    preview_context,
    request_cancellation,
)
from .tools import get_plugin
from .tools.base import ExpertCommandError, sanitize_display


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
def healthz(request):
    return JsonResponse({"status": "ok", "time": timezone.now().isoformat()})


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@login_required
def dashboard(request):
    tasks = ScanTask.objects.all()
    status = request.GET.get("status", "")
    query = request.GET.get("q", "").strip()
    if status in TaskStatus.values:
        tasks = tasks.filter(status=status)
    if query:
        tasks = tasks.filter(
            Q(name__icontains=query)
            | Q(target_ip__icontains=query)
            | Q(url_hostname__icontains=query)
        )
    context = {
        "tasks": tasks[:200],
        "status_choices": TaskStatus.choices,
        "current_status": status,
        "query": query,
        "active_count": ScanTask.objects.filter(
            status__in=ACTIVE_TASK_STATUSES
        ).count(),
        "max_active": settings.KALIRECON["MAX_ACTIVE_TASKS"],
    }
    return render(request, "recon/dashboard.html", context)


# --------------------------------------------------------------------------- #
# Task creation
# --------------------------------------------------------------------------- #
@login_required
def task_create(request):
    expert_enabled = bool(
        settings.KALIRECON["ENABLE_EXPERT_COMMANDS"] and request.user.is_superuser
    )
    if request.method == "POST":
        form = ScanTaskForm(request.POST, user=request.user)
        active = ScanTask.objects.filter(status__in=ACTIVE_TASK_STATUSES).count()
        if active >= settings.KALIRECON["MAX_ACTIVE_TASKS"]:
            messages.error(
                request,
                f"目前進行中的任務已達上限（{settings.KALIRECON['MAX_ACTIVE_TASKS']}），"
                "請稍後再試。",
            )
        elif form.is_valid():
            task = _persist_task(request, form)
            _enqueue(task, request.user)
            messages.success(request, "任務已建立並排入佇列。")
            return redirect("task_detail", task_id=task.id)
    else:
        form = ScanTaskForm(user=request.user)

    return render(
        request,
        "recon/task_create.html",
        {
            "form": form,
            "expert_enabled": expert_enabled,
            "tool_meta": _tool_meta(),
            "selectable_tools": SELECTABLE_TOOLS,
        },
    )


@transaction.atomic
def _persist_task(request, form) -> ScanTask:
    parsed = form.parsed
    cleaned = form.cleaned_data
    task = ScanTask.objects.create(
        name=cleaned["name"],
        target_ip=parsed.ip,
        target_url=parsed.original_url,
        url_scheme=parsed.scheme,
        url_hostname=parsed.hostname,
        url_port=parsed.port,
        url_base_path=parsed.base_path,
        profile=cleaned["profile"],
        requested_tools=cleaned["tools"],
        tool_config=form.tool_config,
        rate_limit=cleaned["rate_limit"],
        max_duration=cleaned["max_duration"],
        authorized=cleaned["authorized"],
        created_by=request.user,
        status=TaskStatus.CREATED,
    )
    create_steps(task)
    AuditEvent.objects.create(
        task=task, actor=request.user, action="task.create",
        detail={"tools": cleaned["tools"], "profile": cleaned["profile"]},
    )
    return task


def _enqueue(task: ScanTask, user) -> None:
    from .tasks import run_scan_task

    with transaction.atomic():
        task.status = TaskStatus.QUEUED
        task.queued_at = timezone.now()
        task.save(update_fields=["status", "queued_at"])
    transaction.on_commit(lambda: run_scan_task.delay(str(task.id)))


# --------------------------------------------------------------------------- #
# Task detail / status / actions
# --------------------------------------------------------------------------- #
@login_required
def task_detail(request, task_id):
    task = get_object_or_404(ScanTask, pk=task_id)
    steps = task.steps.all().order_by("order")
    return render(
        request,
        "recon/task_detail.html",
        {
            "task": task,
            "steps": steps,
            "services": task.services.all(),
            "endpoints": task.endpoints.all(),
            "findings": task.findings.all(),
            "artifacts": task.artifacts.all(),
            "ip_host_mapping": (
                {task.url_hostname: task.target_ip} if task.url_hostname else {}
            ),
        },
    )


@login_required
def task_status(request, task_id):
    task = get_object_or_404(ScanTask, pk=task_id)
    steps = [
        {
            "order": s.order,
            "tool": s.tool,
            "title": s.title,
            "status": s.status,
            "status_display": s.get_status_display(),
            "command_mode": s.command_mode,
            "display_command": s.display_command,
            "exit_code": s.exit_code,
            "duration": s.duration_seconds,
            "error_summary": s.error_summary,
        }
        for s in task.steps.all().order_by("order")
    ]
    return JsonResponse(
        {
            "id": str(task.id),
            "status": task.status,
            "status_display": task.get_status_display(),
            "progress": task.progress,
            "is_terminal": task.is_terminal,
            "error_summary": task.error_summary,
            "counts": {
                "services": task.services.count(),
                "endpoints": task.endpoints.count(),
                "findings": task.findings.count(),
            },
            "steps": steps,
        }
    )


@login_required
@require_POST
def task_cancel(request, task_id):
    task = get_object_or_404(ScanTask, pk=task_id)
    if task.is_terminal:
        messages.info(request, "任務已結束，無法取消。")
    else:
        request_cancellation(task)
        AuditEvent.objects.create(
            task=task, actor=request.user, action="task.cancel", detail={}
        )
        messages.success(request, "已要求取消任務。")
    return redirect("task_detail", task_id=task.id)


@login_required
@require_POST
def task_rerun(request, task_id):
    source = get_object_or_404(ScanTask, pk=task_id)
    active = ScanTask.objects.filter(status__in=ACTIVE_TASK_STATUSES).count()
    if active >= settings.KALIRECON["MAX_ACTIVE_TASKS"]:
        messages.error(request, "進行中的任務已達上限，請稍後再試。")
        return redirect("task_detail", task_id=source.id)
    with transaction.atomic():
        task = ScanTask.objects.create(
            name=f"{source.name}（重跑）",
            target_ip=source.target_ip,
            target_url=source.target_url,
            url_scheme=source.url_scheme,
            url_hostname=source.url_hostname,
            url_port=source.url_port,
            url_base_path=source.url_base_path,
            profile=source.profile,
            requested_tools=source.requested_tools,
            tool_config=source.tool_config,
            rate_limit=source.rate_limit,
            max_duration=source.max_duration,
            authorized=source.authorized,
            created_by=request.user,
            status=TaskStatus.CREATED,
        )
        # Re-validate any expert commands against current policy.
        _revalidate_expert(task)
        create_steps(task)
        AuditEvent.objects.create(
            task=task, actor=request.user, action="task.rerun",
            detail={"source": str(source.id)},
        )
    _enqueue(task, request.user)
    messages.success(request, "已依原設定重新建立任務。")
    return redirect("task_detail", task_id=task.id)


def _revalidate_expert(task: ScanTask) -> None:
    parsed = parse_target(task.target_ip, task.target_url)
    config = dict(task.tool_config or {})
    for tool, cfg in list(config.items()):
        if cfg.get("mode") != CommandMode.EXPERT:
            continue
        plugin = get_plugin(tool)
        ctx = preview_context(parsed, task.profile, task.rate_limit, tool)
        try:
            plugin.validate_expert(cfg.get("command", ""), None, None, ctx)
        except ExpertCommandError:
            # Fall back to default mode rather than silently executing.
            config[tool] = {"mode": CommandMode.DEFAULT}
    task.tool_config = config
    task.save(update_fields=["tool_config"])


# --------------------------------------------------------------------------- #
# Expert command preview (AJAX)
# --------------------------------------------------------------------------- #
@login_required
@require_POST
def command_preview(request):
    if not (settings.KALIRECON["ENABLE_EXPERT_COMMANDS"] and request.user.is_superuser):
        return JsonResponse({"ok": False, "error": "未啟用進階自訂指令。"}, status=403)
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return HttpResponseBadRequest("invalid json")
    tool = payload.get("tool", "")
    if tool not in SELECTABLE_TOOLS:
        return JsonResponse({"ok": False, "error": "未知工具。"}, status=400)
    try:
        parsed = parse_target(payload.get("target_ip", ""), payload.get("target_url", ""))
    except TargetValidationError as exc:
        return JsonResponse({"ok": False, "error": str(exc)})
    profile = payload.get("profile", Profile.SAFE)
    rate = int(payload.get("rate_limit", 50) or 50)
    plugin = get_plugin(tool)
    ctx = preview_context(parsed, profile, rate, tool)
    command = payload.get("command", "")
    if not command:
        return JsonResponse(
            {"ok": True, "default": default_command_string(parsed, profile, rate, tool)}
        )
    try:
        argv = plugin.validate_expert(command, None, None, ctx)
    except ExpertCommandError as exc:
        return JsonResponse({"ok": False, "error": str(exc)})
    return JsonResponse({"ok": True, "normalized": sanitize_display(argv), "argv": argv})


# --------------------------------------------------------------------------- #
# Artifacts / reports download
# --------------------------------------------------------------------------- #
@login_required
def artifact_download(request, task_id, artifact_id):
    task = get_object_or_404(ScanTask, pk=task_id)
    artifact = get_object_or_404(Artifact, pk=artifact_id, task=task)
    ws = Workspace()
    try:
        path: Path = ws.resolve_rel(task, artifact.rel_path)
    except WorkspaceError:
        raise Http404("invalid path") from None
    if not path.exists() or not path.is_file():
        raise Http404("artifact missing")
    response = FileResponse(
        open(path, "rb"),
        content_type=artifact.mime_type or "application/octet-stream",
    )
    response["Content-Disposition"] = f'attachment; filename="{artifact.name}"'
    return response


@login_required
def report_view(request, task_id, fmt):
    task = get_object_or_404(ScanTask, pk=task_id)
    ws = Workspace()
    rel = "reports/report.html" if fmt == "html" else "reports/report.json"
    try:
        path = ws.resolve_rel(task, rel)
    except WorkspaceError:
        raise Http404() from None
    if not path.exists():
        raise Http404("report not generated yet")
    if fmt == "json":
        return HttpResponse(
            path.read_text("utf-8"), content_type="application/json"
        )
    return HttpResponse(path.read_text("utf-8"), content_type="text/html")


# --------------------------------------------------------------------------- #
# Status / observability page
# --------------------------------------------------------------------------- #
@login_required
@user_passes_test(lambda u: u.is_staff)
def status_page(request):
    return render(request, "recon/status.html", {"checks": _system_checks()})


def _system_checks() -> list[dict]:
    checks = []
    # Database
    try:
        ScanTask.objects.exists()
        checks.append({"name": "PostgreSQL / DB", "ok": True, "detail": "connected"})
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "PostgreSQL / DB", "ok": False, "detail": str(exc)})
    # Redis / Celery broker
    try:
        import redis

        client = redis.from_url(settings.CELERY_BROKER_URL)
        client.ping()
        checks.append({"name": "Redis broker", "ok": True, "detail": "pong"})
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "Redis broker", "ok": False, "detail": str(exc)})
    # Docker socket + scanner image
    try:
        from .services.docker_runner import get_client

        client = get_client()
        client.ping()
        images = client.images.list(name=settings.KALIRECON["SCANNER_IMAGE"])
        checks.append({"name": "Docker socket", "ok": True, "detail": "reachable"})
        checks.append(
            {
                "name": "掃描器映像",
                "ok": bool(images),
                "detail": settings.KALIRECON["SCANNER_IMAGE"],
            }
        )
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "Docker socket", "ok": False, "detail": str(exc)})
    checks.append(
        {
            "name": "進階自訂指令",
            "ok": True,
            "detail": "啟用" if settings.KALIRECON["ENABLE_EXPERT_COMMANDS"] else "停用",
        }
    )
    return checks


def _tool_meta() -> list[dict]:
    meta = []
    for name in SELECTABLE_TOOLS:
        plugin = get_plugin(name)
        meta.append(
            {
                "name": name,
                "title": plugin.title,
                "executable": plugin.executable,
                "dependencies": plugin.dependencies,
                "web_required": plugin.web_required,
                "https_only": plugin.https_only,
            }
        )
    return meta
