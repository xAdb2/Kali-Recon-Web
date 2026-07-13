"""Workflow planning and sequential execution."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ..constants import (
    TOOL_HTTP_PROBE,
    TOOL_NMAP_PORTS,
    CommandMode,
    StepStatus,
    TaskStatus,
)
from ..models import Endpoint, Finding, ScanStep, Service
from ..tools import get_plugin
from ..tools.base import ExpertCommandError, RunContext, sanitize_display
from .artifacts import Workspace
from .docker_runner import LABEL_STEP, LABEL_TASK, RunSpec, run_step, stop_task_containers
from .target import ParsedTarget, parse_target

logger = logging.getLogger("recon.workflow")

# Canonical execution order. Prerequisites are auto-inserted below.
TOOL_ORDER = [
    "nmap_ports",
    "nmap_services",
    "http_probe",
    "whatweb",
    "tls",
    "dirsearch",
    "nuclei",
]
WEB_TOOLS = {"whatweb", "tls", "dirsearch", "nuclei"}


def limits() -> dict:
    return {
        "max_rate": settings.KALIRECON["MAX_RATE"],
        "max_threads": settings.KALIRECON["MAX_THREADS"],
    }


def plan_tools(requested: list[str], target: ParsedTarget) -> list[str]:
    """Expand dependencies and filter by applicability, preserving order."""
    wanted = set(requested)
    if "nmap_services" in wanted:
        wanted.add("nmap_ports")
    if wanted & WEB_TOOLS:
        wanted.add(TOOL_HTTP_PROBE)

    plan: list[str] = []
    for name in TOOL_ORDER:
        if name not in wanted:
            continue
        plugin = get_plugin(name)
        if plugin.web_required and not target.has_url:
            continue
        if plugin.https_only and not target.is_https:
            continue
        plan.append(name)
    return plan


def parsed_from_task(task) -> ParsedTarget:
    return parse_target(task.target_ip, task.target_url)


def build_context(task, open_ports=None, step=None, step_rel=None) -> RunContext:
    target = parsed_from_task(task)
    rel = step_rel or (step.workspace_rel if step else "steps/00-preview")
    return RunContext(
        target=target,
        profile=task.profile,
        rate_limit=task.rate_limit,
        max_threads=settings.KALIRECON["MAX_THREADS"],
        open_ports=list(open_ports or []),
        workspace_root=settings.KALIRECON["WORKSPACE_ROOT"],
        task_rel=str(task.id),
        step_rel=rel,
        limits=limits(),
    )


def preview_context(target: ParsedTarget, profile: str, rate_limit: int,
                    tool: str) -> RunContext:
    return RunContext(
        target=target,
        profile=profile,
        rate_limit=rate_limit,
        max_threads=settings.KALIRECON["MAX_THREADS"],
        open_ports=[],
        workspace_root=settings.KALIRECON["WORKSPACE_ROOT"],
        task_rel="<task>",
        step_rel=f"steps/NN-{tool}",
        limits=limits(),
    )


def default_command_string(target: ParsedTarget, profile: str, rate_limit: int,
                           tool: str) -> str:
    """Human-readable default command used to pre-populate the expert field."""
    plugin = get_plugin(tool)
    ctx = preview_context(target, profile, rate_limit, tool)
    try:
        argv = plugin.build_argv(None, None, ctx)
    except Exception:  # noqa: BLE001
        return ""
    return sanitize_display(argv)


@transaction.atomic
def create_steps(task) -> list[ScanStep]:
    """Create ScanStep rows (with auto-inserted prerequisites) for a task."""
    target = parsed_from_task(task)
    plan = plan_tools(task.requested_tools, target)
    config = task.tool_config or {}
    steps = []
    for order, tool in enumerate(plan, start=1):
        plugin = get_plugin(tool)
        cfg = config.get(tool, {})
        mode = cfg.get("mode", CommandMode.DEFAULT)
        expert_text = cfg.get("command", "") if mode == CommandMode.EXPERT else ""
        step = ScanStep.objects.create(
            task=task,
            tool=tool,
            title=plugin.title,
            order=order,
            status=StepStatus.PENDING,
            command_mode=mode,
            expert_command_text=expert_text,
        )
        steps.append(step)
    return steps


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return timezone.now()


def _refresh_cancel(task) -> bool:
    task.refresh_from_db(fields=["status", "cancel_requested_at"])
    return task.cancel_requested_at is not None or task.status in {
        TaskStatus.CANCELLING,
        TaskStatus.CANCELLED,
    }


def run_workflow(task, runner=None) -> None:
    """Execute all steps sequentially. Robust to per-step failure."""
    runner = runner or run_step
    ws = Workspace()
    ws.ensure_task_dirs(task)

    with transaction.atomic():
        task.status = TaskStatus.RUNNING
        task.started_at = task.started_at or _now()
        task.save(update_fields=["status", "started_at"])

    ws.write_task_json(task, "metadata.json", _task_metadata(task))

    open_ports: list[int] = []
    task_deadline = None
    if task.max_duration:
        task_deadline = task.started_at.timestamp() + task.max_duration

    steps = list(task.steps.all().order_by("order"))
    cancelled = False
    timed_out_task = False

    for step in steps:
        if _refresh_cancel(task):
            cancelled = True
            _mark(step, StepStatus.CANCELLED, "任務已取消。")
            continue
        if task_deadline and timezone.now().timestamp() > task_deadline:
            timed_out_task = True
            _mark(step, StepStatus.SKIPPED, "任務逾時，略過剩餘步驟。")
            continue
        _run_single_step(task, step, ws, open_ports, runner)
        if step.tool == TOOL_NMAP_PORTS and step.status == StepStatus.COMPLETED:
            open_ports = sorted(
                {s.port for s in task.services.filter(source_tool="nmap_ports")}
            )

    # Final status
    if cancelled:
        final = TaskStatus.CANCELLED
    elif timed_out_task:
        final = TaskStatus.TIMED_OUT
    else:
        final = _aggregate_status(task)

    _write_normalized(task, ws)
    try:
        from .report import generate_reports

        generate_reports(task, ws)
    except Exception:  # noqa: BLE001
        logger.exception("report generation failed for task %s", task.id)

    with transaction.atomic():
        task.status = final
        task.finished_at = _now()
        if final in {TaskStatus.FAILED, TaskStatus.PARTIAL, TaskStatus.TIMED_OUT}:
            task.error_summary = _collect_errors(task)
        task.save(update_fields=["status", "finished_at", "error_summary"])


def _run_single_step(task, step, ws: Workspace, open_ports, runner) -> None:
    plugin = get_plugin(step.tool)
    ctx = build_context(task, open_ports=open_ports, step=step)

    if not plugin.is_applicable(task, ctx):
        _mark(step, StepStatus.SKIPPED, "不符合執行條件（缺少前置結果或不適用）。")
        return

    # Resolve argv (default or expert, re-validated at execution time).
    try:
        if step.command_mode == CommandMode.EXPERT:
            argv = plugin.validate_expert(step.expert_command_text, task, step, ctx)
        else:
            argv = plugin.build_argv(task, step, ctx)
    except ExpertCommandError as exc:
        _mark(step, StepStatus.FAILED, f"進階指令驗證失敗：{exc}")
        return
    except Exception as exc:  # noqa: BLE001
        _mark(step, StepStatus.FAILED, f"指令建立失敗：{exc}")
        return

    step.argv = argv
    step.display_command = sanitize_display(argv)
    step.status = StepStatus.RUNNING
    step.started_at = _now()
    step.save(update_fields=["argv", "display_command", "status", "started_at"])

    ws.ensure_step_dir(step)
    ws.write_step_text(
        step, "command.json",
        json.dumps(
            {
                "mode": step.command_mode,
                "expert_text": step.expert_command_text,
                "argv": argv,
                "display": step.display_command,
            },
            ensure_ascii=False,
            indent=2,
        ),
    )

    target = ctx.target
    extra_hosts = {}
    if target.has_url:
        extra_hosts[target.hostname] = target.ip

    spec = RunSpec(
        argv=argv,
        labels={LABEL_TASK: str(task.id), LABEL_STEP: str(step.id)},
        extra_hosts=extra_hosts,
        timeout=plugin.get_timeout(task),
    )
    result = runner(spec)

    ws.write_step_text(step, "stdout.log", result.stdout or "")
    ws.write_step_text(step, "stderr.log", result.stderr or "")
    step.container_id = result.container_id
    step.exit_code = result.exit_code

    # Parse whatever is available, regardless of exit code.
    parse_error = ""
    try:
        pr = plugin.parse(task, step, ws)
        _store_parse_result(task, step, pr)
        if pr.tool_version:
            step.tool_version = pr.tool_version
    except Exception as exc:  # noqa: BLE001
        parse_error = str(exc)
        logger.warning("parse failed for step %s: %s", step.id, exc)

    if result.timed_out:
        status = StepStatus.TIMED_OUT
        err = "步驟逾時。"
    elif result.error:
        status = StepStatus.FAILED
        err = f"容器執行失敗：{result.error}"
    elif result.exit_code not in (0, None):
        status = StepStatus.COMPLETED if _tolerant_exit(step.tool) else StepStatus.FAILED
        err = "" if status == StepStatus.COMPLETED else f"結束代碼 {result.exit_code}"
    else:
        status = StepStatus.COMPLETED
        err = ""
    if parse_error and status == StepStatus.COMPLETED:
        err = f"解析警告：{parse_error}"

    step.status = status
    step.finished_at = _now()
    step.error_summary = err
    ws.write_step_text(step, "step.json", _step_json(step))
    step.save()
    ws.register_step_dir(task, step)


def _tolerant_exit(tool: str) -> bool:
    # openssl s_client / curl can exit non-zero yet still produce useful data.
    return tool in {"tls", "http_probe"}


def _mark(step, status, err="") -> None:
    step.status = status
    step.error_summary = err
    if status in {StepStatus.SKIPPED, StepStatus.CANCELLED} and not step.finished_at:
        step.finished_at = _now()
    step.save(update_fields=["status", "error_summary", "finished_at"])


def _aggregate_status(task) -> str:
    statuses = list(task.steps.values_list("status", flat=True))
    succeeded = any(s == StepStatus.COMPLETED for s in statuses)
    failed = any(s in {StepStatus.FAILED, StepStatus.TIMED_OUT} for s in statuses)
    if failed and not succeeded:
        return TaskStatus.FAILED
    if failed and succeeded:
        return TaskStatus.PARTIAL
    return TaskStatus.COMPLETED


def _collect_errors(task) -> str:
    lines = []
    for step in task.steps.all():
        if step.error_summary and step.status in {
            StepStatus.FAILED,
            StepStatus.TIMED_OUT,
            StepStatus.SKIPPED,
        }:
            lines.append(f"{step.order:02d} {step.tool}: {step.error_summary}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Normalization / dedup
# --------------------------------------------------------------------------- #
def _store_parse_result(task, step, pr) -> None:
    for svc in pr.services:
        Service.objects.update_or_create(
            task=task,
            ip=svc.get("ip") or task.target_ip,
            port=svc["port"],
            transport=svc.get("transport", "tcp"),
            defaults={
                "service_name": svc.get("service_name", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "extra_info": svc.get("extra_info", ""),
                "source_tool": svc.get("source_tool", step.tool),
            },
        )
    for ep in pr.endpoints:
        _upsert_endpoint(task, ep)
    for fd in pr.findings:
        _upsert_finding(task, fd)


def _upsert_endpoint(task, ep) -> None:
    url = ep.get("url")
    if not url:
        return
    method = ep.get("method", "GET")
    obj, created = Endpoint.objects.get_or_create(
        task=task, url=url, method=method,
        defaults={
            "status_code": ep.get("status_code"),
            "title": ep.get("title", "") or "",
            "content_length": ep.get("content_length"),
            "content_type": ep.get("content_type", "") or "",
            "redirect_location": ep.get("redirect_location", "") or "",
            "in_scope": ep.get("in_scope", True),
            "source_tools": ep.get("source_tools", []),
        },
    )
    if not created:
        changed = False
        for field in ("status_code", "title", "content_length", "content_type",
                      "redirect_location"):
            val = ep.get(field)
            if val and not getattr(obj, field):
                setattr(obj, field, val)
                changed = True
        merged = set(obj.source_tools or []) | set(ep.get("source_tools", []))
        if merged != set(obj.source_tools or []):
            obj.source_tools = sorted(merged)
            changed = True
        if changed:
            obj.save()


def _finding_key(fd) -> str:
    raw = "|".join(
        [
            fd.get("source_tool", ""),
            fd.get("category", ""),
            fd.get("title", ""),
            str(fd.get("evidence", ""))[:120],
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64]


def _upsert_finding(task, fd) -> None:
    key = _finding_key(fd)
    Finding.objects.update_or_create(
        task=task,
        dedup_key=key,
        defaults={
            "severity": fd.get("severity", "info"),
            "confidence": fd.get("confidence", "medium"),
            "category": fd.get("category", ""),
            "title": fd.get("title", "")[:512],
            "description": fd.get("description", ""),
            "evidence": str(fd.get("evidence", "")),
            "remediation": fd.get("remediation", ""),
            "source_tool": fd.get("source_tool", ""),
        },
    )


def _write_normalized(task, ws: Workspace) -> None:
    services = [
        {
            "ip": s.ip, "port": s.port, "transport": s.transport,
            "service_name": s.service_name, "product": s.product,
            "version": s.version, "extra_info": s.extra_info,
            "source_tool": s.source_tool,
        }
        for s in task.services.all()
    ]
    endpoints = [
        {
            "url": e.url, "method": e.method, "status_code": e.status_code,
            "title": e.title, "content_length": e.content_length,
            "content_type": e.content_type, "redirect_location": e.redirect_location,
            "in_scope": e.in_scope, "source_tools": e.source_tools,
        }
        for e in task.endpoints.all()
    ]
    findings = [
        {
            "severity": f.severity, "confidence": f.confidence,
            "category": f.category, "title": f.title, "description": f.description,
            "evidence": f.evidence, "remediation": f.remediation,
            "source_tool": f.source_tool, "dedup_key": f.dedup_key,
        }
        for f in task.findings.all()
    ]
    ws.write_task_json(task, "normalized/services.json", services)
    ws.write_task_json(task, "normalized/endpoints.json", endpoints)
    ws.write_task_json(task, "normalized/findings.json", findings)


def _task_metadata(task) -> dict:
    return {
        "task_id": str(task.id),
        "name": task.name,
        "target_ip": task.target_ip,
        "target_url": task.target_url,
        "hostname": task.url_hostname,
        "ip_host_mapping": (
            {task.url_hostname: task.target_ip} if task.url_hostname else {}
        ),
        "profile": task.profile,
        "requested_tools": task.requested_tools,
        "created_at": task.created_at.isoformat() if task.created_at else None,
    }


def _step_json(step) -> str:
    return json.dumps(
        {
            "id": str(step.id),
            "tool": step.tool,
            "order": step.order,
            "status": step.status,
            "command_mode": step.command_mode,
            "argv": step.argv,
            "display_command": step.display_command,
            "exit_code": step.exit_code,
            "container_id": step.container_id,
            "started_at": step.started_at.isoformat() if step.started_at else None,
            "finished_at": step.finished_at.isoformat() if step.finished_at else None,
            "error_summary": step.error_summary,
        },
        ensure_ascii=False,
        indent=2,
    )


def request_cancellation(task) -> None:
    with transaction.atomic():
        task.cancel_requested_at = task.cancel_requested_at or _now()
        if task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}:
            task.status = TaskStatus.CANCELLING
        task.save(update_fields=["cancel_requested_at", "status"])
    stop_task_containers(task.id)
