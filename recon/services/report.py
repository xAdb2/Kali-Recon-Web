"""HTML + JSON report generation."""
from __future__ import annotations

from django.template.loader import render_to_string
from django.utils import timezone

from ..constants import SEVERITY_ORDER, Severity, StepStatus
from .artifacts import Workspace


def _grouped_findings(task):
    groups = {sev: [] for sev in Severity.values}
    for f in task.findings.all():
        groups.setdefault(f.severity, []).append(f)
    ordered = sorted(groups.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
    return [(sev, items) for sev, items in ordered if items]


def build_report_data(task) -> dict:
    steps = list(task.steps.all().order_by("order"))
    return {
        "task": {
            "id": str(task.id),
            "name": task.name,
            "status": task.status,
            "target_ip": task.target_ip,
            "target_url": task.target_url,
            "hostname": task.url_hostname,
            "scheme": task.url_scheme,
            "port": task.url_port,
            "base_path": task.url_base_path,
            "profile": task.profile,
            "rate_limit": task.rate_limit,
            "max_duration": task.max_duration,
            "requested_tools": task.requested_tools,
            "created_at": _iso(task.created_at),
            "started_at": _iso(task.started_at),
            "finished_at": _iso(task.finished_at),
            "error_summary": task.error_summary,
        },
        "ip_host_mapping": (
            {task.url_hostname: task.target_ip} if task.url_hostname else {}
        ),
        "steps": [
            {
                "order": s.order,
                "tool": s.tool,
                "title": s.title,
                "status": s.status,
                "command_mode": s.command_mode,
                "display_command": s.display_command,
                "exit_code": s.exit_code,
                "tool_version": s.tool_version,
                "duration_seconds": s.duration_seconds,
                "error_summary": s.error_summary,
            }
            for s in steps
        ],
        "services": [
            {
                "ip": s.ip, "port": s.port, "transport": s.transport,
                "service_name": s.service_name, "product": s.product,
                "version": s.version, "extra_info": s.extra_info,
                "source_tool": s.source_tool,
            }
            for s in task.services.all()
        ],
        "endpoints": [
            {
                "url": e.url, "method": e.method, "status_code": e.status_code,
                "title": e.title, "content_length": e.content_length,
                "content_type": e.content_type,
                "redirect_location": e.redirect_location,
                "in_scope": e.in_scope, "source_tools": e.source_tools,
            }
            for e in task.endpoints.all()
        ],
        "findings": [
            {
                "severity": f.severity, "confidence": f.confidence,
                "category": f.category, "title": f.title,
                "description": f.description, "evidence": f.evidence,
                "remediation": f.remediation, "source_tool": f.source_tool,
                "dedup_key": f.dedup_key,
            }
            for f in task.findings.all()
        ],
        "generated_at": _iso(timezone.now()),
    }


def generate_reports(task, ws: Workspace | None = None) -> dict:
    ws = ws or Workspace()
    data = build_report_data(task)

    failed_steps = [
        s for s in task.steps.all()
        if s.status in {StepStatus.FAILED, StepStatus.TIMED_OUT, StepStatus.SKIPPED}
    ]
    manual_findings = [
        f for f in task.findings.all()
        if f.severity in {Severity.LOW, Severity.MEDIUM} or f.confidence == "low"
    ]

    html = render_to_string(
        "recon/report.html",
        {
            "task": task,
            "data": data,
            "grouped_findings": _grouped_findings(task),
            "failed_steps": failed_steps,
            "manual_findings": manual_findings,
            "artifacts": task.artifacts.all(),
        },
    )
    ws.write_task_text(task, "reports/report.html", html)
    ws.write_task_json(task, "reports/report.json", data)
    ws.register_artifact(task, "reports/report.html", name="report.html",
                         artifact_type="report")
    ws.register_artifact(task, "reports/report.json", name="report.json",
                         artifact_type="report")
    return data


def _iso(value):
    return value.isoformat() if value else None
