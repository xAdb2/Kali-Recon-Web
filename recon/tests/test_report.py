import json

import pytest

from recon.models import Endpoint, Finding
from recon.services.artifacts import Workspace
from recon.services.report import build_report_data, generate_reports

from .conftest import build_task

pytestmark = pytest.mark.django_db


def _seed(task):
    Finding.objects.create(
        task=task,
        severity="high",
        confidence="high",
        category="exposure",
        title="<script>alert(1)</script> XSS-looking title",
        description="desc",
        evidence="<img src=x onerror=alert(1)>",
        source_tool="nuclei",
        dedup_key="k1",
    )
    Endpoint.objects.create(
        task=task, url="https://test.test.tw/a", method="GET",
        title="<b>bold</b>", source_tools=["dirsearch"],
    )


def test_html_report_escapes_tool_controlled_strings():
    task = build_task()
    _seed(task)
    ws = Workspace()
    ws.ensure_task_dirs(task)
    generate_reports(task, ws)
    html = ws.resolve_rel(task, "reports/report.html").read_text("utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "onerror=alert(1)>" not in html


def test_json_report_schema_and_dedup():
    task = build_task()
    _seed(task)
    # Duplicate finding key should not create a second row.
    Finding.objects.update_or_create(
        task=task, dedup_key="k1",
        defaults={"severity": "high", "title": "dup", "source_tool": "nuclei"},
    )
    ws = Workspace()
    ws.ensure_task_dirs(task)
    data = generate_reports(task, ws)
    raw = json.loads(ws.resolve_rel(task, "reports/report.json").read_text("utf-8"))
    for key in ["task", "steps", "services", "endpoints", "findings", "generated_at"]:
        assert key in raw
    assert raw["task"]["target_ip"] == "12.34.56.78"
    assert len(data["findings"]) == 1  # dedup kept a single finding


def test_report_data_ip_host_mapping():
    task = build_task()
    data = build_report_data(task)
    assert data["ip_host_mapping"] == {"test.test.tw": "12.34.56.78"}
