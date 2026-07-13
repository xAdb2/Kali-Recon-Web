import pytest
from django.utils import timezone

from recon.constants import StepStatus, TaskStatus
from recon.services.target import parse_target
from recon.services.workflow import (
    create_steps,
    plan_tools,
    request_cancellation,
    run_workflow,
)

from .conftest import build_task, make_fixture_runner

HTTPS = parse_target("12.34.56.78", "https://test.test.tw/")
HTTP = parse_target("12.34.56.78", "http://test.test.tw/")
NO_URL = parse_target("12.34.56.78", "")

pytestmark = pytest.mark.django_db


def test_plan_inserts_nmap_ports_prereq():
    assert plan_tools(["nmap_services"], HTTPS) == ["nmap_ports", "nmap_services"]


def test_plan_inserts_http_probe_for_web_tools():
    plan = plan_tools(["nuclei"], HTTPS)
    assert plan == ["http_probe", "nuclei"]


def test_plan_drops_web_tools_without_url():
    assert plan_tools(["whatweb", "nmap_ports"], NO_URL) == ["nmap_ports"]


def test_plan_drops_tls_for_http():
    assert "tls" not in plan_tools(["tls"], HTTP)


def test_create_steps_orders_with_prereqs():
    task = build_task(requested_tools=["nuclei"])
    steps = create_steps(task)
    tools = [s.tool for s in steps]
    assert tools == ["http_probe", "nuclei"]
    assert [s.order for s in steps] == [1, 2]


def test_successful_task_produces_records_and_reports():
    task = build_task()
    create_steps(task)
    run_workflow(task, runner=make_fixture_runner())
    task.refresh_from_db()
    assert task.status == TaskStatus.COMPLETED
    assert task.services.count() >= 3
    assert task.endpoints.count() >= 1
    assert task.findings.count() >= 1
    assert task.artifacts.filter(name="report.html").exists()
    assert task.artifacts.filter(name="report.json").exists()


def test_partial_task_preserves_earlier_results():
    task = build_task()
    create_steps(task)
    run_workflow(task, runner=make_fixture_runner(fail_tools=["nuclei"]))
    task.refresh_from_db()
    assert task.status == TaskStatus.PARTIAL
    # Earlier successful services/endpoints remain.
    assert task.services.count() >= 3
    nuclei_step = task.steps.get(tool="nuclei")
    assert nuclei_step.status == StepStatus.FAILED
    assert task.error_summary


def test_failed_task_when_all_steps_fail():
    task = build_task(requested_tools=["nmap_ports"])
    create_steps(task)
    run_workflow(task, runner=make_fixture_runner(fail_tools=["nmap_ports"]))
    task.refresh_from_db()
    assert task.status == TaskStatus.FAILED


def test_timeout_marks_step_timed_out():
    task = build_task(requested_tools=["nmap_ports", "nmap_services"])
    create_steps(task)
    run_workflow(task, runner=make_fixture_runner(timeout_tools=["nmap_services"]))
    task.refresh_from_db()
    svc_step = task.steps.get(tool="nmap_services")
    assert svc_step.status == StepStatus.TIMED_OUT
    assert task.status in {TaskStatus.PARTIAL, TaskStatus.TIMED_OUT}


def test_cancellation_state_transitions():
    task = build_task(requested_tools=["nmap_ports", "nmap_services"])
    create_steps(task)
    task.cancel_requested_at = timezone.now()
    task.save(update_fields=["cancel_requested_at"])
    run_workflow(task, runner=make_fixture_runner())
    task.refresh_from_db()
    assert task.status == TaskStatus.CANCELLED
    assert all(
        s.status == StepStatus.CANCELLED for s in task.steps.all()
    )


def test_request_cancellation_sets_cancelling(monkeypatch):
    calls = {}
    monkeypatch.setattr(
        "recon.services.workflow.stop_task_containers",
        lambda tid: calls.setdefault("stopped", tid),
    )
    task = build_task(status=TaskStatus.RUNNING)
    request_cancellation(task)
    task.refresh_from_db()
    assert task.status == TaskStatus.CANCELLING
    assert task.cancel_requested_at is not None
    assert calls["stopped"] == task.id
