import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from recon.constants import TaskStatus
from recon.models import ScanTask
from recon.services.workflow import create_steps

from .conftest import build_task

pytestmark = pytest.mark.django_db


def _superuser():
    return get_user_model().objects.create_superuser("admin", "a@b.c", "pw-strong-123")


def test_dashboard_requires_login(client):
    resp = client.get(reverse("dashboard"))
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_healthz_public(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.django_db(transaction=True)
def test_create_task_enqueues_celery(client, monkeypatch):
    calls = []

    class FakeTask:
        def delay(self, task_id):
            calls.append(task_id)

    monkeypatch.setattr("recon.tasks.run_scan_task", FakeTask())
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("task_create"),
        data={
            "name": "UI 任務",
            "target_ip": "12.34.56.78",
            "target_url": "https://test.test.tw/",
            "profile": "SAFE",
            "tools": ["nmap_ports", "nuclei"],
            "rate_limit": "50",
            "max_duration": "3600",
            "authorized": "on",
        },
    )
    assert resp.status_code == 302
    task = ScanTask.objects.get(name="UI 任務")
    assert task.status == TaskStatus.QUEUED
    # http_probe prereq auto-inserted for nuclei.
    tools = list(task.steps.order_by("order").values_list("tool", flat=True))
    assert tools == ["nmap_ports", "http_probe", "nuclei"]
    assert calls == [str(task.id)]


def test_create_task_requires_authorization(client):
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("task_create"),
        data={
            "name": "無授權",
            "target_ip": "12.34.56.78",
            "profile": "SAFE",
            "tools": ["nmap_ports"],
            "rate_limit": "50",
            "max_duration": "3600",
        },
    )
    assert resp.status_code == 200  # re-rendered with errors
    assert not ScanTask.objects.filter(name="無授權").exists()


def test_web_tool_without_url_rejected(client):
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("task_create"),
        data={
            "name": "缺URL",
            "target_ip": "12.34.56.78",
            "profile": "SAFE",
            "tools": ["nuclei"],
            "rate_limit": "50",
            "max_duration": "3600",
            "authorized": "on",
        },
    )
    assert resp.status_code == 200
    assert not ScanTask.objects.filter(name="缺URL").exists()


def test_status_endpoint_returns_steps(client):
    user = _superuser()
    client.force_login(user)
    task = build_task(created_by=user, requested_tools=["nmap_ports"])
    create_steps(task)
    resp = client.get(reverse("task_status", args=[task.id]))
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == TaskStatus.CREATED
    assert len(data["steps"]) == 1
    assert data["steps"][0]["tool"] == "nmap_ports"


def test_command_preview_normalizes_for_superuser(client):
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("command_preview"),
        data={
            "tool": "nmap_ports",
            "command": "nmap -sT -Pn --top-ports 100",
            "target_ip": "12.34.56.78",
            "target_url": "https://test.test.tw/",
            "profile": "SAFE",
            "rate_limit": 50,
        },
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "-oX" in data["normalized"]
    assert data["argv"][-1] == "12.34.56.78"


def test_command_preview_rejects_out_of_scope(client):
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("command_preview"),
        data={
            "tool": "nmap_ports",
            "command": "nmap -sT 9.9.9.9",
            "target_ip": "12.34.56.78",
            "target_url": "",
            "profile": "SAFE",
        },
        content_type="application/json",
    )
    assert resp.json()["ok"] is False


def test_command_preview_forbidden_for_non_superuser(client):
    user = get_user_model().objects.create_user("op", password="pw-strong-123")
    client.force_login(user)
    resp = client.post(
        reverse("command_preview"),
        data={"tool": "nmap_ports", "command": "nmap -sT"},
        content_type="application/json",
    )
    assert resp.status_code == 403


def test_expert_disabled_via_setting(client, settings):
    settings.KALIRECON = {**settings.KALIRECON, "ENABLE_EXPERT_COMMANDS": False}
    user = _superuser()
    client.force_login(user)
    resp = client.post(
        reverse("command_preview"),
        data={"tool": "nmap_ports", "command": "nmap -sT"},
        content_type="application/json",
    )
    assert resp.status_code == 403
