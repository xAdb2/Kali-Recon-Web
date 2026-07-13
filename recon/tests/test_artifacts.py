import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from recon.models import Artifact
from recon.services.artifacts import Workspace, WorkspaceError

from .conftest import build_task

pytestmark = pytest.mark.django_db


def _make_artifact(task, rel="steps/01-nmap_ports/result.xml", content="<x/>"):
    ws = Workspace()
    ws.ensure_task_dirs(task)
    path = ws.resolve_rel(task, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return ws.register_artifact(task, rel, name="result.xml")


def test_path_traversal_blocked():
    task = build_task()
    ws = Workspace()
    ws.ensure_task_dirs(task)
    with pytest.raises(WorkspaceError):
        ws.resolve_rel(task, "../../etc/passwd")


def test_unauthenticated_download_denied(client):
    task = build_task()
    artifact = _make_artifact(task)
    url = reverse("artifact_download", args=[task.id, artifact.id])
    resp = client.get(url)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_authenticated_download_succeeds(client):
    User = get_user_model()
    user = User.objects.create_user("op", password="pw-strong-123")
    client.force_login(user)
    task = build_task(created_by=user)
    artifact = _make_artifact(task, content="<hello/>")
    url = reverse("artifact_download", args=[task.id, artifact.id])
    resp = client.get(url)
    assert resp.status_code == 200
    assert b"<hello/>" in b"".join(resp.streaming_content)


def test_download_with_traversal_rel_path_404(client):
    User = get_user_model()
    user = User.objects.create_user("op2", password="pw-strong-123")
    client.force_login(user)
    task = build_task(created_by=user)
    # Force a malicious rel_path directly in the DB row.
    artifact = Artifact.objects.create(
        task=task, name="evil", rel_path="../../etc/passwd", size=0
    )
    url = reverse("artifact_download", args=[task.id, artifact.id])
    resp = client.get(url)
    assert resp.status_code == 404
