"""Workspace filesystem access and artifact registration.

The workspace is a Docker named volume mounted at the same path in the web,
worker and scanner containers. All path handling is confined to a task's own
directory to prevent traversal.
"""
from __future__ import annotations

import hashlib
import json
import mimetypes
from pathlib import Path

from django.conf import settings

_MIME_OVERRIDES = {
    ".log": "text/plain",
    ".jsonl": "application/x-ndjson",
    ".xml": "application/xml",
}


class WorkspaceError(Exception):
    pass


class Workspace:
    def __init__(self, root: str | None = None):
        self.root = Path(root or settings.KALIRECON["WORKSPACE_ROOT"]).resolve()

    # ---- path helpers ------------------------------------------------------
    def task_dir(self, task) -> Path:
        return (self.root / str(task.id)).resolve()

    def step_dir(self, step) -> Path:
        return (self.task_dir(step.task) / step.workspace_rel).resolve()

    def _safe(self, base: Path, rel: str) -> Path:
        candidate = (base / rel).resolve()
        if base != candidate and base not in candidate.parents:
            raise WorkspaceError(f"path traversal blocked: {rel}")
        return candidate

    def resolve_rel(self, task, rel_path: str) -> Path:
        """Resolve a task-relative artifact path, blocking traversal."""
        return self._safe(self.task_dir(task), rel_path)

    # ---- directory setup ---------------------------------------------------
    def ensure_task_dirs(self, task) -> None:
        base = self.task_dir(task)
        for sub in ("", "steps", "normalized", "reports"):
            (base / sub).mkdir(parents=True, exist_ok=True)

    def ensure_step_dir(self, step) -> Path:
        d = self.step_dir(step)
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ---- read/write --------------------------------------------------------
    def read_step_text(self, step, filename: str) -> str:
        path = self._safe(self.step_dir(step), filename)
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def write_step_bytes(self, step, filename: str, data: bytes) -> Path:
        path = self._safe(self.step_dir(step), filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_step_text(self, step, filename: str, text: str) -> Path:
        return self.write_step_bytes(step, filename, text.encode("utf-8"))

    def write_task_json(self, task, rel_path: str, data) -> Path:
        path = self.resolve_rel(task, rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        return path

    def write_task_text(self, task, rel_path: str, text: str) -> Path:
        path = self.resolve_rel(task, rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    # ---- artifact registration --------------------------------------------
    def register_artifact(self, task, rel_path: str, *, step=None, name="",
                          artifact_type="file"):
        from ..models import Artifact

        abs_path = self.resolve_rel(task, rel_path)
        if not abs_path.exists() or not abs_path.is_file():
            return None
        data = abs_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        suffix = abs_path.suffix.lower()
        mime = _MIME_OVERRIDES.get(suffix) or (
            mimetypes.guess_type(abs_path.name)[0] or "application/octet-stream"
        )
        artifact, _ = Artifact.objects.update_or_create(
            task=task,
            rel_path=rel_path,
            defaults={
                "step": step,
                "name": name or abs_path.name,
                "artifact_type": artifact_type,
                "mime_type": mime,
                "size": len(data),
                "sha256": sha,
            },
        )
        return artifact

    def register_step_dir(self, task, step) -> None:
        base = self.step_dir(step)
        if not base.exists():
            return
        for path in sorted(base.iterdir()):
            if path.is_file():
                rel = path.relative_to(self.task_dir(task)).as_posix()
                self.register_artifact(task, rel, step=step, name=path.name)
