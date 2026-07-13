"""Ephemeral scanner container runner (Docker SDK).

Each tool step runs in its own throwaway container labelled with the task and
step UUIDs. The container never runs a shell: ``command`` is always an argv
list. HTTP/TLS tools receive an ``extra_hosts`` mapping so the hostname resolves
to the user-supplied IP inside the container.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from django.conf import settings

logger = logging.getLogger("recon.docker")

LABEL_APP = "kalirecon"
LABEL_TASK = "kalirecon.task"
LABEL_STEP = "kalirecon.step"


class DockerRunnerError(Exception):
    pass


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    container_id: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error


@dataclass
class RunSpec:
    argv: list[str]
    labels: dict[str, str] = field(default_factory=dict)
    extra_hosts: dict[str, str] = field(default_factory=dict)
    timeout: int = 900
    workdir: str = "/workspace"


def _cfg(key: str):
    return settings.KALIRECON[key]


def get_client():
    import docker  # imported lazily so unit tests need no docker daemon

    host = _cfg("DOCKER_HOST")
    if host:
        return docker.DockerClient(base_url=host)
    return docker.from_env()


def _nano_cpus() -> int:
    try:
        return int(float(_cfg("SCANNER_CPU")) * 1_000_000_000)
    except (TypeError, ValueError):
        return 1_000_000_000


def _mounts():
    from docker.types import Mount

    return [
        Mount(
            target="/workspace",
            source=_cfg("WORKSPACE_VOLUME"),
            type="volume",
            read_only=False,
        )
    ]


def run_step(spec: RunSpec, client=None) -> RunResult:
    """Run one scanner step to completion (or timeout) and return its result."""
    try:
        client = client or get_client()
    except Exception as exc:  # noqa: BLE001
        return RunResult(exit_code=None, error=f"Docker 連線失敗：{exc}")

    extra_hosts = {h: ip for h, ip in spec.extra_hosts.items() if h and ip}
    labels = {LABEL_APP: "1", **spec.labels}
    network = _cfg("SCANNER_NETWORK") or None

    container = None
    try:
        container = client.containers.run(
            image=_cfg("SCANNER_IMAGE"),
            command=spec.argv,
            detach=True,
            labels=labels,
            extra_hosts=extra_hosts or None,
            mounts=_mounts(),
            working_dir=spec.workdir,
            network=network,
            environment={"HOME": "/tmp"},
            user="scanner",
            read_only=True,
            tmpfs={"/tmp": "rw,size=256m"},
            mem_limit=_cfg("SCANNER_MEMORY"),
            nano_cpus=_nano_cpus(),
            pids_limit=_cfg("SCANNER_PIDS_LIMIT"),
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            stdin_open=False,
            tty=False,
        )
        cid = container.id
        timed_out = False
        exit_code: int | None = None
        try:
            result = container.wait(timeout=spec.timeout)
            exit_code = result.get("StatusCode")
        except Exception as exc:  # noqa: BLE001 - includes ReadTimeout
            timed_out = True
            logger.warning("step timed out, killing container %s: %s", cid, exc)
            try:
                container.kill()
            except Exception:  # noqa: BLE001
                pass
        stdout = _logs(container, stdout=True, stderr=False)
        stderr = _logs(container, stdout=False, stderr=True)
        return RunResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            container_id=cid,
            timed_out=timed_out,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("scanner container failed")
        return RunResult(exit_code=None, error=str(exc))
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass


def _logs(container, *, stdout: bool, stderr: bool) -> str:
    try:
        data = container.logs(stdout=stdout, stderr=stderr)
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)
    except Exception:  # noqa: BLE001
        return ""


def stop_task_containers(task_id, client=None) -> int:
    """Kill and remove any running scanner containers for a task."""
    try:
        client = client or get_client()
    except Exception as exc:  # noqa: BLE001
        logger.warning("cannot reach docker to stop containers: %s", exc)
        return 0
    stopped = 0
    for container in client.containers.list(
        filters={"label": f"{LABEL_TASK}={task_id}"}
    ):
        try:
            container.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            container.remove(force=True)
        except Exception:  # noqa: BLE001
            pass
        stopped += 1
    return stopped


def cleanup_orphans(client=None) -> int:
    """Remove leftover scanner containers (e.g. after a worker restart)."""
    try:
        client = client or get_client()
    except Exception as exc:  # noqa: BLE001
        logger.warning("cannot reach docker for orphan cleanup: %s", exc)
        return 0
    removed = 0
    for container in client.containers.list(
        all=True, filters={"label": f"{LABEL_APP}=1"}
    ):
        try:
            container.remove(force=True)
            removed += 1
        except Exception:  # noqa: BLE001
            pass
    return removed
