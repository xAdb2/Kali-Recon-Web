#!/usr/bin/env python
"""Block until PostgreSQL and Redis TCP ports accept connections."""
from __future__ import annotations

import os
import socket
import sys
import time


def wait(host: str, port: int, name: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                print(f"[wait] {name} is up at {host}:{port}")
                return True
        except OSError:
            time.sleep(1)
    print(f"[wait] timed out waiting for {name} at {host}:{port}", file=sys.stderr)
    return False


def main() -> int:
    ok = True
    ok &= wait(os.environ.get("POSTGRES_HOST", "db"),
               int(os.environ.get("POSTGRES_PORT", "5432")), "postgres")
    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    # crude parse: redis://host:port/db
    rest = redis_url.split("://", 1)[-1]
    hostport = rest.split("/", 1)[0]
    rhost, _, rport = hostport.partition(":")
    ok &= wait(rhost or "redis", int(rport or "6379"), "redis")
    return 0 if ok else 0  # non-fatal: entrypoint proceeds and retries migrate


if __name__ == "__main__":
    sys.exit(main())
