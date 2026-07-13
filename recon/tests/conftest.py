"""Shared pytest fixtures and a fixture-driven fake scanner runner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.conf import settings

from recon.constants import Profile
from recon.models import ScanTask
from recon.services.docker_runner import RunResult

FIXTURES = Path(settings.BASE_DIR) / "fixtures"

_WHATWEB_JSON = json.dumps(
    [
        {
            "target": "https://test.test.tw/",
            "http_status": 200,
            "plugins": {
                "Title": {"string": ["Test Site"]},
                "nginx": {"version": ["1.24.0"]},
                "Bootstrap": {},
            },
        }
    ]
)

_CURL_BODY = "<html><head><title>Test Site</title></head><body>ok</body></html>"
_CURL_STDOUT = json.dumps(
    {
        "status": 200,
        "content_type": "text/html",
        "size_download": len(_CURL_BODY),
        "redirect_url": "",
        "url_effective": "https://test.test.tw/",
        "ssl_verify": 0,
        "num_redirects": 0,
    }
)

_OPENSSL_STDOUT = """CONNECTED(00000003)
subject=CN=test.test.tw
issuer=C=US, O=Let's Encrypt, CN=R3
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
---
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
"""


@pytest.fixture(autouse=True)
def workspace_tmp(tmp_path, settings):
    """Point the workspace at an isolated temp dir for every test."""
    settings.KALIRECON = {**settings.KALIRECON, "WORKSPACE_ROOT": str(tmp_path)}
    settings.KALIRECON["ENABLE_EXPERT_COMMANDS"] = True
    yield


def read_fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def _arg_after(argv, flag):
    if flag in argv:
        idx = argv.index(flag)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def _detect_tool(argv):
    exe = argv[0]
    if exe == "nmap":
        return "nmap_services" if "-sV" in argv else "nmap_ports"
    return {
        "curl": "http_probe",
        "whatweb": "whatweb",
        "openssl": "tls",
        "dirsearch": "dirsearch",
        "nuclei": "nuclei",
    }.get(exe, exe)


def make_fixture_runner(fail_tools=(), timeout_tools=()):
    """Return a runner(spec) that writes fixture outputs like a real scan."""

    def runner(spec):
        argv = spec.argv
        tool = _detect_tool(argv)
        if tool in timeout_tools:
            return RunResult(exit_code=None, timed_out=True, container_id="fake-c")
        if tool in fail_tools:
            return RunResult(exit_code=1, stderr="模擬失敗", container_id="fake-c")

        stdout = ""
        if tool in {"nmap_ports", "nmap_services"}:
            _write(_arg_after(argv, "-oX"), read_fixture("nmap", "ports.xml"))
        elif tool == "http_probe":
            _write(_arg_after(argv, "-o"), _CURL_BODY)
            _write(_arg_after(argv, "-D"), "HTTP/1.1 200 OK\r\n")
            stdout = _CURL_STDOUT
        elif tool == "whatweb":
            path = next(
                (a.split("=", 1)[1] for a in argv if a.startswith("--log-json=")),
                None,
            )
            _write(path, _WHATWEB_JSON)
        elif tool == "tls":
            stdout = _OPENSSL_STDOUT
        elif tool == "dirsearch":
            _write(_arg_after(argv, "-o"), read_fixture("dirsearch", "results.json"))
        elif tool == "nuclei":
            _write(_arg_after(argv, "-o"), read_fixture("nuclei", "results.jsonl"))
        return RunResult(exit_code=0, stdout=stdout, container_id="fake-c")

    return runner


def _write(path, text):
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def fixture_runner():
    return make_fixture_runner()


def build_task(**overrides) -> ScanTask:
    data = {
        "name": "示範任務",
        "target_ip": "12.34.56.78",
        "target_url": "https://test.test.tw/",
        "url_scheme": "https",
        "url_hostname": "test.test.tw",
        "url_port": None,
        "url_base_path": "/",
        "profile": Profile.SAFE,
        "requested_tools": ["nmap_services", "whatweb", "tls", "dirsearch", "nuclei"],
        "tool_config": {},
        "rate_limit": 50,
        "max_duration": 3600,
        "authorized": True,
    }
    data.update(overrides)
    return ScanTask.objects.create(**data)
