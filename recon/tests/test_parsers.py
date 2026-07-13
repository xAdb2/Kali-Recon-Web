import pytest

from recon.parsers.dirsearch import (
    DirsearchParseError,
    parse_dirsearch_csv,
    parse_dirsearch_json,
)
from recon.parsers.nmap import NmapParseError, extract_open_ports, parse_nmap_xml
from recon.parsers.nuclei import parse_nuclei_jsonl

from .conftest import read_fixture


def test_nmap_parses_open_ports_only():
    services = parse_nmap_xml(read_fixture("nmap", "ports.xml"))
    ports = {s["port"] for s in services}
    assert ports == {22, 80, 443}  # 3306 is closed
    ssh = next(s for s in services if s["port"] == 22)
    assert ssh["product"] == "OpenSSH"
    assert ssh["ip"] == "12.34.56.78"


def test_nmap_extract_open_ports_sorted():
    assert extract_open_ports(read_fixture("nmap", "ports.xml")) == [22, 80, 443]


def test_nmap_malformed_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml(read_fixture("nmap", "malformed.xml"))


def test_dirsearch_json():
    rows = parse_dirsearch_json(read_fixture("dirsearch", "results.json"))
    assert len(rows) == 4
    admin = next(r for r in rows if r["url"].endswith("/admin/"))
    assert admin["status_code"] == 401
    old = next(r for r in rows if r["url"].endswith("/old"))
    assert old["redirect_location"] == "https://test.test.tw/new"


def test_dirsearch_csv():
    rows = parse_dirsearch_csv(read_fixture("dirsearch", "results.csv"))
    assert len(rows) == 3
    assert rows[0]["status_code"] == 401


def test_dirsearch_malformed_raises():
    with pytest.raises(DirsearchParseError):
        parse_dirsearch_json(read_fixture("dirsearch", "malformed.json"))


def test_nuclei_jsonl():
    findings = parse_nuclei_jsonl(read_fixture("nuclei", "results.jsonl"))
    assert len(findings) == 3
    sev = {f["template_id"]: f["severity"] for f in findings}
    assert sev["exposed-git-config"] == "medium"


def test_nuclei_malformed_skips_bad_lines():
    # 3-line fixture with one broken JSON line and one non-JSON line.
    findings = parse_nuclei_jsonl(read_fixture("nuclei", "malformed.jsonl"))
    ids = {f["template_id"] for f in findings}
    assert ids == {"tech-detect", "exposed-env"}
