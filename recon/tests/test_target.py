import pytest

from recon.services.target import (
    TargetValidationError,
    normalize_ip,
    parse_target,
)


@pytest.mark.parametrize("value", ["12.34.56.78", "8.8.8.8", "::1", "2001:db8::1"])
def test_valid_ips(value):
    assert normalize_ip(value)


@pytest.mark.parametrize(
    "value",
    ["12.34.56.0/24", "not-an-ip", "1.2.3.4 5.6.7.8", "1.2.3.4;rm -rf", "",
     "example.com", "12.34.56.78\n"],
)
def test_invalid_ips(value):
    with pytest.raises(TargetValidationError):
        normalize_ip(value)


def test_url_parsing_scheme_host_port_path():
    t = parse_target("12.34.56.78", "https://test.test.tw:8443/app/")
    assert t.scheme == "https"
    assert t.hostname == "test.test.tw"
    assert t.port == 8443
    assert t.base_path == "/app/"
    assert t.is_https
    assert t.host_for_header == "test.test.tw:8443"


def test_default_port_and_root_path():
    t = parse_target("12.34.56.78", "http://test.test.tw")
    assert t.effective_port == 80
    assert t.base_path == "/"
    assert t.canonical_url == "http://test.test.tw/"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://test.test.tw/",
        "gopher://test.test.tw/",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ],
)
def test_reject_unsupported_scheme(url):
    with pytest.raises(TargetValidationError):
        parse_target("12.34.56.78", url)


def test_reject_userinfo():
    with pytest.raises(TargetValidationError):
        parse_target("12.34.56.78", "https://user:pass@test.test.tw/")


def test_reject_control_chars():
    with pytest.raises(TargetValidationError):
        parse_target("12.34.56.78", "https://test.test.tw/\x00evil")


def test_hostname_idna_normalization():
    t = parse_target("12.34.56.78", "https://TEST.test.tw/")
    assert t.hostname == "test.test.tw"


def test_nmap_only_no_url():
    t = parse_target("12.34.56.78", "")
    assert not t.has_url
    assert t.ip == "12.34.56.78"
