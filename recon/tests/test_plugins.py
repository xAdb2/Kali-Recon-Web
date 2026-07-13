import pytest

from recon.constants import Profile
from recon.services.target import parse_target
from recon.services.workflow import preview_context
from recon.tools import all_plugins, get_plugin

TARGET = parse_target("12.34.56.78", "https://test.test.tw/")

_ALLOWED_EXES = {"nmap", "curl", "whatweb", "dirsearch", "openssl", "nuclei"}


def ctx(tool, open_ports=None, target=TARGET, profile=Profile.SAFE):
    c = preview_context(target, profile, 50, tool)
    if open_ports:
        c.open_ports = open_ports
    return c


def test_every_plugin_has_allowlisted_executable():
    for plugin in all_plugins():
        assert plugin.executable in _ALLOWED_EXES


@pytest.mark.parametrize(
    "tool,open_ports",
    [
        ("nmap_ports", None),
        ("nmap_services", [80, 443]),
        ("http_probe", None),
        ("whatweb", None),
        ("tls", None),
        ("dirsearch", None),
        ("nuclei", None),
    ],
)
def test_build_argv_returns_list_with_allowlisted_first_token(tool, open_ports):
    plugin = get_plugin(tool)
    argv = plugin.build_argv(None, None, ctx(tool, open_ports))
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert argv[0] == plugin.executable
    assert argv[0] in _ALLOWED_EXES


def test_no_plugin_argv_contains_shell():
    for tool in ["nmap_ports", "http_probe", "dirsearch", "nuclei"]:
        argv = get_plugin(tool).build_argv(None, None, ctx(tool, [80]))
        joined = " ".join(argv)
        assert "sh" != argv[0] and "bash" != argv[0]
        assert "/bin/sh" not in argv
        assert "-c" not in argv[:1]
        assert ";" not in joined.replace("test.test.tw", "")


def test_nmap_ports_default_uses_connect_scan_and_target_ip():
    argv = get_plugin("nmap_ports").build_argv(None, None, ctx("nmap_ports"))
    assert "-sT" in argv
    assert argv[-1] == "12.34.56.78"
    assert "-oX" in argv


def test_http_probe_targets_canonical_url_no_follow():
    argv = get_plugin("http_probe").build_argv(None, None, ctx("http_probe"))
    assert argv[-1] == "https://test.test.tw/"
    assert "-L" not in argv  # does not follow redirects


def test_nmap_services_uses_discovered_ports():
    argv = get_plugin("nmap_services").build_argv(None, None, ctx("nmap_services", [80, 443]))
    assert "-p" in argv
    assert "80,443" in argv


def test_nmap_services_not_applicable_without_ports():
    plugin = get_plugin("nmap_services")
    assert plugin.is_applicable(None, ctx("nmap_services", [])) is False
    assert plugin.is_applicable(None, ctx("nmap_services", [80])) is True


def test_tls_only_https():
    http_target = parse_target("12.34.56.78", "http://test.test.tw/")
    assert get_plugin("tls").is_applicable(None, ctx("tls", target=http_target)) is False
    assert get_plugin("tls").is_applicable(None, ctx("tls")) is True
