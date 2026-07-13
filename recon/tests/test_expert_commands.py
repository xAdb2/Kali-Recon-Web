"""Positive and negative expert-command validation for every plugin."""
import pytest

from recon.constants import Profile
from recon.services.target import parse_target
from recon.services.workflow import preview_context
from recon.tools import get_plugin
from recon.tools.base import ExpertCommandError, tokenize_expert

TARGET = parse_target("12.34.56.78", "https://test.test.tw/")


def ctx(tool):
    return preview_context(TARGET, Profile.SAFE, 50, tool)


def validate(tool, text):
    return get_plugin(tool).validate_expert(text, None, None, ctx(tool))


# --- generic tokenizer ------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "nmap -sT; rm -rf /",
        "nmap -sT && curl x",
        "nmap -sT | tee out",
        "nmap -sT > /etc/passwd",
        "nmap `id`",
        "nmap $(id)",
        "nmap ${HOME}",
        "nmap -sT \n curl",
        "nmap -sT & ",
        "FOO=bar nmap -sT",
    ],
)
def test_tokenizer_rejects_shell_syntax(text):
    with pytest.raises(ExpertCommandError):
        tokenize_expert(text)


def test_tokenizer_accepts_simple():
    assert tokenize_expert("nmap -sT -Pn 12.34.56.78")[0] == "nmap"


# --- executable pinning -----------------------------------------------------
@pytest.mark.parametrize(
    "tool,text",
    [
        ("nmap_ports", "sudo nmap -sT 12.34.56.78"),
        ("nmap_ports", "python -c pass"),
        ("http_probe", "wget https://test.test.tw/"),
        ("nuclei", "bash -c nuclei"),
    ],
)
def test_first_token_must_be_plugin_executable(tool, text):
    with pytest.raises(ExpertCommandError):
        validate(tool, text)


# --- nmap -------------------------------------------------------------------
def test_nmap_accepts_and_injects_output_and_target():
    argv = validate("nmap_ports", "nmap -sT -Pn --top-ports 200")
    assert argv[0] == "nmap"
    assert "-oX" in argv
    assert argv[-1] == "12.34.56.78"


@pytest.mark.parametrize(
    "text",
    [
        "nmap -sT 9.9.9.9",  # second/other target
        "nmap -iL /etc/hosts",  # input list
        "nmap -sT -D RND:10 12.34.56.78",  # decoy
        "nmap --script /tmp/evil.nse 12.34.56.78",  # script path
        "nmap --script vuln 12.34.56.78",  # non-allowlisted script
    ],
)
def test_nmap_rejects(text):
    with pytest.raises(ExpertCommandError):
        validate("nmap_ports", text)


def test_nmap_strips_user_output_flag():
    argv = validate("nmap_ports", "nmap -sT -oX /tmp/evil.xml")
    assert "/tmp/evil.xml" not in argv
    assert argv[argv.index("-oX") + 1].endswith("result.xml")


# --- curl / http_probe ------------------------------------------------------
def test_curl_accepts_default_url():
    argv = validate("http_probe", "curl -sS https://test.test.tw/")
    assert argv[0] == "curl"
    assert argv[-1] == "https://test.test.tw/"


@pytest.mark.parametrize(
    "text",
    [
        "curl https://evil.example/",  # out of scope host
        "curl file:///etc/passwd",
        "curl -x http://127.0.0.1:8080 https://test.test.tw/",  # proxy
        "curl -T /etc/passwd https://test.test.tw/",  # upload
        "curl -d @/etc/passwd https://test.test.tw/",  # file body
    ],
)
def test_curl_rejects(text):
    with pytest.raises(ExpertCommandError):
        validate("http_probe", text)


# --- whatweb ----------------------------------------------------------------
def test_whatweb_accepts():
    argv = validate("whatweb", "whatweb -a 1")
    assert argv[0] == "whatweb"
    assert any(a.startswith("--log-json=") for a in argv)


def test_whatweb_rejects_input_file():
    with pytest.raises(ExpertCommandError):
        validate("whatweb", "whatweb -i /etc/hosts")


# --- dirsearch --------------------------------------------------------------
def test_dirsearch_accepts_allowed_wordlist():
    argv = validate("dirsearch", "dirsearch -t 5 -w /opt/wordlists/common.txt")
    assert argv[0] == "dirsearch"
    assert "--format=json" in argv


@pytest.mark.parametrize(
    "text",
    [
        "dirsearch -l /tmp/targets.txt",
        "dirsearch -w /etc/passwd",
        "dirsearch -w ../../etc/passwd",
        "dirsearch -u https://evil.example/",
    ],
)
def test_dirsearch_rejects(text):
    with pytest.raises(ExpertCommandError):
        validate("dirsearch", text)


# --- openssl / tls ----------------------------------------------------------
def test_openssl_accepts_s_client():
    argv = validate("tls", "openssl s_client")
    assert argv[:2] == ["openssl", "s_client"]
    assert "-connect" in argv
    assert argv[argv.index("-connect") + 1] == "12.34.56.78:443"


@pytest.mark.parametrize(
    "text",
    [
        "openssl x509 -in /etc/ssl/cert.pem",  # wrong subcommand
        "openssl s_client -connect 9.9.9.9:443",  # override stripped/re-injected
        "openssl s_client -CAfile /etc/passwd",
    ],
)
def test_openssl_rejects(text):
    # note: -connect override is stripped, but wrong subcommand / banned file flags fail
    if "x509" in text or "CAfile" in text:
        with pytest.raises(ExpertCommandError):
            validate("tls", text)
    else:
        argv = validate("tls", text)
        assert argv[argv.index("-connect") + 1] == "12.34.56.78:443"


# --- nuclei -----------------------------------------------------------------
def test_nuclei_accepts_allowed_tags():
    argv = validate("nuclei", "nuclei -tags tech,exposure")
    assert argv[0] == "nuclei"
    assert "-jsonl" in argv


@pytest.mark.parametrize(
    "text",
    [
        "nuclei -tags dos",
        "nuclei -headless",
        "nuclei -t /tmp/evil.yaml",
        "nuclei -l /tmp/targets.txt",
        "nuclei -u https://evil.example/",
    ],
)
def test_nuclei_rejects(text):
    with pytest.raises(ExpertCommandError):
        validate("nuclei", text)
