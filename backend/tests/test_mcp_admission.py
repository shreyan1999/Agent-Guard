"""The two AGT controls that run before a connection is opened.

``agent_os.mcp_auth_enforcement`` judges how a connection is authenticated, and
``agent_os.mcp_cve_feed`` judges whether the server's own package has a known
vulnerability. Both sit earlier than every other MCP control here: by the time a
descriptor is being graded, the platform has already trusted the server enough
to talk to it.

Two exemptions carry most of the risk of this being security theatre, so they
are pinned in both directions. ``stdio`` is exempt because a subprocess has no
network connection to authenticate — a check that cannot fail is worse than no
check, since it still shows up in a report. A loopback address is exempt because
reaching one already required ``AGT_TOOL_ALLOW_PRIVATE``, and the tests below
assert that setting ``AGT_MCP_AUTH_STRICT`` really does remove that exemption
rather than merely claiming to.

The public-address cases use IP literals rather than hostnames so no test
depends on DNS, and the allowed ones are asserted against the policy object
directly — a test that let a connection proceed would reach for the network.
"""

import pytest
from starlette.testclient import TestClient

import main
import mcp_admission
from mcp_admission import ConnectionAdmission, VulnerabilityIndex, PackageEntry

from test_mcp_connector import _import, mcp_server  # noqa: F401

# An IP literal, so no test depends on DNS. Deliberately *not* an RFC 5737
# documentation address: Python's ipaddress module counts 192.0.2.0/24,
# 198.51.100.0/24 and 203.0.113.0/24 as private, so one of those would take the
# loopback exemption and never reach the policy being tested. Nothing here ever
# connects — the allowed cases are asserted against the policy object directly.
PUBLIC = "8.8.8.8"


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


@pytest.fixture
def admission():
    return ConnectionAdmission()


def check(admission, url, *, transport="http", token=False, name="srv"):
    return admission.check(server_name=name, url=url, transport=transport,
                           has_token=token)


# ── the auth method ───────────────────────────────────────────────────────────

def test_a_public_server_with_no_credential_is_refused(admission):
    """AGT's default policy denies auth_method=none, and so does this."""
    verdict = check(admission, f"https://{PUBLIC}/mcp")
    assert verdict["allowed"] is False
    assert verdict["auth_method"] == "none"
    assert verdict["enforced"] is True


def test_a_public_server_with_a_bearer_token_over_tls_is_allowed(admission):
    verdict = check(admission, f"https://{PUBLIC}/mcp", token=True)
    assert verdict["allowed"] is True
    assert verdict["auth_method"] == "bearer"


def test_a_token_is_not_sent_over_cleartext(admission):
    """The gap AGT's default path leaves open.

    ``McpAuthPolicy`` applies ``require_tls`` only to servers in its explicit
    allowlist. A connection falling through to the default allowlist is judged
    on its auth method alone, so a bearer token to a public host over plain
    http was *allowed* — the credential travelling in cleartext past the
    control that exists to require one.
    """
    verdict = check(admission, f"http://{PUBLIC}/mcp", token=True)
    assert verdict["allowed"] is False
    assert "TLS" in verdict["reason"]


def test_a_loopback_server_is_exempt_by_default(admission):
    """Reaching it already required AGT_TOOL_ALLOW_PRIVATE."""
    verdict = check(admission, "http://127.0.0.1:9000/mcp")
    assert verdict["allowed"] is True
    assert verdict["enforced"] is False
    assert "AGT_TOOL_ALLOW_PRIVATE" in verdict["reason"]


def test_strict_mode_really_removes_the_loopback_exemption(monkeypatch):
    """The exemption has to be switchable or it is just a hole with a comment."""
    monkeypatch.setenv("AGT_MCP_AUTH_STRICT", "1")
    verdict = check(ConnectionAdmission(), "http://127.0.0.1:9000/mcp")
    assert verdict["allowed"] is False
    assert verdict["enforced"] is True


def test_a_private_range_address_is_treated_like_loopback(admission):
    assert check(admission, "http://10.1.2.3/mcp")["enforced"] is False
    assert check(admission, "http://192.168.1.5:8080/mcp")["enforced"] is False


def test_stdio_is_exempt_and_says_why(admission):
    """A subprocess has no connection to authenticate."""
    verdict = check(admission, "", transport="stdio")
    assert verdict["allowed"] is True
    assert verdict["enforced"] is False
    assert verdict["auth_method"] == "stdio"
    assert "command allowlist" in verdict["reason"]


def test_an_unresolvable_host_is_treated_as_public(admission):
    """"Not known to be private" is not "private". The exemption is earned."""
    verdict = check(admission, "https://this-host-does-not-resolve.invalid/mcp")
    assert verdict["enforced"] is True


def test_pinning_a_server_can_only_narrow_it(admission):
    admission.pin("finance", f"https://{PUBLIC}/finance", ["mtls"])
    bearer = check(admission, f"https://{PUBLIC}/finance", token=True,
                   name="finance")
    assert bearer["allowed"] is False
    assert "not allowed for server" in bearer["reason"]


def test_unpinning_restores_the_default_allowlist(admission):
    admission.pin("finance", f"https://{PUBLIC}/finance", ["mtls"])
    assert admission.unpin("finance") is True
    assert check(admission, f"https://{PUBLIC}/finance", token=True,
                 name="finance")["allowed"] is True


def test_the_allowlist_is_configurable(monkeypatch):
    monkeypatch.setenv("AGT_MCP_AUTH_METHODS", "mtls")
    verdict = check(ConnectionAdmission(), f"https://{PUBLIC}/mcp", token=True)
    assert verdict["allowed"] is False


def test_a_typo_in_the_allowlist_narrows_rather_than_crashes(monkeypatch):
    """McpServerEntry raises on an unknown method.

    Letting that propagate would take the whole admission control down over one
    bad environment variable, so an unrecognised name is dropped — which can
    only make the allowlist smaller.
    """
    monkeypatch.setenv("AGT_MCP_AUTH_METHODS", "oauth2,not-a-method")
    assert mcp_admission._env_methods() == ["oauth2"]
    monkeypatch.setenv("AGT_MCP_AUTH_METHODS", "entirely,bogus")
    assert mcp_admission._env_methods() == list(mcp_admission.DEFAULT_METHODS)


# ── through the API ───────────────────────────────────────────────────────────

def test_discovery_refuses_an_unauthenticated_public_server(client):
    """Refused before connecting, which is the point — reading the descriptors
    is the thing being protected against."""
    r = client.post("/mcp/discover", json={"server_url": f"https://{PUBLIC}/mcp",
                                           "transport": "http"})
    assert r.status_code == 400
    assert "Unauthenticated" in r.json()["detail"]


def test_the_loopback_demo_server_still_imports(client, mcp_server):
    """The exemption exists so the shipped demo runs. If this breaks, the
    exemption was written wrong."""
    assert _import(client, mcp_server[1], tools=["echo"]).status_code == 200


def test_an_import_records_how_the_connection_was_authenticated(client, mcp_server):
    body = _import(client, mcp_server[1], tools=["echo"]).json()
    assert body["admission"]["auth_method"] == "none"
    assert body["admission"]["enforced"] is False
    spec = body["imported"][0]
    assert spec["mcp"]["auth_method"] == "none"


def test_discovery_and_dispatch_auth_are_recorded_separately(client, mcp_server):
    """They genuinely differ: discovery may carry a one-off token while a
    dispatch reads auth_env, so a tool imported over an authenticated
    connection can still dispatch unauthenticated."""
    body = _import(client, mcp_server[1], tools=["echo"],
                   auth_token="t0ken", auth_env=None).json()
    spec = body["imported"][0]["mcp"]
    assert spec["auth_method"] == "bearer"
    assert spec["dispatch_auth_method"] == "none"


# ── the packages a launch command names ──────────────────────────────────────

@pytest.mark.parametrize("command,args,expected", [
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem@1.2.0"],
     ("@modelcontextprotocol/server-filesystem", "1.2.0", "npm")),
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem"],
     ("@modelcontextprotocol/server-filesystem", "", "npm")),
    ("uvx", ["mcp-server-git==0.3.1"], ("mcp-server-git", "0.3.1", "PyPI")),
    ("python", ["-m", "mcp_server_sqlite"], ("mcp_server_sqlite", "", "PyPI")),
])
def test_a_package_specification_is_read_from_the_command(command, args, expected):
    found = mcp_admission.packages_from_launch(command, args)
    assert len(found) == 1
    assert (found[0].name, found[0].version, found[0].ecosystem) == expected


@pytest.mark.parametrize("command,args", [
    ("python", ["server.py"]),        # code from disk, no published package
    ("node", ["/app/index.js"]),
    ("docker", ["run", "some/image"]),
    ("npx", []),
])
def test_a_command_naming_no_package_yields_nothing(command, args):
    """And *nothing* is later reported as unchecked, never as clean."""
    assert mcp_admission.packages_from_launch(command, args) == []


# ── the advisory feed ─────────────────────────────────────────────────────────

def test_a_package_with_no_advisory_is_unchecked_not_clean():
    """The distinction the whole control rests on. Offline, nothing was
    queried, and saying "no vulnerabilities" would be a claim about a lookup
    that never happened."""
    report = VulnerabilityIndex().check(
        [PackageEntry(name="mcp-server-git", version="0.3.1", ecosystem="PyPI")])
    assert report["vulnerabilities"] == []
    assert len(report["unchecked"]) == 1
    assert report["checked"] == []
    assert "AGT_MCP_CVE_ONLINE" in report["unchecked"][0]["reason"]


def test_an_unversioned_package_says_so_specifically():
    report = VulnerabilityIndex().check(
        [PackageEntry(name="x", version="", ecosystem="npm")])
    assert "no version to look up" in report["unchecked"][0]["reason"]


def test_an_operator_advisory_is_found():
    index = VulnerabilityIndex()
    index.add_advisory(package="evil-mcp", version="1.0.0",
                       cve_id="CVE-2026-0001", severity="critical",
                       summary="Arbitrary file read.")
    report = index.check([PackageEntry(name="evil-mcp", version="1.0.0",
                                       ecosystem="npm")])
    assert [v["cve_id"] for v in report["vulnerabilities"]] == ["CVE-2026-0001"]
    assert report["highest_severity"] == "CRITICAL"
    assert report["blocking"] is True
    assert report["unchecked"] == []


def test_the_agt_cache_key_mismatch_this_works_around():
    """Pinned because the workaround is invisible otherwise.

    ``McpCveFeed.add_manual_advisory`` writes to ``manual:<pkg>:<ver>`` while
    ``check_package`` reads ``<ecosystem>:<pkg>:<ver>``, so an advisory added
    for an npm package is never returned by ``check_all``. If AGT fixes that,
    this test fails and the probe in ``_lookup`` can be simplified.
    """
    from agent_os.mcp_cve_feed import McpCveFeed, VulnerabilityRecord
    feed = McpCveFeed()
    feed.add_package("evil-mcp", version="1.0.0", ecosystem="npm")
    feed.add_manual_advisory(VulnerabilityRecord(
        cve_id="CVE-2026-0001", package="evil-mcp", version="1.0.0",
        severity="CRITICAL", summary="x"))

    assert feed.check_all() == []                       # the mismatch
    assert feed.check_package("evil-mcp", "1.0.0", "manual")   # where it landed


def test_a_lower_severity_is_reported_but_does_not_block():
    index = VulnerabilityIndex()
    index.add_advisory(package="meh", version="2.0", cve_id="CVE-2026-0002",
                       severity="MEDIUM", summary="Minor.")
    report = index.check([PackageEntry(name="meh", version="2.0",
                                       ecosystem="npm")])
    assert report["highest_severity"] == "MEDIUM"
    assert report["blocking"] is False


def test_advisories_are_recorded_through_the_api(client):
    r = client.post("/mcp/advisories", json={
        "package": "evil-mcp", "version": "1.0.0", "cve_id": "CVE-2026-0001",
        "severity": "critical", "summary": "Arbitrary file read."})
    assert r.status_code == 200
    assert r.json()["severity"] == "CRITICAL"
    assert main._mcp_vulns.describe()["local_advisories"] == 1


def test_a_bad_severity_is_refused(client):
    assert client.post("/mcp/advisories", json={
        "package": "p", "version": "1", "cve_id": "c",
        "severity": "catastrophic"}).status_code == 400


def test_a_remote_server_names_no_package_and_says_so(client, mcp_server):
    """An HTTP MCP server is reached by URL. There is no package to check, and
    the report says that rather than returning an empty clean bill."""
    _import(client, mcp_server[1], tools=["echo"])
    report = client.post("/mcp/servers/demo-notes/vulnerabilities").json()
    assert report["vulnerabilities"] == []
    assert report["checked"] == []
    assert "names no package" in report["note"]


def test_scanning_an_unknown_server_is_a_404(client):
    assert client.post("/mcp/servers/nope/vulnerabilities").status_code == 404


def test_the_feed_reports_that_it_is_offline(client):
    entry = next(c for c in client.get("/mcp/controls").json()["controls"]
                 if c["gate"] == "mcp_vulnerabilities")
    assert entry["online"] is False
    assert "operator-entered" in entry["source"]
