"""The client SDK, driven against the real app via an injected TestClient.

These exercise the genuine paths a deployed agent uses: registration captures
the once-issued private key, authorization signs a real challenge nonce with
agentmesh.identity, and reporting streams telemetry into the SLOs.
"""
import pytest
from starlette.testclient import TestClient

import agt_client
from agt_client import GovernanceClient, GovernanceError


@pytest.fixture
def sdk(app_module):
    """A GovernanceClient whose transport is a TestClient over the seeded app."""
    return GovernanceClient(session=TestClient(app_module.app))


def test_register_captures_the_issued_identity(sdk):
    view = sdk.register("sdk-agent", owner="team@corp")
    assert view["id"] == "sdk-agent"
    assert sdk.agent_id == "sdk-agent"
    assert sdk.did and sdk.did.startswith("did:mesh:")


def test_report_call_feeds_the_slo(sdk):
    sdk.register("sdk-agent")
    res = sdk.report_call("search", allowed=True, latency_ms=42)
    assert res["accepted"] == 1
    assert res["denied_reported"] == 0


def test_report_batches_multiple_events(sdk):
    sdk.register("sdk-agent")
    res = sdk.report([
        {"tool": "search", "allowed": True, "latency_ms": 10},
        {"tool": "delete", "allowed": False, "policy_denied": True, "latency_ms": 3},
    ])
    assert res["accepted"] == 2
    assert res["denied_reported"] == 1


def test_authorize_attaches_a_real_attestation(sdk):
    sdk.register("sdk-agent", trust_score=0.9)
    res = sdk.authorize("web_search", action="read")
    assert res["allowed"] is True
    # The SDK signed the challenge with the key it captured at registration.
    assert res["identity_verified"] is True


def test_authorize_without_attestation_is_flagged(sdk):
    sdk.register("sdk-agent", trust_score=0.9)
    res = sdk.authorize("web_search", action="read", attest=False)
    assert res["allowed"] is True
    assert res["identity_verified"] is False


def test_signal_records_an_out_of_band_success(sdk):
    sdk.register("sdk-agent")
    view = sdk.signal(success=True)
    assert view["agent_id"] == "sdk-agent"


def test_errors_surface_as_governance_errors(sdk):
    # Reporting before registering has no agent_id to send.
    with pytest.raises(GovernanceError):
        sdk.report_call("search")


def test_gateway_rejection_raises(sdk):
    sdk.register("sdk-agent")
    # A second registration of the same id is a 400 from the gateway.
    with pytest.raises(GovernanceError):
        sdk.register("sdk-agent")


def test_urllib_session_is_the_default_transport():
    # Without an injected session the SDK stays dependency-free.
    client = GovernanceClient(base_url="http://localhost:8000")
    assert isinstance(client._session, agt_client._UrllibSession)
