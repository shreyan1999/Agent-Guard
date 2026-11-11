"""Three numbers on the Agent SRE card that said the wrong thing.

None of these was a missing feature. Each was a figure the card displayed
confidently and got backwards, which on a governance dashboard is worse than a
blank — a reader cannot tell a wrong number from a right one.

**Burn rate.** ``ErrorBudget.burn_rate`` divides a dimensionless fraction of
events by a rate in budget-units-per-second. With agent_sre's shipped defaults
that multiplies the observed error rate by 25,920: one failure in three calls
reported 8640x beside "99% of budget remaining", and any error rate above 0.04%
tripped CRITICAL. Fixed by configuring the window the denominator is derived
from rather than overriding the output — agent_sre computes the firing alerts
and the SLO status from its own burn_rate(), so patching only the displayed
number would have left a sane figure beside a badge computed from the broken one.

**Latency direction.** ``SLIValue.is_good`` is ``value >= target`` for every
indicator. Right for a success rate, backwards for a latency: a 15 ms response
against a 3000 ms target scored as failing, and the panel painted the fastest
calls 0% in red.

**Windows.** The four indicators are measured over 30d, 24h, 1h and 7d. Stacked
without labels, `n=54` above `n=27` reads as a discrepancy when it is the same
traffic through a longer lens.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from starlette.testclient import TestClient

import main
import sre_monitor

AGENT = "research-agent"


@pytest.fixture
def client(app_module):
    return TestClient(main.app)


def indicators(client, agent=AGENT):
    slo = next(s for s in client.get("/sre/slos").json()
               if s["agent_id"] == agent)
    return slo, {i["name"]: i for i in slo["indicators"]}


# ── burn rate ────────────────────────────────────────────────────────────────

def test_the_window_is_derived_from_the_target():
    """`total / (1 - target)` makes agent_sre's denominator the allowed error
    rate, which turns its expression into the standard burn rate."""
    assert sre_monitor._budget_window(0.95) == 2000      # 100 / 0.05
    assert sre_monitor._budget_window(0.99) == 10000     # 100 / 0.01


def test_a_target_of_one_does_not_divide_by_zero():
    assert sre_monitor._budget_window(1.0) > 0


def test_one_failure_in_three_is_no_longer_catastrophic(client):
    """The exact case from the screenshot: 8640x and CRITICAL, for two
    successes and one failure."""
    for success in (True, True, False):
        client.post(f"/sre/signal/{AGENT}?success={str(success).lower()}")
    slo, _ = indicators(client)

    burn = slo["error_budget"]["burn_rate"]
    assert burn == pytest.approx(6.67, abs=0.05)   # (1/3) / 0.05
    assert slo["status"] != "critical"


def test_burn_rate_reads_as_a_multiple_of_sustainable(client):
    """1.0 must mean "spending budget exactly as fast as it is earned"."""
    # A 95% target allows a 5% error rate; five failures in a hundred is
    # exactly that, so the burn rate is 1.0.
    for i in range(100):
        client.post(f"/sre/signal/{AGENT}?success={str(i >= 5).lower()}")
    slo, _ = indicators(client)
    assert slo["error_budget"]["burn_rate"] == pytest.approx(1.0, abs=0.05)


def test_a_clean_run_burns_nothing(client):
    for _ in range(5):
        client.post(f"/sre/signal/{AGENT}?success=true")
    slo, _ = indicators(client)
    assert slo["error_budget"]["burn_rate"] == 0.0
    assert slo["status"] == "healthy"


def test_sustained_failure_is_still_critical(client):
    """The alert must not have been silenced along with the false positive."""
    for _ in range(10):
        client.post(f"/sre/signal/{AGENT}?success=false")
    slo, _ = indicators(client)
    assert slo["error_budget"]["burn_rate"] == pytest.approx(20.0, abs=0.1)
    assert slo["status"] == "critical"


# ── latency direction ────────────────────────────────────────────────────────

def test_a_fast_response_is_compliant(client, endpoint_tool):
    """Loopback calls land far under the 3000 ms target, so the row is 100%."""
    for _ in range(4):
        client.post("/tools/call", json={"tool_name": "reporting",
                                         "action": "read", "agent_id": AGENT})
    _, ind = indicators(client)
    latency = ind["response_latency_p95"]
    assert latency["measurement_count"] == 4
    assert latency["compliance"] == 1.0
    assert latency["current_value"] < 3000


def test_the_row_declares_its_direction_and_who_computed_it(client, endpoint_tool):
    """A compliance this platform computed rather than read must say so."""
    client.post("/tools/call", json={"tool_name": "reporting",
                                     "action": "read", "agent_id": AGENT})
    _, ind = indicators(client)
    latency = ind["response_latency_p95"]
    assert latency["direction"] == "lower_is_better"
    assert latency["compliance_source"] == "agentguard"
    assert "3000 ms" in latency["target_note"]
    # Everything else is still agent_sre's own verdict.
    assert ind["task_success_rate"]["compliance_source"] == "agent_sre"
    assert ind["task_success_rate"]["direction"] == "higher_is_better"


def test_a_slow_response_is_not_compliant():
    """The check has to fail in the right direction too, or it is just a
    constant. Driven at the store, since a real call cannot be made slow."""
    store = sre_monitor.SLOStore()
    entry = store.ensure("slowpoke")
    entry.latency.record_latency(9000.0)          # target is 3000 ms
    entry.latency.record_latency(12000.0)
    assert sre_monitor.SLOStore._latency_compliance(entry) == 0.0


def test_a_mixed_run_is_a_real_fraction():
    store = sre_monitor.SLOStore()
    entry = store.ensure("mixed")
    for ms in (10.0, 20.0, 9000.0, 30.0):
        entry.latency.record_latency(ms)
    assert sre_monitor.SLOStore._latency_compliance(entry) == 0.75


def test_the_upstream_rule_this_works_around():
    """Pinned against agent_sre directly, so the override is not invisible.

    If SLIValue ever learns a direction, this fails and _latency_compliance
    can be reconsidered.
    """
    from agent_sre.slo import SLIValue
    fast = SLIValue(name="response_latency_p95", value=15.0,
                    metadata={"target": 3000.0})
    assert fast.is_good is False          # 15 ms judged as failing
    slow = SLIValue(name="response_latency_p95", value=9000.0,
                    metadata={"target": 3000.0})
    assert slow.is_good is True           # 9 s judged as meeting it


# ── windows ──────────────────────────────────────────────────────────────────

def test_every_indicator_reports_the_window_it_is_measured_over(client):
    _, ind = indicators(client)
    assert {i["window"] for i in ind.values()} == {"30d", "24h", "1h", "7d"}


def test_the_windows_really_do_differ(client):
    """The reason the label is needed: the counts are not comparable."""
    _, ind = indicators(client)
    assert ind["task_success_rate"]["window"] != \
        ind["response_latency_p95"]["window"]


def test_the_panel_renders_the_window(frontend_src):
    """A label the API supplies and the panel drops helps nobody."""
    source = (frontend_src / "panels" / "SREPanel.js").read_text(encoding="utf-8")
    assert "ind.window" in source
    assert "ind.current_value" in source, \
        "the latency row should show the percentile it is named after"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def endpoint_tool(client, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    monkeypatch.setenv("AGT_TOOL_ALLOW_PRIVATE", "1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client.post("/tools/register", json={
        "name": "reporting", "description": "Runs a report.",
        "actions": ["read"], "risk": "low", "category": "data_read",
        "endpoint_url": f"http://127.0.0.1:{server.server_address[1]}/run"})
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
