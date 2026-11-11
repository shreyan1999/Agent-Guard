"""A swallowed failure has to leave a trace, and has to cost the control it backs.

Every telemetry path in this app catches its own exceptions on purpose: observing
a governed call must never fail it. That policy is right. What was wrong was the
silence around it — `except Exception: return None` meant the anomaly detector
could be dead for the life of the process while `/compliance/owasp` went on
listing `sre_anomaly_detection: true` and the SOC 2 assessment counted it as
evidence for CC7.2.

So a swallowed failure now does two things, and the second is the one that
matters. It writes a log line with the traceback, and it marks its subsystem
degraded — which `_runtime_controls()` reads, so the platform stops scoring
itself on a detector that is not running. Logging a failure nobody reads would
have left the compliance report saying the same untrue thing.

The last test here is the whole point: break the detector, and watch a SOC 2
control stop claiming to be met.
"""

import logging

import pytest

import observability


@pytest.fixture
def clean_registry():
    observability.reset()
    yield observability
    observability.reset()


@pytest.fixture
def captured(clean_registry):
    """A logger whose output is captured, so the log line itself is assertable."""
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    log = observability.get_logger("test.observability")
    handler = Capture()
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    try:
        yield log, records
    finally:
        log.removeHandler(handler)


# -- The record itself --------------------------------------------------------

def test_a_swallowed_failure_is_logged_with_its_traceback(captured):
    log, records = captured
    try:
        {}["missing"]
    except Exception:
        observability.record_failure(observability.SRE_ANOMALY, log,
                                     "anomaly: could not record %r", "agent-1")
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == "anomaly: could not record 'agent-1'"
    assert records[0].exc_info is not None, "the traceback is the diagnosable part"


def test_a_swallowed_failure_marks_its_subsystem_degraded(captured):
    log, _ = captured
    assert observability.degraded_names() == []
    try:
        raise RuntimeError("detector is gone")
    except Exception:
        observability.record_failure(observability.SRE_ANOMALY, log, "failed")
    assert observability.degraded_names() == [observability.SRE_ANOMALY]
    assert observability.is_degraded(observability.SRE_ANOMALY)
    assert not observability.is_degraded(observability.SRE_ALERTS)


def test_failures_accumulate_per_subsystem(captured):
    log, _ = captured
    for _ in range(3):
        try:
            raise ValueError("again")
        except Exception:
            observability.record_failure(observability.SRE_ALERTS, log, "failed")
    report = observability.degraded_report()
    assert len(report) == 1
    assert report[0]["subsystem"] == observability.SRE_ALERTS
    assert report[0]["failures"] == 3
    assert report[0]["last_error_type"] == "ValueError"


def test_the_report_carries_the_type_but_never_the_message(captured):
    """It is served through /compliance/owasp; a message can name a path."""
    log, _ = captured
    try:
        raise OSError("/etc/agt/secret-key.hex is unreadable")
    except Exception:
        observability.record_failure(observability.STATE, log, "failed")
    blob = str(observability.degraded_report())
    assert "OSError" in blob
    assert "secret-key" not in blob


def test_record_failure_never_raises(clean_registry):
    """It is called from inside except blocks; it cannot be the thing that fails."""
    class Broken:
        def warning(self, *a, **k):
            raise RuntimeError("the logger is down")

    observability.record_failure("x", Broken(), "no active exception either")


def test_reset_clears_the_registry(captured):
    log, _ = captured
    try:
        raise RuntimeError("boom")
    except Exception:
        observability.record_failure(observability.SRE_SLO, log, "failed")
    assert observability.degraded_names()
    observability.reset()
    assert observability.degraded_names() == []


# -- What it costs the platform ----------------------------------------------

def _break_anomaly_detector(app_module, monkeypatch):
    """Make AGT's detector raise, the way a changed upstream signature would.

    Applied through `monkeypatch` so it is undone when the test ends. Setting
    the attribute directly patched the detector *instance*, which `clear()`
    used to keep across a teardown — the break then leaked into every later
    test and disabled anomaly detection for the rest of the suite.
    """
    def broken(*args, **kwargs):
        raise TypeError("record_tool_call() got an unexpected keyword argument")
    monkeypatch.setattr(app_module._anomaly._detector,
                        "record_tool_call", broken)


def test_a_broken_detector_stops_being_reported_as_enabled(client, app_module, monkeypatch):
    assert client.get("/compliance/owasp").json()[
        "runtime_controls"]["sre_anomaly_detection"] is True

    _break_anomaly_detector(app_module, monkeypatch)
    client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent"})

    controls = client.get("/compliance/owasp").json()["runtime_controls"]
    assert controls["sre_anomaly_detection"] is False
    assert any(d["subsystem"] == observability.SRE_ANOMALY
               for d in controls["degraded_subsystems"])


def test_the_governed_call_still_succeeds(client, app_module, monkeypatch):
    """Degrading a control must not fail the call the control was observing."""
    _break_anomaly_detector(app_module, monkeypatch)
    r = client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read", "agent_id": "research-agent"})
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_a_broken_detector_costs_a_soc2_control(client, app_module, monkeypatch):
    """The whole point: the compliance report stops claiming what it cannot see.

    CC7.2 is met on the strength of the audit chain *plus* anomaly detection
    over the same traffic. With the detector dead, only the chain is left, so
    the control drops to partial rather than staying met.
    """
    def status_of(control_id):
        report = client.get("/compliance/report?framework=soc2").json()
        return next(c["status"] for c in report["controls"]
                    if c["control_id"] == control_id)

    def governed_call():
        return client.post("/tools/call", json={
            "tool_name": "db_query", "action": "read",
            "agent_id": "research-agent"})

    # CC7.2 rests on the chain *and* the detector, so it needs entries in the
    # chain before it can be met at all. Seeding writes none.
    governed_call()
    assert status_of("SOC2-CC7.2") == "met"

    _break_anomaly_detector(app_module, monkeypatch)
    governed_call()

    assert status_of("SOC2-CC7.2") == "partial", \
        "the report went on counting a detector that had stopped working"


def test_degradation_does_not_leak_between_tests(client):
    """teardown_state resets the registry, like the breach detectors."""
    controls = client.get("/compliance/owasp").json()["runtime_controls"]
    assert controls["sre_anomaly_detection"] is True
    assert controls["degraded_subsystems"] == []
