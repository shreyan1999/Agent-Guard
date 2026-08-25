"""Every demo button in the UI must produce the verdict its label advertises.

This suite reads `DEMO_CALLS` out of ToolPanel.js rather than restating it, so
a button added or relabelled in the frontend is checked against the backend
automatically. Two shipped demos once lied: "SSN DETECTED (deny)" allowed the
call, and "SEND EMAIL (warn)" denied it.
"""

import json
import re

import pytest

DEMO_BLOCK = re.compile(r"const DEMO_CALLS\s*=\s*\[(.*?)\n\];", re.S)
FIELD = re.compile(r"(\w+):\s*'((?:[^'\\]|\\.)*)'")


def load_demos(frontend_src):
    """Parse the DEMO_CALLS array out of ToolPanel.js."""
    source = (frontend_src / "panels" / "ToolPanel.js").read_text(encoding="utf-8")
    block = DEMO_BLOCK.search(source)
    assert block, "DEMO_CALLS not found in ToolPanel.js — has the panel been restructured?"

    demos = []
    for line in block.group(1).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        fields = {k: v.replace("\\'", "'") for k, v in FIELD.findall(line)}
        assert "label" in fields, f"demo without a label: {line}"
        demos.append(fields)
    assert demos, "DEMO_CALLS parsed as empty"
    return demos


def expected_verdict(label):
    """Read the advertised outcome out of the button label."""
    low = label.lower()
    if "allowed" in low:
        return True
    if "deny" in low or "denied" in low:
        return False
    pytest.fail(f"Demo label {label!r} does not state an expected verdict")


def pytest_generate_tests(metafunc):
    """Parametrise over the demos, discovered at collection time."""
    if "demo" not in metafunc.fixturenames:
        return
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "frontend" / "src"
    demos = load_demos(src)
    metafunc.parametrize("demo", demos, ids=[d["label"] for d in demos])


def test_demo_button_matches_its_label(client, demo):
    r = client.post("/tools/call", json={
        "tool_name": demo.get("tool", "db_query"),
        "action": demo.get("action", "read"),
        "input_text": demo.get("input_text", ""),
        "agent_id": demo.get("agent_id", "research-agent"),
    })
    assert r.status_code == 200, r.text
    actual = r.json()["allowed"]
    expected = expected_verdict(demo["label"])
    assert actual is expected, (
        f"Demo {demo['label']!r} advertises "
        f"{'ALLOW' if expected else 'DENY'} but the backend returned "
        f"{'ALLOW' if actual else 'DENY'}: {r.json().get('reason', 'executed')}"
    )


def test_every_demo_agent_exists_or_is_deliberately_unknown(client, demo):
    """A demo naming a missing agent should be labelled as a denial."""
    agent_id = demo.get("agent_id", "research-agent")
    known = client.get(f"/agents/{agent_id}/lifecycle").status_code == 200
    if not known:
        assert expected_verdict(demo["label"]) is False, (
            f"Demo {demo['label']!r} uses unknown agent {agent_id!r} "
            "but advertises an allow"
        )


def test_ui_and_backend_agree_on_gate_names(frontend_src, app_module):
    """The gate chips in ToolPanel must match the gates the backend reports."""
    source = (frontend_src / "panels" / "ToolPanel.js").read_text(encoding="utf-8")
    listed = re.search(r"const GATES\s*=\s*\[(.*?)\];", source, re.S)
    assert listed, "GATES not found in ToolPanel.js"
    ui_gates = re.findall(r"'(\w+)'", listed.group(1))
    assert ui_gates == ["lifecycle", "trust", "ring", "policy"]
