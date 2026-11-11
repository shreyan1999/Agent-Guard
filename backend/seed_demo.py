"""Populate a running AgentGuard instance with realistic governance activity.

A freshly started instance has four demo agents, four built-in tools and an
empty audit chain, so every panel that reads from the chain is honestly blank:
no decisions, no alerts, no SLO measurements, no traces. That is correct, and
it is also useless for testing the UI or demoing the product. This script
fills it in.

**It fabricates nothing.** Every row it produces comes from a real request to
the real API: agents are registered through `POST /agents`, calls go through
`POST /tools/call` and are decided by the actual five gates, alerts are raised
by AGT's own AlertManager because a call was really denied, and SLO
measurements come from calls that really ran. There is no path here that writes
to the audit chain directly — which is the point, because a seeder that injected
entries would be forging exactly the evidence the chain exists to be.

Two consequences worth knowing:

  * The calls below are chosen so that **every gate denies at least once** —
    lifecycle (unregistered, and suspended), trust, ring and policy — because a
    dashboard that only ever shows allows tells you nothing about the gates.
  * Nothing is tagged synthetic, because nothing here *is* synthetic. The
    platform reserves that label for measurements typed in from the SRE panel's
    demo buttons (`POST /sre/signal`), and this script deliberately does not use
    that endpoint: real calls produce real measurements.

Usage
-----
    python seed_demo.py                         # against http://127.0.0.1:8000
    python seed_demo.py --url http://host:8000
    python seed_demo.py --token s3cret-root     # when AGT_API_KEYS is set
    python seed_demo.py --reset                 # start a fresh audit chain first

Re-running is safe and produces the same scenario each time: agents that already
exist are reused rather than duplicated, and any of them left suspended by a
previous run is resumed before the traffic starts. Without that second step a
re-run quietly loses coverage -- a suspended agent's calls stop at the lifecycle
gate, so the ring denials it was there to produce never happen.

One thing a re-run cannot reproduce: the private key of an agent is issued once,
at registration, so a later run does not hold it and its calls go unattested.
That is reported rather than hidden.

State is in-memory unless AGT_STATE_DIR is set, so a backend restart clears
everything this created.
"""

from __future__ import annotations

import argparse
import sys
import time

from agt_client import GovernanceClient, GovernanceError

BASE_DEFAULT = "http://127.0.0.1:8000"

# The scenario itself lives in demo_seed, because `POST /demo/seed` runs the
# same one in-process for the dashboard's button. One definition, so the
# terminal and the UI cannot seed different fleets.
from demo_seed import (
    CHILD_POLICY, MCP_CALLS, MCP_SERVER_NAME, MCP_SERVER_URL, PLAYGROUND_AGENTS,
    SEED_AGENTS, SEED_CALLS, SEED_TELEMETRY, SEEDED_AGENT_IDS,
)


class Seeder:
    def __init__(self, base: str, token: str | None) -> None:
        self.base = base.rstrip("/")
        self.token = token
        self.admin = GovernanceClient(base_url=self.base, token=token)
        self.clients: dict[str, GovernanceClient] = {}
        self.notes: list[str] = []
        # Signing a challenge needs `agentmesh.identity` -- the toolkit itself,
        # not just the SDK. This script is meant to be runnable from anywhere
        # that can reach the API, including a machine with nothing but a stock
        # Python, so it checks once and falls back to unattested calls rather
        # than failing outright. Attestation is optional on the platform by
        # default; the calls are still real decisions, they are just flagged
        # `identity_verified: false`.
        try:
            import agentmesh.identity  # noqa: F401
            self.can_attest = True
        except ImportError:
            self.can_attest = False

    # -- helpers ---------------------------------------------------------
    def _get(self, path: str):
        return self.admin._call("GET", path)

    def _post(self, path: str, payload=None):
        return self.admin._call("POST", path, payload)

    def note(self, line: str) -> None:
        self.notes.append(line)
        print(f"  {line}")

    # -- steps -----------------------------------------------------------
    def check_reachable(self) -> None:
        health = self._get("/health")
        if health.get("status") != "ok":
            raise SystemExit(f"{self.base} did not report healthy: {health}")
        mode = ("attested -- the toolkit is importable here" if self.can_attest else
                "unattested -- agent-governance-toolkit is not importable here, so "
                "calls carry identity_verified: false")
        print(f"connected to {self.base}")
        print(f"signing: {mode}\n")

    def reset_chain(self) -> None:
        before = self.admin._call("DELETE", "/audit")
        self.note(f"audit chain reset (replaced root "
                  f"{(before.get('previous_merkle_root') or '')[:12]}...)")

    def register_playground(self) -> None:
        """Register the Tool Playground's own agents when the platform has not.

        Memory-only mode seeds them at startup; under AGT_STATE_DIR it
        deliberately does not, which would leave the playground's preset buttons
        calling as agents that do not exist.
        """
        existing = {a["id"] for a in self._get("/agents")}
        missing = [a for a in PLAYGROUND_AGENTS if a[0] not in existing]
        if not missing:
            return
        print("playground agents")
        for agent_id, trust, owner, purpose in missing:
            client = GovernanceClient(base_url=self.base, token=self.token,
                                      agent_id=agent_id)
            try:
                client.register(agent_id=agent_id, trust_score=trust,
                                owner=owner, purpose=purpose)
                self.note(f"{agent_id:<16} registered  trust={trust}")
            except GovernanceError as exc:
                self.note(f"{agent_id:<16} NOT registered: {exc}")
        print()

    def register_agents(self) -> None:
        print("agents")
        existing = {a["id"] for a in self._get("/agents")}
        for agent_id, trust, owner, purpose in SEED_AGENTS:
            client = GovernanceClient(base_url=self.base, token=self.token,
                                      agent_id=agent_id)
            if agent_id in existing:
                # Re-run: the agent is there, but its private key was issued
                # once and we do not have it, so its calls go unattested.
                self.note(f"{agent_id:<14} already registered (calls will be unattested)")
            else:
                try:
                    client.register(agent_id=agent_id, trust_score=trust,
                                    owner=owner, purpose=purpose)
                    self.note(f"{agent_id:<14} registered  trust={trust}  did={client.did[:22]}...")
                except GovernanceError as exc:
                    self.note(f"{agent_id:<14} NOT registered: {exc}")
                    continue
            self.clients[agent_id] = client
        print()

    def ensure_active(self) -> None:
        """Resume any seeded agent a previous run left suspended.

        Without this the script is not reproducible: the lifecycle gate runs
        first, so a still-suspended agent stops there and the ring denials it
        exists to produce never happen -- the run looks fine while quietly
        covering one gate fewer.
        """
        seeded = {a[0] for a in SEED_AGENTS}
        stuck = [a for a in self._get("/agents")
                 if a["id"] in seeded and a["state"] != "active"]
        if not stuck:
            return
        print("lifecycle reset")
        for agent in stuck:
            try:
                self._post(f"/sre/resume/{agent['id']}")
                self.note(f"{agent['id']:<14} {agent['state']} -> active "
                          f"(left over from an earlier run)")
            except GovernanceError as exc:
                self.note(f"{agent['id']:<14} could not resume: {exc}")
        print()

    def create_policy(self) -> None:
        print("policies")
        names = {p["name"] for p in self._get("/policies")}
        if CHILD_POLICY["name"] in names:
            self.note(f"{CHILD_POLICY['name']} already exists")
        else:
            try:
                self._post("/policies", CHILD_POLICY)
                self.note(f"{CHILD_POLICY['name']} created, extends default-policy")
            except GovernanceError as exc:
                self.note(f"{CHILD_POLICY['name']} NOT created: {exc}")
        print()

    def fire_calls(self) -> dict:
        print("governed calls")
        tally = {"allow": 0, "deny": 0, "surprise": 0}
        by_gate: dict[str, int] = {}

        for agent_id, tool, action, text, policy, expect, why in SEED_CALLS:
            client = self.clients.get(agent_id) or GovernanceClient(
                base_url=self.base, token=self.token, agent_id=agent_id)
            try:
                result = client.authorize(tool, action=action, input_text=text,
                                          policy_name=policy,
                                          attest=self.can_attest)
            except GovernanceError as exc:
                self.note(f"{agent_id:<14} {action:<11} ERROR {exc}")
                continue

            allowed = bool(result.get("allowed"))
            got = "allow" if allowed else "deny"
            gate = result.get("denied_by") or "-"
            rule = result.get("rule") or "-"
            if not allowed:
                by_gate[gate] = by_gate.get(gate, 0) + 1
            tally[got] += 1

            # The check that keeps this honest: if the platform disagreed with
            # what this script advertised, say so loudly instead of filing the
            # row away as if it matched.
            flag = ""
            if got != expect:
                tally["surprise"] += 1
                flag = f"   <-- expected {expect} ({why})"
            print(f"  {agent_id:<14} {action:<11} -> {got:<5} "
                  f"gate={gate:<10} rule={rule}{flag}")
        print()
        return {"tally": tally, "by_gate": by_gate}

    def attested_call(self) -> None:
        """One call that proves key possession, so identity_verified is not all false."""
        print("attestation")
        client = self.clients.get("billing-agent")
        if not self.can_attest:
            self.note("skipped -- signing needs agent-governance-toolkit on this machine")
            print()
            return
        if client is None or client._private_jwk is None:
            self.note("skipped -- billing-agent's private key is not held by this run")
            print()
            return
        result = client.authorize("db_query", action="read", attest=True,
                                  input_text="SELECT 1", policy_name="finance-policy")
        self.note(f"billing-agent identity_verified={result.get('identity_verified')}")
        print()

    def import_mcp(self) -> bool:
        """Onboard the demo MCP server's tools, if one is listening.

        Optional on purpose: a seeder cannot conjure a server on another port.
        When it is not reachable this says why rather than failing, because a
        silent skip would leave the receipts panel empty and the fifth gate
        unexercised with nothing explaining it.
        """
        print("mcp import")
        try:
            body = self._post("/mcp/import",
                              {"server_url": MCP_SERVER_URL, "transport": "auto"})
        except GovernanceError as exc:
            detail = str(exc)
            hint = ""
            if "blocked address" in detail or "AGT_TOOL_ALLOW_PRIVATE" in detail:
                hint = ("  The SSRF guard refuses loopback by default; set "
                        "AGT_TOOL_ALLOW_PRIVATE=1 on the backend.")
            self.note(f"skipped -- nothing importable at {MCP_SERVER_URL}.")
            self.note(f"  run `python demo_mcp_server.py` to enable this half.{hint}")
            print()
            return False
        names = [t["name"] for t in body.get("imported", [])]
        for tool in body.get("imported", []):
            policy = tool.get("runtime_policy") or {}
            self.note(f"{tool['name']:<30} risk={tool['risk']:<9} "
                      f"min_trust={policy.get('min_trust')} "
                      f"blocked={policy.get('blocked')}")
        print()
        return bool(names)

    def fire_mcp_calls(self) -> dict:
        """Calls that reach the fifth gate -- AGT's MCP trust proxy.

        Every one of these earns a signed receipt whichever way it is decided,
        which is what fills the receipts panel.
        """
        print("mcp calls")
        by_gate: dict = {}
        surprises = 0
        for agent_id, tool, arguments, expect, why in MCP_CALLS:
            client = self.clients.get(agent_id) or GovernanceClient(
                base_url=self.base, token=self.token, agent_id=agent_id)
            try:
                result = client.authorize(tool, action="invoke",
                                          attest=self.can_attest,
                                          arguments=arguments)
            except GovernanceError as exc:
                self.note(f"{agent_id:<14} {tool:<30} ERROR {exc}")
                continue
            allowed = bool(result.get("allowed"))
            got = "allow" if allowed else "deny"
            gate = result.get("denied_by") or "-"
            if not allowed:
                by_gate[gate] = by_gate.get(gate, 0) + 1
            flag = ""
            if got != expect:
                surprises += 1
                flag = f"   <-- expected {expect} ({why})"
            receipt = "yes" if result.get("receipt") else "no"
            print(f"  {agent_id:<14} {tool.split('.')[-1]:<14} -> {got:<5} "
                  f"gate={gate:<10} receipt={receipt}{flag}")
        print()
        return {"by_gate": by_gate, "surprises": surprises}

    def send_telemetry(self) -> None:
        print("out-of-band telemetry (/ingest/events)")
        for agent_id, events in SEED_TELEMETRY:
            client = self.clients.get(agent_id)
            if client is None:
                continue
            try:
                body = client.report(events)
                self.note(f"{agent_id:<14} accepted={body['accepted']} "
                          f"denied_reported={body['denied_reported']} "
                          f"avg_latency={body['avg_latency_ms']}ms")
            except GovernanceError as exc:
                self.note(f"{agent_id:<14} NOT accepted: {exc}")
        print()

    def engage_kill_switch(self) -> None:
        """Suspend one agent, then call as it -- the lifecycle gate's other half."""
        print("kill switch")
        target = "scraper-agent"
        try:
            state = self._post(f"/sre/kill/{target}")
            self.note(f"{target} suspended (state={state.get('status')})")
        except GovernanceError as exc:
            self.note(f"{target} NOT suspended: {exc}")
            print()
            return
        client = self.clients.get(target) or GovernanceClient(
            base_url=self.base, token=self.token, agent_id=target)
        result = client.authorize("db_query", action="read",
                                  attest=self.can_attest)
        self.note(f"call as {target} -> allowed={result.get('allowed')} "
                  f"gate={result.get('denied_by')} rule={result.get('rule')}")
        print()

    def summary(self, call_stats: dict) -> None:
        """Report what the platform actually holds, not what this script sent."""
        stats = self._get("/stats")
        alerts = self._get("/sre/alerts?limit=50")
        slos = self._get("/sre/slos")
        measured = [s for s in slos
                    if any((i.get("measurement_count") or 0) > 0
                           for i in (s.get("indicators") or []))]

        print("-" * 62)
        print("what the instance now holds (read back from the API)\n")
        print(f"  agents registered      {stats['total_agents']}")
        print(f"  active                 {stats['lifecycle']['by_state'].get('active', 0)}")
        print(f"  suspended              {stats['lifecycle']['by_state'].get('suspended', 0)}")
        print(f"  policies               {stats['total_policies']}")
        print(f"  audit entries          {stats['audit_events']}")
        print(f"  denials in chain       {stats['denials']}")
        print(f"  alerts raised          {len(alerts.get('alerts', []))}"
              f"  (suppressed {alerts.get('stats', {}).get('suppressed', 0)})")
        print(f"  SLOs with measurements {len(measured)} of {len(slos)}")
        print(f"  chain valid            {stats['chain_valid']}")

        receipts = self._get("/mcp/receipts")
        traces = self._get("/traces")
        print(f"  signed receipts        {receipts['total']}")
        print(f"  decision traces        "
              + (f"{len(traces['traces'])}" if traces["enabled"]
                 else "off (set AGT_STATE_DIR to capture them)"))

        gates = call_stats["by_gate"]
        print(f"\n  denials by gate        "
              + (", ".join(f"{g}={n}" for g, n in sorted(gates.items())) or "none"))

        # mcp_proxy is only expected when the MCP half actually ran.
        expected = {"lifecycle", "trust", "ring", "policy"}
        if "mcp_proxy" in gates:
            expected.add("mcp_proxy")
        missing = expected - set(gates)
        if missing:
            print(f"  !! no denial recorded at: {', '.join(sorted(missing))}")
        else:
            print("  every gate denied at least once")

        if call_stats["tally"]["surprise"]:
            print(f"\n  !! {call_stats['tally']['surprise']} call(s) did not match "
                  f"what this script advertised -- see the rows marked above.")
        print("-" * 62)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fill a running AgentGuard instance with real governance activity.")
    parser.add_argument("--url", default=BASE_DEFAULT,
                        help=f"instance base URL (default {BASE_DEFAULT})")
    parser.add_argument("--token", default=None,
                        help="bearer token, when the instance has AGT_API_KEYS set")
    parser.add_argument("--reset", action="store_true",
                        help="start a fresh audit chain before seeding (admin only)")
    args = parser.parse_args()

    # Text echoed back from the API can hold characters the console cannot
    # encode -- a lifecycle error reads "suspended -> suspended" with a real
    # arrow, and on a cp1252 Windows console that raised UnicodeEncodeError
    # mid-run. Keep the console's own encoding (so nothing turns to mojibake)
    # and let it substitute what it cannot represent.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - old/odd streams
            pass

    seeder = Seeder(args.url, args.token)
    try:
        seeder.check_reachable()
    except Exception as exc:
        print(f"could not reach {args.url}: {exc}", file=sys.stderr)
        print("is the backend running? (uvicorn main:app --port 8000)", file=sys.stderr)
        return 1

    if args.reset:
        print("reset")
        seeder.reset_chain()
        print()

    seeder.register_playground()
    seeder.register_agents()
    seeder.ensure_active()
    seeder.create_policy()
    stats = seeder.fire_calls()
    if seeder.import_mcp():
        mcp = seeder.fire_mcp_calls()
        for gate, count in mcp["by_gate"].items():
            stats["by_gate"][gate] = stats["by_gate"].get(gate, 0) + count
        stats["tally"]["surprise"] += mcp["surprises"]
    seeder.attested_call()
    seeder.send_telemetry()
    seeder.engage_kill_switch()
    time.sleep(0.2)          # let the alert hub drain before it is read back
    seeder.summary(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
