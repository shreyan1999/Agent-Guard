"""AGT's own MCP scanners, for the two things the connector never looked at.

``mcp_connector`` grades a tool *descriptor* at import, and ``mcp_gate`` scans
the *arguments* at dispatch. Two blind spots remained, and AGT already ships a
scanner for each:

* **Rug pull** — a server that changes a descriptor *after* it was imported.
  The import-time grade is a point-in-time snapshot, and nothing re-checked it.
  ``agent_os.mcp_security.MCPSecurityScanner`` fingerprints a tool's description
  and schema at registration and reports a ``RUG_PULL`` threat when either
  changes. A tool caught this way is *quarantined*, not merely reported: the
  dispatch gate refuses it until an operator re-imports it deliberately.

* **Response content** — everything governed so far flows outward. The bytes
  coming *back* from a third-party server reach the model verbatim, and a
  response is as good a place to hide "ignore your instructions" as a
  descriptor. ``agent_os.mcp_response_scanner.MCPResponseScanner`` checks tool
  output for instruction injection, credential leaks, PII and exfiltration URLs.

Both scanners are AGT's, not this project's. Where they overlap with the
connector's own descriptor evaluation they are *additive*: the connector's
grader catches the canonical tool-poisoning payload that AGT's ``scan_tool``
misses, so neither replaces the other and both are kept.

A withheld response is honest about what already happened: the remote call ran,
its side effects are real, and only the content is quarantined. Nothing here
claims a call was prevented after the fact.
"""

from __future__ import annotations

import json
import threading
import warnings

from agent_os.mcp_response_scanner import MCPResponseScanner
from agent_os.mcp_security import MCPSecurityScanner, MCPSeverity, MCPThreatType

import mcp_security_config


def descriptor_of(spec: dict) -> dict:
    """The description and schema a rug-pull check fingerprints.

    Stored on the registry entry at import so the fingerprint survives a
    restart — ``MCPSecurityScanner`` keeps its registry in memory only.
    """
    mcp = spec.get("mcp") or {}
    d = mcp.get("descriptor") or {}
    return {
        "description": str(d.get("description") or ""),
        "input_schema": d.get("input_schema"),
    }


# AGT's severities are a three-value scale; the registry's risk tiers are four.
# `warning` maps to `high` rather than `medium` because every WARNING this
# scanner emits is a named attack shape — typosquatting, an encoded payload —
# not a stylistic complaint, and rounding those down would be the more
# consequential mistake.
_SEVERITY_TO_RISK = {
    MCPSeverity.CRITICAL: "critical",
    MCPSeverity.WARNING: "high",
    MCPSeverity.INFO: "low",
}


class DescriptorMonitor:
    """Fingerprints imported MCP descriptors, and runs AGT's own scan over them.

    Two jobs, sharing one scanner because AGT's rug-pull registry lives on it.

    The fingerprints answer *did this descriptor change after we approved it*.
    The scan answers *is this descriptor hostile on its face* — and it is the
    part the rule files in ``config/`` govern, because ``MCPSecurityConfig``
    patterns are only ever consulted by ``scan_tool``. ``register_tool`` and
    ``check_rug_pull`` never touch them, so loading a config without also
    calling ``scan_tool`` would be configuration that changes nothing.

    What the scan adds over the connector's own 21 checks is mostly
    cross-server: a tool whose name is already registered by a *different*
    server (impersonation), or within two edits of one (typosquatting). The
    connector grades each descriptor alone and has no view across servers, so
    that class of attack was invisible to it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules = mcp_security_config.RuleSet()
        self._scanner = self._build()

    def _build(self) -> MCPSecurityScanner:
        """A scanner running the configured rules rather than the built-in ones.

        The injection detector is assigned after construction because
        ``MCPSecurityScanner.__init__`` accepts ``config=`` but builds its
        ``PromptInjectionDetector()`` with no arguments and exposes no parameter
        for one. Reaching the nested detector is the only way to configure the
        second half of the rule set, and without it AGT's second warning — that
        those rules may not cover every technique — stays true.
        """
        with warnings.catch_warnings():
            # AGT emits its "built-in sample rules" warning from inside
            # PromptInjectionDetector.__init__, which the scanner's constructor
            # calls before this code can hand it anything. The default detector
            # it builds is discarded on the next line and never scans, so the
            # warning describes an object that does not survive the call.
            # Suppressed narrowly by message, and only around this construction.
            warnings.filterwarnings(
                "ignore", message=r".*uses built-in sample rules.*",
                category=UserWarning)
            scanner = MCPSecurityScanner(config=self._rules.mcp)
        scanner._injection_detector = self._rules.injection_detector()
        return scanner

    def reload_rules(self) -> dict:
        """Re-read the rule files and rebuild the scanner around them.

        The fingerprint registry is deliberately *not* carried over: it is
        rebuilt by ``reseed`` from the persisted descriptors, which is the same
        path a restart takes, so a reload cannot leave baselines that no longer
        match what is on disk.
        """
        with self._lock:
            status = self._rules.reload()
            self._scanner = self._build()
        return status

    def rules(self) -> dict:
        return self._rules.describe()

    def scan(self, server: str, remote_tool: str, description: str,
             input_schema: "dict | None") -> list:
        """Run AGT's descriptor scan, and report what it found.

        RUG_PULL is filtered out. ``scan_tool`` calls ``check_rug_pull``
        internally, but a rug pull is owned by ``/mcp/servers/{s}/verify``,
        which quarantines the tool. Reporting the same finding from two places
        with two different consequences would make an operator guess which one
        acted.
        """
        with self._lock:
            threats = self._scanner.scan_tool(
                remote_tool, description or "", input_schema,
                server or "unknown")
        return [
            {
                "threat": t.threat_type.name,
                "severity": t.severity.name,
                "risk": _SEVERITY_TO_RISK.get(t.severity, "medium"),
                "message": t.message,
                "detail": dict(getattr(t, "details", None) or {}),
            }
            for t in threats if t.threat_type is not MCPThreatType.RUG_PULL
        ]

    def register(self, server: str, remote_tool: str, description: str,
                 input_schema: "dict | None") -> None:
        """Record the descriptor a tool was imported with."""
        with self._lock:
            self._scanner.register_tool(remote_tool, description or "",
                                        input_schema, server or "unknown")

    def reseed(self, tools: list) -> int:
        """Re-register every persisted MCP tool after a restart.

        The scanner's fingerprint registry is in-memory, so without this a
        restart would silently forget every baseline and no rug pull could ever
        be detected again — the failure mode being defended against.
        """
        seeded = 0
        for spec in tools:
            if spec.get("kind") != "mcp":
                continue
            mcp = spec.get("mcp") or {}
            desc = descriptor_of(spec)
            if not mcp.get("remote_tool"):
                continue
            self.register(mcp.get("server") or "unknown", mcp["remote_tool"],
                          desc["description"], desc["input_schema"])
            seeded += 1
        return seeded

    def check(self, server: str, remote_tool: str, description: str,
              input_schema: "dict | None") -> "dict | None":
        """Compare a freshly discovered descriptor against its baseline."""
        with self._lock:
            threat = self._scanner.check_rug_pull(
                remote_tool, description or "", input_schema, server or "unknown")
        if threat is None:
            return None
        details = getattr(threat, "details", None) or {}
        return {
            "threat": getattr(threat.threat_type, "name", str(threat.threat_type)),
            "severity": getattr(threat.severity, "name", str(threat.severity)),
            "message": threat.message,
            "changed_fields": list(details.get("changed_fields") or []),
            "version": details.get("version"),
        }

    def forget(self, server: str, remote_tool: str) -> None:
        """Drop a baseline when its tool is withdrawn."""
        with self._lock:
            self._scanner._tool_registry.pop(f"{server}::{remote_tool}", None)

    def clear(self) -> None:
        with self._lock:
            self._scanner = self._build()


# ── Response scanning ────────────────────────────────────────────────────────

def _response_text(outcome: dict) -> str:
    """Flatten a tool result into the text a model would actually read.

    Two shapes, because two kinds of tool answer. An MCP result carries
    ``content`` blocks and ``structured_content``; a webhook result carries the
    response body as ``response``. Reading only the first was how a webhook
    response came back from this scanner marked "scanned, safe" having had
    nothing read at all — a quieter failure than not scanning it, because it
    claimed the opposite.
    """
    parts = []
    for block in outcome.get("content") or []:
        if isinstance(block, dict):
            parts.append(str(block.get("text") or ""))
        else:
            parts.append(str(block))
    structured = outcome.get("structured_content")
    if structured is not None:
        try:
            parts.append(json.dumps(structured, ensure_ascii=False))
        except (TypeError, ValueError):
            parts.append(str(structured))
    # A webhook's body. Whatever the endpoint returned reaches the model the
    # same way an MCP content block does, so it is held to the same standard.
    body = outcome.get("response")
    if isinstance(body, str) and body:
        parts.append(body)
    return "\n".join(p for p in parts if p)


class ResponseGuard:
    """Scans what a tool sends back, before it reaches the model.

    Named for MCP because that is where the risk was first taken seriously,
    but the scanner is AGT's ``MCPResponseScanner`` and the risk is the
    transport's, not the protocol's: bytes returned by an HTTP endpoint reach
    the model exactly as an MCP content block does, and can carry exactly the
    same "ignore your instructions" payload.
    """

    def __init__(self) -> None:
        self._scanner = MCPResponseScanner()

    def inspect(self, tool_name: str, outcome: dict) -> dict:
        """Return a serialisable verdict for one tool response.

        ``MCPResponseScanner`` is stateless and fails closed on its own errors,
        so it needs no lock and an internal failure reports unsafe rather than
        waving the content through.
        """
        text = _response_text(outcome)
        if not text:
            return {"scanned": True, "safe": True, "threats": []}
        result = self._scanner.scan_response(text, tool_name)
        return {
            "scanned": True,
            "safe": bool(result.is_safe),
            "threats": [
                {"category": t.category, "description": t.description,
                 "matched": t.matched_pattern}
                for t in (result.threats or [])
            ],
        }
