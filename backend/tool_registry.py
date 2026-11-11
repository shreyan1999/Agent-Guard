"""Real tool onboarding plus SSRF-guarded webhook invocation.

Tools are user-onboarded definitions the governance layer evaluates. A tool may
optionally carry an HTTP(S) endpoint; when a governed call is allowed the
endpoint is *really* invoked and its actual status and latency feed the SLO.
Nothing here fabricates a result: a tool with no endpoint is honestly reported
as a governance decision only, and a webhook that fails is reported as failed.

A tool is one of two kinds. A ``webhook`` tool is the plain case above. An
``mcp`` tool was imported from a Model Context Protocol server: the registry
stores where it came from and the risk evaluation of its descriptor, while the
invocation itself belongs to the MCP connector. Either kind is governed
identically — the four gates decide before anything is dispatched.

An MCP server is either remote (a URL, reached over one of the two HTTP
transports and held to the same SSRF standard as a webhook) or local (a command
this platform launches, spoken to over the child's stdin/stdout). A spec stores
one addressing form or the other, never both.

The invoker is SSRF-aware. It rejects non-HTTP schemes, refuses to call hosts
that resolve to private/loopback/link-local/reserved addresses unless
``allow_private`` is set (AGT_TOOL_ALLOW_PRIVATE, for local testing), never
follows redirects, and bounds both the response size and the time. The residual
gap is DNS rebinding between the pre-flight resolution and urllib's own
resolution; that is documented, not hidden.
"""

import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from state_store import MetaStore

_ALLOWED_SCHEMES = ("http", "https")
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_TIMEOUT_MS = 10_000
# Only for a local (stdio) MCP tool, whose call includes a process spawn.
_MAX_STDIO_TIMEOUT_MS = 60_000
_RISKS = ("low", "medium", "high", "critical")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_KINDS = ("webhook", "mcp")

# What a tool is *for*, independent of who supplied it. A category is coarse on
# purpose: it is meant to be written into a policy condition
# (`tool.category == "code_execution"`) and to stay stable as tools come and go,
# which a per-tool allowlist never does. Ordered most-consequential first, which
# is also the precedence the MCP connector derives one with.
TOOL_CATEGORIES = (
    "code_execution",
    "secrets",
    "finance",
    "filesystem",
    "data_write",
    "communication",
    "network",
    "search",
    "data_read",
    "uncategorised",
)
DEFAULT_CATEGORY = "uncategorised"

# An MCP tool may *name* the environment variable holding its bearer token, so
# the registry never stores the secret itself. Only this prefix is readable:
# without the restriction, onboarding a tool pointed at an attacker-controlled
# server and naming any process variable would be an exfiltration primitive.
MCP_AUTH_ENV_RE = re.compile(r"^AGT_MCP_[A-Z0-9_]{1,48}$")

# How an MCP server is spoken to. "http" is Streamable HTTP (the current
# transport); "sse" is the 2024-11-05 HTTP+SSE transport many deployed servers
# still speak; "stdio" is a local server this platform launches and talks to
# over the child's stdin/stdout; "auto" tries the two remote transports in that
# order. Only a resolved transport is ever stored — "auto" is a discovery-time
# choice, and it never resolves to stdio: falling back to executing something
# because a URL did not answer would not be a fallback.
MCP_TRANSPORTS = ("auto", "http", "sse", "stdio")
REMOTE_MCP_TRANSPORTS = ("http", "sse")

_MAX_STDIO_ARGS = 64
_MAX_STDIO_ARG_LEN = 4096


class ToolError(ValueError):
    """A tool definition or endpoint was rejected."""


def _is_blocked(ip: "ipaddress._BaseAddress") -> bool:
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def validate_endpoint(url: str, *, allow_private: bool = False,
                      resolve: bool = True) -> str:
    """Reject an endpoint that is unsafe to call, returning it if it is safe."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ToolError("Endpoint must use http or https")
    if not parsed.hostname:
        raise ToolError("Endpoint must include a host")
    if resolve:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(
                parsed.hostname, port, proto=socket.IPPROTO_TCP
            )
        except socket.gaierror as exc:
            raise ToolError(f"Cannot resolve endpoint host: {exc}")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not allow_private and _is_blocked(ip):
                raise ToolError(
                    f"Endpoint resolves to a blocked address ({ip}); set "
                    "AGT_TOOL_ALLOW_PRIVATE=1 to permit local targets"
                )
    return url


def _clean_stdio_launch(mcp: dict) -> dict:
    """Normalise how a local MCP server is launched, storing no secrets.

    Only the *names* of environment variables are kept, and only AGT_MCP_* ones,
    for the same reason a bearer token is never stored: the registry is written
    to disk and read back by anything that can read the state directory. The
    value is resolved from this process's environment at spawn time.
    """
    command = str(mcp.get("command") or "").strip()
    if not command:
        raise ToolError("A local (stdio) MCP tool needs mcp.command")

    args = []
    for arg in (mcp.get("args") or []):
        arg = str(arg)
        if len(arg) > _MAX_STDIO_ARG_LEN:
            raise ToolError("A stdio argument exceeded the length limit")
        args.append(arg)
    if len(args) > _MAX_STDIO_ARGS:
        raise ToolError(f"A stdio server takes at most {_MAX_STDIO_ARGS} arguments")

    cwd = str(mcp.get("cwd") or "").strip() or None
    if cwd and not os.path.isdir(cwd):
        raise ToolError(f"mcp.cwd is not a directory: {cwd}")

    env_names = []
    for name in (mcp.get("env_passthrough") or []):
        name = str(name).strip()
        if not MCP_AUTH_ENV_RE.match(name):
            raise ToolError(
                f"mcp.env_passthrough takes variable names matching "
                f"{MCP_AUTH_ENV_RE.pattern}; '{name}' does not")
        env_names.append(name)

    return {"server_url": None, "command": command, "args": args,
            "cwd": cwd, "env_passthrough": env_names}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: a 3xx could otherwise bypass the SSRF check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"Redirect blocked to {newurl}", headers, fp
        )


def invoke(url: str, payload: dict, *, timeout_ms: int = 3000,
           allow_private: bool = False) -> dict:
    """Really POST ``payload`` as JSON to ``url`` and report the true outcome.

    Re-validates the resolved address immediately before connecting, does not
    follow redirects, and bounds the response and time. Any transport failure is
    returned truthfully with ``ok=False`` — this never invents a success.
    """
    validate_endpoint(url, allow_private=allow_private, resolve=True)
    data = json.dumps(payload).encode("utf-8")
    timeout = min(max(int(timeout_ms), 1), _MAX_TIMEOUT_MS) / 1000.0
    request = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AgentGuard-ToolProbe/1.0",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    start = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as resp:
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            status = resp.status
    except urllib.error.HTTPError as exc:
        # A non-2xx (or a blocked redirect) still carries a real status code.
        raw = exc.read(_MAX_RESPONSE_BYTES + 1) if hasattr(exc, "read") else b""
        status = exc.code
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "endpoint": url,
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
        }
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    truncated = len(raw) > _MAX_RESPONSE_BYTES
    text = raw[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    return {
        "ok": 200 <= status < 300,
        "endpoint": url,
        "http_status": status,
        "latency_ms": latency_ms,
        "response": text,
        "truncated": truncated,
    }


# The auth methods AGT's McpAuthPolicy recognises, plus the two this platform
# adds for cases that policy is not asked about: a local server, which has no
# connection to authenticate, and a record that predates the field.
MCP_AUTH_METHODS = ("oauth2", "mtls", "api_key", "bearer", "none", "stdio",
                    "unknown")


def _clean_auth_method(value) -> str:
    """Normalise a recorded auth method, defaulting to an honest 'unknown'."""
    name = str(value or "").strip().lower()
    return name if name in MCP_AUTH_METHODS else "unknown"


class ToolRegistry:
    """A persisted set of onboarded tool definitions.

    Durable when constructed with a durable ``MetaStore`` (AGT_STATE_DIR set);
    in-memory otherwise, matching the ephemeral playground default. Definitions
    carry no secrets, so the same JSON-backed store used for agent metadata
    persists them.
    """

    def __init__(self, meta: MetaStore) -> None:
        self._meta = meta
        self._tools: dict[str, dict] = {}

    def load(self) -> None:
        loaded = self._meta.load()
        self._tools = {name: dict(spec) for name, spec in loaded.items()
                       if isinstance(spec, dict)}

    def _persist(self) -> None:
        self._meta.save(self._tools)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[dict]:
        return [dict(name=name, **spec)
                for name, spec in sorted(self._tools.items())]

    def get(self, name: str) -> "dict | None":
        return self._tools.get(name)

    def exists(self, name: str) -> bool:
        return name in self._tools

    def register(self, name: str, *, description: str = "",
                 actions: "list[str] | None" = None, risk: str = "medium",
                 endpoint_url: "str | None" = None, timeout_ms: int = 3000,
                 builtin: bool = False, created_by: "str | None" = None,
                 allow_private: bool = False, kind: str = "webhook",
                 mcp: "dict | None" = None,
                 evaluation: "dict | None" = None,
                 required_capabilities: "list[str] | None" = None,
                 category: str = DEFAULT_CATEGORY) -> dict:
        """Onboard (or update) one tool definition, validating every field."""
        name = (name or "").strip()
        if not _NAME_RE.match(name):
            raise ToolError(
                "Tool name must be 1-64 chars of letters, digits, '_', '.', '-'"
            )
        if risk not in _RISKS:
            raise ToolError(f"Risk must be one of {', '.join(_RISKS)}")
        if kind not in _KINDS:
            raise ToolError(f"Kind must be one of {', '.join(_KINDS)}")
        if category not in TOOL_CATEGORIES:
            raise ToolError(
                f"Category must be one of {', '.join(TOOL_CATEGORIES)}")
        clean_actions = [a.strip() for a in (actions or []) if a and a.strip()]
        try:
            timeout_ms = int(timeout_ms)
        except (TypeError, ValueError):
            raise ToolError("timeout_ms must be an integer")
        # A call to a local MCP server includes starting it, and a first
        # `npx`/`uvx` run may fetch the package before the server says anything.
        # The 10s ceiling is right for an HTTP request and would report a
        # working local server as a timeout, so that one case gets its own.
        ceiling = (_MAX_STDIO_TIMEOUT_MS
                   if kind == "mcp" and (mcp or {}).get("transport") == "stdio"
                   else _MAX_TIMEOUT_MS)
        if not 1 <= timeout_ms <= ceiling:
            raise ToolError(f"timeout_ms must be between 1 and {ceiling}")

        url = None
        if endpoint_url and endpoint_url.strip():
            url = validate_endpoint(
                endpoint_url.strip(), allow_private=allow_private, resolve=True
            )

        mcp_spec = self._clean_mcp(mcp, allow_private=allow_private) \
            if kind == "mcp" else None

        existing = self._tools.get(name, {})
        spec = {
            "description": description.strip(),
            "actions": clean_actions,
            "risk": risk,
            "category": category,
            "endpoint_url": url,
            "timeout_ms": timeout_ms,
            "builtin": bool(builtin) or bool(existing.get("builtin")),
            "created_by": created_by or existing.get("created_by"),
            "kind": kind,
            "mcp": mcp_spec,
            # The descriptor evaluation that justified onboarding, kept with the
            # definition so the decision stays auditable after the fact.
            "evaluation": evaluation if isinstance(evaluation, dict) else None,
            # Capabilities the calling agent must hold. Enforced at dispatch by
            # AGT's trust proxy; empty (the default) gates nothing.
            "required_capabilities": [
                c.strip() for c in (required_capabilities or []) if c and c.strip()
            ],
            # Set when a re-verification finds the server changed this tool's
            # descriptor after import (a rug pull). A fresh import clears it:
            # re-importing *is* the operator approving the new descriptor.
            "quarantined": False,
        }
        self._tools[name] = spec
        self._persist()
        return dict(name=name, **spec)

    @staticmethod
    def _clean_mcp(mcp: "dict | None", *, allow_private: bool) -> dict:
        """Validate the routing metadata of a tool imported from an MCP server.

        A remote tool is addressed by URL and guarded by the SSRF check; a local
        one is addressed by the command that launches it, and the guard for that
        is AGT's — its command allowlist and environment validation run inside
        its client when the child is actually started. Deciding here as well
        would mean keeping a second copy of a policy that is not this project's
        to set. What this does enforce is the shape: exactly one of the two
        addressing forms is stored, so a spec can never be ambiguous about
        whether dispatching it dials out or starts a process.
        """
        mcp = mcp or {}
        remote_tool = str(mcp.get("remote_tool") or "").strip()
        if not remote_tool:
            raise ToolError("An MCP tool needs mcp.remote_tool")
        auth_env = str(mcp.get("auth_env") or "").strip()
        if auth_env and not MCP_AUTH_ENV_RE.match(auth_env):
            raise ToolError(
                f"mcp.auth_env must match {MCP_AUTH_ENV_RE.pattern} — only "
                "AGT_MCP_* variables are readable")
        transport = str(mcp.get("transport") or "http").strip()
        if transport not in MCP_TRANSPORTS or transport == "auto":
            raise ToolError(
                "mcp.transport must be a resolved transport: "
                + ", ".join(t for t in MCP_TRANSPORTS if t != "auto"))
        cleaned = {
            "server": str(mcp.get("server") or "").strip(),
            "remote_tool": remote_tool,
            "transport": transport,
            "auth_env": auth_env or None,
            "protocol_version": str(mcp.get("protocol_version") or "").strip() or None,
            # How the connection that discovered this tool was authenticated,
            # and how a dispatch of it will be. Kept separately because they
            # genuinely differ: discovery may carry a one-off token the caller
            # typed, while a dispatch reads auth_env, so a tool imported over an
            # authenticated connection can still dispatch unauthenticated.
            # Recorded rather than enforced here — AGT's McpAuthPolicy already
            # decided, in mcp_admission, before the connection was opened.
            "auth_method": _clean_auth_method(mcp.get("auth_method")),
            "dispatch_auth_method": _clean_auth_method(
                mcp.get("dispatch_auth_method")),
            # What AGT's descriptor scan found at import. Persisted because it
            # may have escalated the risk tier, and a tier whose reason is not
            # recorded is one nobody can review later.
            "security_scan": [dict(f) for f in (mcp.get("security_scan") or [])
                              if isinstance(f, dict)],
        }
        if transport == "stdio":
            cleaned.update(_clean_stdio_launch(mcp))
        else:
            server_url = str(mcp.get("server_url") or "").strip()
            if not server_url:
                raise ToolError("A remote MCP tool needs mcp.server_url")
            cleaned.update({
                "server_url": validate_endpoint(
                    server_url, allow_private=allow_private, resolve=True),
                "command": None, "args": [], "cwd": None,
                "env_passthrough": [],
            })
        # The import-time descriptor is the baseline a rug-pull check
        # fingerprints against; persist it so it survives a restart.
        descriptor = mcp.get("descriptor")
        if isinstance(descriptor, dict):
            cleaned["descriptor"] = {
                "description": str(descriptor.get("description") or ""),
                "input_schema": descriptor.get("input_schema"),
                # The server's own claims about the tool — readOnlyHint,
                # destructiveHint, idempotentHint. They are assertions rather
                # than evidence, which is exactly why they are kept beside the
                # text that can contradict them: the reversibility grade reads
                # both and only trusts the claim when the wording agrees.
                "annotations": descriptor.get("annotations")
                if isinstance(descriptor.get("annotations"), dict) else {},
            }
        return cleaned

    def quarantine(self, name: str, flag: bool = True) -> bool:
        """Mark (or clear) a tool as refused at dispatch. Returns True if changed."""
        spec = self._tools.get(name)
        if spec is None or bool(spec.get("quarantined")) == bool(flag):
            return False
        spec["quarantined"] = bool(flag)
        self._persist()
        return True

    def remove(self, name: str) -> bool:
        if self._tools.pop(name, None) is not None:
            self._persist()
            return True
        return False

    def by_mcp_server(self, server: str) -> list[str]:
        """Names of every tool imported from one MCP server."""
        return sorted(
            name for name, spec in self._tools.items()
            if spec.get("kind") == "mcp"
            and (spec.get("mcp") or {}).get("server") == server
        )

    def clear(self) -> None:
        self._tools.clear()
