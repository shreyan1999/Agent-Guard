"""Real tool onboarding plus SSRF-guarded webhook invocation.

Tools are user-onboarded definitions the governance layer evaluates. A tool may
optionally carry an HTTP(S) endpoint; when a governed call is allowed the
endpoint is *really* invoked and its actual status and latency feed the SLO.
Nothing here fabricates a result: a tool with no endpoint is honestly reported
as a governance decision only, and a webhook that fails is reported as failed.

The invoker is SSRF-aware. It rejects non-HTTP schemes, refuses to call hosts
that resolve to private/loopback/link-local/reserved addresses unless
``allow_private`` is set (AGT_TOOL_ALLOW_PRIVATE, for local testing), never
follows redirects, and bounds both the response size and the time. The residual
gap is DNS rebinding between the pre-flight resolution and urllib's own
resolution; that is documented, not hidden.
"""

import ipaddress
import json
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
_RISKS = ("low", "medium", "high", "critical")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


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
            "User-Agent": "AGT-Dashboard-ToolProbe/1.0",
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
                 allow_private: bool = False) -> dict:
        """Onboard (or update) one tool definition, validating every field."""
        name = (name or "").strip()
        if not _NAME_RE.match(name):
            raise ToolError(
                "Tool name must be 1-64 chars of letters, digits, '_', '.', '-'"
            )
        if risk not in _RISKS:
            raise ToolError(f"Risk must be one of {', '.join(_RISKS)}")
        clean_actions = [a.strip() for a in (actions or []) if a and a.strip()]
        try:
            timeout_ms = int(timeout_ms)
        except (TypeError, ValueError):
            raise ToolError("timeout_ms must be an integer")
        if not 1 <= timeout_ms <= _MAX_TIMEOUT_MS:
            raise ToolError(f"timeout_ms must be between 1 and {_MAX_TIMEOUT_MS}")

        url = None
        if endpoint_url and endpoint_url.strip():
            url = validate_endpoint(
                endpoint_url.strip(), allow_private=allow_private, resolve=True
            )

        existing = self._tools.get(name, {})
        spec = {
            "description": description.strip(),
            "actions": clean_actions,
            "risk": risk,
            "endpoint_url": url,
            "timeout_ms": timeout_ms,
            "builtin": bool(builtin) or bool(existing.get("builtin")),
            "created_by": created_by or existing.get("created_by"),
        }
        self._tools[name] = spec
        self._persist()
        return dict(name=name, **spec)

    def remove(self, name: str) -> bool:
        if self._tools.pop(name, None) is not None:
            self._persist()
            return True
        return False

    def clear(self) -> None:
        self._tools.clear()
