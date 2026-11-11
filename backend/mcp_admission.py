"""Whether AgentGuard may open a connection to an MCP server at all.

Everything else in this package governs a *call*. These two AGT controls govern
the *connection*, and they run earlier — before discovery reads a single
descriptor, because by then the platform has already trusted the server enough
to talk to it.

* **Auth method** — ``agent_os.mcp_auth_enforcement.McpAuthPolicy``. AgentGuard
  connected to whatever URL an operator typed, over whatever scheme, with or
  without a token. The SSRF guard checked *where* the address pointed; nothing
  checked *how* the connection was authenticated. A public MCP server reached
  over plain HTTP with no credential is an open door to a tool catalogue the
  model is told to obey.

* **Known vulnerabilities** — ``agent_os.mcp_cve_feed.McpCveFeed``. A local
  (stdio) server is launched from a package specification the operator gave us:
  ``npx -y @modelcontextprotocol/server-filesystem@1.2.0``. That names a package
  and a version, which is what a CVE database is keyed on. The descriptor grade
  says whether the *tool text* is hostile; it says nothing about whether the
  *implementation* has a published CVE.

Two deliberate exemptions in the auth policy, both narrower than they look.

``stdio`` has no network connection to authenticate. Its security boundary is
the child process, and AGT already enforces that with the command allowlist and
the sanitised child environment in ``agent_os.cli.mcp_scan``. Demanding
``oauth2`` of a subprocess would be a check that cannot fail, which is worse
than no check because it still appears in a report.

A **loopback or private** address is exempt because reaching one at all already
requires the operator to have set ``AGT_TOOL_ALLOW_PRIVATE``. That unlock is the
decision; asking twice adds no safety and would make the shipped demo — a
loopback MCP server with no credential — impossible to run. Set
``AGT_MCP_AUTH_STRICT=1`` to drop the exemption and hold private addresses to
the same bar as public ones.

What is *not* exempt: a public server. With no token its auth method is
``none``, which AGT's default policy denies, and so does AgentGuard — before
discovering its tools rather than after.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
from urllib.parse import urlparse

from agent_os.mcp_auth_enforcement import (
    VALID_AUTH_METHODS, AuthCheckResult, McpAuthPolicy, McpServerEntry,
)
from agent_os.mcp_cve_feed import McpCveFeed, PackageEntry, VulnerabilityRecord

# AGT's own default, kept as the default here so the policy AgentGuard applies
# is the toolkit's rather than one invented at this boundary.
DEFAULT_METHODS = ("oauth2", "mtls", "bearer")

# Severities that stop an import rather than annotate it.
BLOCKING_SEVERITIES = ("CRITICAL",)

_TRUE = ("1", "true", "yes", "on")


def _env_methods() -> list[str]:
    """The auth allowlist, from AGT_MCP_AUTH_METHODS or AGT's default.

    An unknown name is dropped rather than raised on: ``McpServerEntry``
    validates its own allowlist and would refuse to construct, taking the whole
    admission control down over one typo in an environment variable. Dropping a
    name narrows the allowlist, so the failure direction is closed.
    """
    raw = os.getenv("AGT_MCP_AUTH_METHODS", "").strip()
    if not raw:
        return list(DEFAULT_METHODS)
    named = [m.strip().lower() for m in raw.split(",") if m.strip()]
    valid = [m for m in named if m in VALID_AUTH_METHODS]
    return valid or list(DEFAULT_METHODS)


def _strict() -> bool:
    return os.getenv("AGT_MCP_AUTH_STRICT", "").strip().lower() in _TRUE


def is_private_host(url: str) -> bool:
    """True when the URL's host is loopback, private, or otherwise not public.

    A resolution failure answers *False* — "not known to be private". The
    exemption has to be earned, so anything unresolvable is treated as public
    and held to the full auth requirement.
    """
    try:
        host = urlparse(url).hostname or ""
    except (ValueError, AttributeError):
        return False
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return bool(address.is_private or address.is_loopback)
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        resolved = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for entry in resolved:
        try:
            address = ipaddress.ip_address(entry[4][0])
        except (ValueError, IndexError):
            return False
        if not (address.is_private or address.is_loopback or address.is_link_local):
            return False
    return bool(resolved)


def auth_method_for(*, transport: str, has_token: bool) -> str:
    """Name the authentication method a connection will actually use.

    AgentGuard offers a bearer token and nothing else, so this is a
    classification rather than a negotiation. It is a named function because the
    answer is recorded on the registry entry and shown to an operator, and an
    inference kept inside a gate is one nobody can audit.
    """
    if transport == "stdio":
        return "stdio"
    return "bearer" if has_token else "none"


class AdmissionDenied(Exception):
    """Raised when AGT's auth policy refuses a connection before it is opened."""

    def __init__(self, result: AuthCheckResult) -> None:
        super().__init__(result.reason)
        self.reason = result.reason
        self.rule = "mcp_admission:auth_method"
        self.result = result


class ConnectionAdmission:
    """AGT's ``McpAuthPolicy``, applied to every outbound MCP connection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._policy = self._build()
        # Which server names already have an entry, tracked here rather than
        # read back out of McpAuthPolicy's private dict. `pinned` are the ones
        # an operator set deliberately and _ensure_entry_locked leaves alone.
        self._entries: set[str] = set()
        self._pinned: set[str] = set()

    @staticmethod
    def _build() -> McpAuthPolicy:
        # deny_none is AGT's fail-closed default and is left on. The stdio and
        # loopback exemptions are applied by *not consulting* the policy for
        # those connections, never by weakening it — so a connection that does
        # reach the policy is judged by the toolkit's rules unmodified.
        return McpAuthPolicy(default_allowed_methods=_env_methods(), deny_none=True)

    def pin(self, server_name: str, url: str, methods: list[str]) -> None:
        """Require specific auth methods for one named server.

        Offered in the strict direction only: AGT applies ``require_tls`` to a
        pinned entry, so pinning can refuse a connection the default allowlist
        would have permitted, and never the reverse.
        """
        usable = [m for m in methods if m in VALID_AUTH_METHODS]
        if not usable:
            raise ValueError(f"No valid auth methods in {methods!r}")
        with self._lock:
            self._policy.add_server(McpServerEntry(
                name=server_name, url=url, allowed_auth_methods=usable))
            self._entries.add(server_name)
            self._pinned.add(server_name)

    def unpin(self, server_name: str) -> bool:
        with self._lock:
            self._pinned.discard(server_name)
            self._entries.discard(server_name)
            return self._policy.remove_server(server_name)

    def check(self, *, server_name: str, url: str, transport: str,
              has_token: bool) -> dict:
        """Judge one connection. Returns a verdict and never raises on denial.

        Returned rather than raised because both callers need it: discovery
        turns a denial into an HTTP 400, and the import path records the auth
        method on the registry entry even when the connection is allowed.
        """
        method = auth_method_for(transport=transport, has_token=has_token)

        if transport == "stdio":
            return {
                "allowed": True, "auth_method": method, "enforced": False,
                "reason": "Local (stdio) server: no network connection to "
                          "authenticate. The launch command is constrained by "
                          "the Agent Governance Toolkit's command allowlist.",
            }

        if is_private_host(url) and not _strict():
            return {
                "allowed": True, "auth_method": method, "enforced": False,
                "reason": "Private or loopback address: reaching it already "
                          "required AGT_TOOL_ALLOW_PRIVATE, which is the "
                          "operator decision this check would otherwise repeat. "
                          "Set AGT_MCP_AUTH_STRICT=1 to enforce here too.",
            }

        name = server_name or url or "mcp"
        with self._lock:
            self._ensure_entry_locked(name, url)
            result = self._policy.check(name, method, url)
        return {
            "allowed": bool(result.allowed), "auth_method": method,
            "enforced": True, "reason": result.reason,
            "allowed_methods": _env_methods(),
        }

    def _ensure_entry_locked(self, server_name: str, url: str) -> None:
        """Give every enforced connection an entry, so AGT's TLS check runs.

        ``McpAuthPolicy`` applies ``require_tls`` only to servers in its
        explicit allowlist. A connection that falls through to the default
        allowlist is judged on its auth method alone, so a bearer token sent to
        a public host over plain ``http://`` is *allowed* — the credential
        travels in cleartext past the control that exists to require one.

        Rather than re-implement the scheme test, every enforced connection is
        given an entry carrying the same methods the default allowlist holds
        plus ``require_tls=True``. The verdict is still AGT's, produced by the
        branch of its own code that already knows ``https`` and ``wss`` are the
        TLS schemes. An entry an operator pinned is left untouched.
        """
        if server_name in self._entries:
            return
        self._policy.add_server(McpServerEntry(
            name=server_name, url=url, allowed_auth_methods=_env_methods(),
            require_tls=True))
        self._entries.add(server_name)

    def enforce(self, *, server_name: str, url: str, transport: str,
                has_token: bool) -> dict:
        """As :meth:`check`, raising :class:`AdmissionDenied` on a refusal."""
        verdict = self.check(server_name=server_name, url=url,
                             transport=transport, has_token=has_token)
        if not verdict["allowed"]:
            raise AdmissionDenied(AuthCheckResult(
                allowed=False, server_name=server_name,
                auth_method=verdict["auth_method"], reason=verdict["reason"]))
        return verdict

    def describe(self) -> dict:
        """The policy in force, for reporting."""
        return {
            "control": "agent_os.mcp_auth_enforcement.McpAuthPolicy",
            "allowed_methods": _env_methods(),
            "deny_unauthenticated": True,
            "strict_private": _strict(),
            "exempt": ["stdio"] + ([] if _strict() else ["private/loopback addresses"]),
        }

    def clear(self) -> None:
        with self._lock:
            self._policy = self._build()
            self._entries.clear()
            self._pinned.clear()


# ── Known vulnerabilities in the server's own implementation ─────────────────

# `npx -y @scope/pkg@1.2.3`, `uvx mcp-server-git==0.3.1`. Flags are skipped and
# the first bare token that is not a flag's value is taken as the package.
# Deliberately conservative: a command this does not understand yields no
# package, and no package is reported as *unchecked*, never as clean.
_NPM_RUNNERS = ("npx", "npm", "pnpm", "yarn", "bunx", "bun")
_PYPI_RUNNERS = ("uvx", "uv", "pipx", "pip", "pip3", "python", "python3")
_SKIP_FLAG_VALUES = ("--package", "-p", "--from", "--with", "-m")
_NOT_A_PACKAGE = ("install", "run", "exec", "add")
_NPM_SPEC = re.compile(
    r"^(?P<name>@[^/@\s]+/[^@\s]+|[^-@\s][^@\s]*)(?:@(?P<version>[^\s]+))?$")
_PYPI_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:(?:==|>=|~=)(?P<version>[^\s]+))?$")


def packages_from_launch(command: str, args: "list[str] | None") -> list[PackageEntry]:
    """The package a local MCP server's launch command names, if it names one.

    Empty when the command is a bare interpreter, a path, or anything else
    without a package specification — ``python server.py`` runs code from disk
    that no public database has an entry for. Empty is reported to the operator
    as *not determinable*, which is the true answer.
    """
    base = os.path.basename((command or "").strip()).lower()
    base = base[:-4] if base.endswith(".exe") else base
    if base in _NPM_RUNNERS:
        ecosystem, pattern = "npm", _NPM_SPEC
    elif base in _PYPI_RUNNERS:
        ecosystem, pattern = "PyPI", _PYPI_SPEC
    else:
        return []

    skip_next = False
    for raw in (args or []):
        token = str(raw).strip()
        if skip_next:
            skip_next = False
        elif token in _SKIP_FLAG_VALUES:
            skip_next = True
            continue
        elif token.startswith("-"):
            continue
        if not token or token.startswith("-"):
            continue
        # A path, not a published package. Stop rather than keep looking: the
        # command has already named what it runs.
        if "/" in token and not token.startswith("@"):
            return []
        if token.endswith(".py") or token.endswith(".js"):
            return []
        if token.lower() in _NOT_A_PACKAGE:
            continue
        match = pattern.match(token)
        if not match:
            continue
        return [PackageEntry(name=match.group("name"),
                             version=match.group("version") or "",
                             ecosystem=ecosystem)]
    return []


def _online() -> bool:
    return os.getenv("AGT_MCP_CVE_ONLINE", "").strip().lower() in _TRUE


class VulnerabilityIndex:
    """AGT's ``McpCveFeed`` over the packages MCP servers are launched from.

    **Offline by default.** ``McpCveFeed`` queries OSV.dev over the network with
    a ten-second timeout, and putting that on the import path would make
    onboarding a server depend on a third party being reachable — an
    availability failure dressed as a security control. Set
    ``AGT_MCP_CVE_ONLINE=1`` to query OSV. Without it only advisories an
    operator has entered are consulted, and a package with no local advisory is
    reported as *unchecked* rather than as clean.

    **A workaround, stated plainly.** ``McpCveFeed.add_manual_advisory`` stores
    a record under the cache key ``manual:<package>:<version>`` while
    ``check_package`` reads ``<ecosystem>:<package>:<version>``, so a manual
    advisory added for an npm package is never returned by ``check_all``. The
    records are read back here by probing the ``manual`` pseudo-ecosystem, which
    is the key AGT actually wrote to. Nothing is re-implemented and no AGT file
    is patched: the advisory store is simply read where it lives.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._feed = McpCveFeed()
        self._manual: set[tuple[str, str]] = set()

    def add_advisory(self, *, package: str, version: str, cve_id: str,
                     severity: str, summary: str,
                     fixed_version: str = "") -> None:
        """Record an advisory an operator knows about, with no network call."""
        with self._lock:
            self._feed.add_manual_advisory(VulnerabilityRecord(
                cve_id=cve_id, package=package, version=version,
                severity=(severity or "UNKNOWN").upper(), summary=summary,
                fixed_version=fixed_version))
            self._manual.add((package, version))

    def check(self, packages: list[PackageEntry]) -> dict:
        """Look up every package named, and say which ones were really checked."""
        findings, unchecked = [], []
        for pkg in packages:
            records = self._lookup(pkg)
            if records is None:
                unchecked.append({
                    "package": pkg.name, "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "reason": ("No version pinned in the launch command, so "
                               "there is no version to look up.")
                    if not pkg.version else
                    ("No local advisory for this package and "
                     "AGT_MCP_CVE_ONLINE is not set, so nothing was queried."),
                })
                continue
            for record in records:
                findings.append({
                    "package": record.package, "version": record.version,
                    "cve_id": record.cve_id, "severity": record.severity,
                    "summary": record.summary,
                    "fixed_version": record.fixed_version,
                    "source": record.source,
                    "references": list(record.references or [])[:5],
                })
        worst = ""
        for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            if any(f["severity"] == tier for f in findings):
                worst = tier
                break
        return {
            "checked": [{"package": p.name, "version": p.version,
                         "ecosystem": p.ecosystem}
                        for p in packages
                        if not any(u["package"] == p.name for u in unchecked)],
            "unchecked": unchecked,
            "online": _online(),
            "vulnerabilities": findings,
            "highest_severity": worst,
            "blocking": any(f["severity"] in BLOCKING_SEVERITIES for f in findings),
        }

    def _lookup(self, pkg: PackageEntry) -> "list[VulnerabilityRecord] | None":
        """Advisories for one package, or None when it could not be checked."""
        with self._lock:
            if (pkg.name, pkg.version) in self._manual:
                # The key add_manual_advisory actually wrote to.
                return list(self._feed.check_package(pkg.name, pkg.version, "manual"))
            if not _online() or not pkg.version:
                return None
            return list(self._feed.check_package(pkg.name, pkg.version, pkg.ecosystem))

    def describe(self) -> dict:
        with self._lock:
            advisories = len(self._manual)
        return {
            "control": "agent_os.mcp_cve_feed.McpCveFeed",
            "online": _online(),
            "source": "OSV.dev" if _online() else "operator-entered advisories only",
            "local_advisories": advisories,
            "blocking_severities": list(BLOCKING_SEVERITIES),
        }

    def clear(self) -> None:
        with self._lock:
            self._feed = McpCveFeed()
            self._manual.clear()
