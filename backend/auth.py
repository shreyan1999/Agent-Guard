"""API-key authentication, role hierarchy and tenant identity.

This is application-layer security (FastAPI), not an AGT primitive: the toolkit
governs what an *agent* may do once inside the platform; this module governs
who may talk to the platform at all.

Auth is opt-in. With no keys configured the provider is disabled and every
request runs as an anonymous local admin — the single-tenant playground mode
this project ships in. Set AGT_API_KEYS (or AGT_API_KEYS_FILE) and the same
endpoints demand a bearer token, enforce roles, and scope agents by tenant.

Key format (AGT_API_KEYS), comma- or newline-separated:

    token:subject:tenant:role1|role2

e.g.  s3cret-ana:ana:acme:operator,  s3cret-root:root:acme:admin

AGT_API_KEYS_FILE may instead point at a JSON list of
{"token","subject","tenant","roles"} objects.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TENANT = "default"

# admin ⊇ operator ⊇ viewer. A principal satisfies a required role when its
# highest role sits at or above the requirement.
_ROLE_LEVEL = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    roles: frozenset[str]

    @property
    def level(self) -> int:
        return max((_ROLE_LEVEL.get(r, -1) for r in self.roles), default=-1)

    def has_role(self, required: str) -> bool:
        need = _ROLE_LEVEL.get(required)
        if need is None:
            return False
        return self.level >= need

    @property
    def is_admin(self) -> bool:
        return self.has_role("admin")


# The identity requests run as when auth is disabled: a local admin that sees
# every tenant, so the playground behaves exactly as it did before auth existed.
ANONYMOUS = Principal(subject="anonymous", tenant=DEFAULT_TENANT,
                      roles=frozenset({"admin"}))


class AuthError(Exception):
    """Raised for malformed key configuration."""


def _parse_entries(raw: str) -> dict[str, Principal]:
    principals: dict[str, Principal] = {}
    parts = [chunk.strip() for line in raw.splitlines()
             for chunk in line.split(",")]
    for entry in filter(None, parts):
        fields = entry.split(":")
        if len(fields) != 4:
            raise AuthError(
                f"Bad AGT_API_KEYS entry (want token:subject:tenant:roles): {entry!r}"
            )
        token, subject, tenant, roles = (f.strip() for f in fields)
        role_set = frozenset(r.strip() for r in roles.split("|") if r.strip())
        if not token or not subject or not tenant or not role_set:
            raise AuthError(f"Incomplete AGT_API_KEYS entry: {entry!r}")
        unknown = role_set - _ROLE_LEVEL.keys()
        if unknown:
            raise AuthError(f"Unknown role(s) {sorted(unknown)} in entry: {entry!r}")
        principals[token] = Principal(subject=subject, tenant=tenant, roles=role_set)
    return principals


def _parse_file(path: str) -> dict[str, Principal]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise AuthError(f"{path}: expected a JSON list of key objects")
    principals: dict[str, Principal] = {}
    for obj in data:
        try:
            token = str(obj["token"]).strip()
            subject = str(obj["subject"]).strip()
            tenant = str(obj["tenant"]).strip()
            role_set = frozenset(str(r).strip() for r in obj["roles"])
        except (KeyError, TypeError) as exc:
            raise AuthError(f"{path}: bad key object {obj!r}") from exc
        if not token or not subject or not tenant or not role_set:
            raise AuthError(f"{path}: incomplete key object {obj!r}")
        unknown = role_set - _ROLE_LEVEL.keys()
        if unknown:
            raise AuthError(f"{path}: unknown role(s) {sorted(unknown)} in {obj!r}")
        principals[token] = Principal(subject=subject, tenant=tenant, roles=role_set)
    return principals


class AuthProvider:
    """Holds the configured API keys and resolves bearer tokens to principals."""

    def __init__(self) -> None:
        self._by_token: dict[str, Principal] = {}
        self.enabled = False
        self.load_from_env()

    def load_from_env(self) -> None:
        """(Re)read AGT_API_KEYS / AGT_API_KEYS_FILE from the environment."""
        by_token: dict[str, Principal] = {}
        file_path = os.environ.get("AGT_API_KEYS_FILE", "").strip()
        if file_path:
            by_token.update(_parse_file(file_path))
        raw = os.environ.get("AGT_API_KEYS", "").strip()
        if raw:
            by_token.update(_parse_entries(raw))
        self._by_token = by_token
        self.enabled = bool(by_token)

    def authenticate(self, token: str | None) -> Principal | None:
        """Return the principal for a bearer token, or None if it is unknown.

        Compared in constant time against every configured key so a caller
        cannot learn a valid prefix from response timing.
        """
        if not token:
            return None
        match: Principal | None = None
        for known, principal in self._by_token.items():
            if secrets.compare_digest(token, known):
                match = principal
        return match
