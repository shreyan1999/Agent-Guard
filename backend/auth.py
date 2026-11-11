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

As an alternative bearer credential, set AGT_JWT_SECRET to accept static HS256
JSON Web Tokens: the signature is verified against that shared secret and the
principal is read from the token's `sub`, `tenant` and `roles` claims (with
`exp`/`nbf` and optional AGT_JWT_ISSUER / AGT_JWT_AUDIENCE enforced). This is a
deliberately static verifier — one symmetric secret, algorithm pinned to
HS256. It does not perform OIDC discovery, JWKS fetching, asymmetric keys or
key rotation; those need an external identity provider.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
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


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment, restoring the stripped padding."""
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def verify_hs256_jwt(
    token: str,
    secret: str,
    *,
    issuer: str | None = None,
    audience: str | None = None,
    now: float | None = None,
) -> Principal | None:
    """Validate a compact HS256 JWT and derive a Principal from its claims.

    This is real cryptographic verification with the standard library only: the
    HMAC-SHA256 signature is recomputed over ``header.payload`` and compared in
    constant time, then ``exp``/``nbf`` and any configured issuer/audience are
    checked. It is deliberately a *static* verifier — one shared symmetric
    secret, algorithm pinned to HS256. It does NOT do OIDC discovery, JWKS
    fetching, asymmetric keys (RS/ES) or key rotation. Returns None for any
    malformed, expired, wrongly-signed or under-specified token.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError):
        return None

    # Pin the algorithm: never honour "none" or an attacker-chosen alg.
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{header_b64}.{payload_b64}".encode("ascii"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected, signature):
        return None

    if not isinstance(payload, dict):
        return None

    clock = time.time() if now is None else now
    exp = payload.get("exp")
    if exp is not None and clock >= float(exp):
        return None
    nbf = payload.get("nbf")
    if nbf is not None and clock < float(nbf):
        return None
    if issuer is not None and payload.get("iss") != issuer:
        return None
    if audience is not None:
        aud = payload.get("aud")
        aud_ok = audience == aud or (isinstance(aud, list) and audience in aud)
        if not aud_ok:
            return None

    subject = str(payload.get("sub", "")).strip()
    if not subject:
        return None
    tenant = str(payload.get("tenant") or DEFAULT_TENANT).strip() or DEFAULT_TENANT

    raw_roles = payload.get("roles")
    if raw_roles is None and payload.get("role") is not None:
        raw_roles = [payload["role"]]
    if isinstance(raw_roles, str):
        raw_roles = [raw_roles]
    if not isinstance(raw_roles, list):
        return None
    role_set = frozenset(
        str(r).strip() for r in raw_roles if str(r).strip() in _ROLE_LEVEL
    )
    if not role_set:
        return None

    return Principal(subject=subject, tenant=tenant, roles=role_set)


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
        self._jwt_secret: str = ""
        self._jwt_issuer: str | None = None
        self._jwt_audience: str | None = None
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
        # Optional static HS256 JWT acceptance (one shared symmetric secret).
        self._jwt_secret = os.environ.get("AGT_JWT_SECRET", "").strip()
        self._jwt_issuer = (os.environ.get("AGT_JWT_ISSUER", "").strip() or None)
        self._jwt_audience = (os.environ.get("AGT_JWT_AUDIENCE", "").strip() or None)
        self.enabled = bool(by_token) or bool(self._jwt_secret)

    def authenticate(self, token: str | None) -> Principal | None:
        """Return the principal for a bearer token, or None if it is unknown.

        A static API key is matched first (constant-time against every
        configured key so timing cannot leak a valid prefix). Failing that, and
        only when AGT_JWT_SECRET is configured, the token is validated as a
        static HS256 JWT and the principal is derived from its claims.
        """
        if not token:
            return None
        # compare_digest refuses a str carrying non-ASCII and raises TypeError.
        # Headers reach here decoded as latin-1, so a single high byte in an
        # Authorization header turned a 401 into an unhandled 500. Compare the
        # UTF-8 bytes instead: same constant-time comparison, no input that can
        # make it throw.
        try:
            candidate = token.encode("utf-8")
        except (UnicodeEncodeError, AttributeError):
            return None
        match: Principal | None = None
        for known, principal in self._by_token.items():
            if secrets.compare_digest(candidate, known.encode("utf-8")):
                match = principal
        if match is not None:
            return match
        if self._jwt_secret:
            return verify_hs256_jwt(
                token, self._jwt_secret,
                issuer=self._jwt_issuer, audience=self._jwt_audience,
            )
        return None
