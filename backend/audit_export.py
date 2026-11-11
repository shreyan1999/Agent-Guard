"""Verifying and exporting the audit chain, with AGT's own tools.

Two halves of the evidence story that were built into AGT and never wired up:

**Verifying the durable file.** ``AGT_AUDIT_FILE`` + ``AGT_AUDIT_KEY`` stream
entries to an HMAC-signed JSON-lines file through AGT's ``FileAuditSink``.
``HashChainVerifier`` is the other end of that — it re-reads the file and checks
every entry's content hash and HMAC against the key it was written with. Without
it a deployment could write a durable audit log and have no way to establish the
file was intact, which is most of the reason to keep one.

**Exporting as evidence rather than as a dump.** ``/audit/export`` hands back the
raw chain, which is fine for a machine that already trusts this instance.
``audit_accountability_export`` turns an entry into a structured external
accountability record — actor, subject, operation, a *digest of the policy that
decided it*, the decision, and references to inputs, outputs and evidence — and
maps that onto an EEOAP-profile statement. The difference is between giving an
auditor a log file and giving them something they can check.

Neither reads or returns the signing key. Verification takes it from the
environment, uses it, and reports only whether the file held.
"""

from __future__ import annotations

import os
from pathlib import Path

import observability

from agentmesh.governance.audit_backends import HashChainVerifier
from audit_accountability_export import (
    accountability_export_to_eeoap_statement,
    audit_entry_to_accountability_export,
    canonical_sha256,
)

_log = observability.get_logger(__name__)

EXPORT_PROFILE = "agt.audit_entry.external_accountability_export"


def durable_audit_config() -> dict:
    """Whether a durable signed audit file is configured, without leaking the key."""
    path = os.getenv("AGT_AUDIT_FILE", "").strip()
    key = os.getenv("AGT_AUDIT_KEY", "").strip()
    return {
        "configured": bool(path and key),
        "path": path or None,
        # Named, never returned: the presence of a key is a fact an operator
        # needs; its value is not.
        "key_present": bool(key),
    }


def verify_durable_file() -> dict:
    """Re-verify the on-disk audit file against the key it was written with.

    Returns a result rather than raising, because "not configured" and "does not
    exist yet" are ordinary states an operator should be able to see, not errors.
    """
    config = durable_audit_config()
    if not config["configured"]:
        return {
            **config, "valid": None, "errors": [],
            "reason": "Durable audit is off. Set AGT_AUDIT_FILE and AGT_AUDIT_KEY "
                      "to stream entries to an HMAC-signed file.",
        }
    path = Path(config["path"])
    if not path.exists():
        return {
            **config, "valid": None, "errors": [],
            "reason": "The audit file does not exist yet — nothing has been "
                      "written to it since it was configured.",
        }
    try:
        valid, errors = HashChainVerifier().verify_file(
            path, os.environ["AGT_AUDIT_KEY"].encode("utf-8"))
    except Exception as exc:                     # a malformed file is a finding
        # The caller gets the type and message; the traceback only fits here.
        _log.warning("audit: the durable audit file could not be verified",
                     exc_info=True)
        return {**config, "valid": False,
                "errors": [f"{type(exc).__name__}: {exc}"],
                "reason": "The file could not be read as a signed audit log."}
    return {
        **config,
        "valid": bool(valid),
        "errors": list(errors or []),
        "reason": ("Every entry's content hash and HMAC verified against the "
                   "configured key."
                   if valid else
                   "The file does not verify. An entry was edited, reordered or "
                   "written under a different key."),
    }


def accountability_records(entries: list) -> list:
    """Turn audit entries into external accountability records + EEOAP statements.

    Each record carries a ``policy_digest`` binding the decision to the policy
    that made it, which is what makes the export checkable rather than merely
    readable. An entry AGT cannot map is reported with its error rather than
    dropped — a silently shorter export would misrepresent the chain.
    """
    records = []
    for entry in entries:
        try:
            export = audit_entry_to_accountability_export(entry)
            records.append({
                "entry_id": getattr(entry, "entry_id", None),
                "export": export,
                "eeoap": accountability_export_to_eeoap_statement(export),
                "digest": canonical_sha256(export),
            })
        except Exception as exc:
            _log.debug("audit: entry %r could not be mapped to an "
                       "accountability record",
                       getattr(entry, "entry_id", None), exc_info=True)
            records.append({
                "entry_id": getattr(entry, "entry_id", None),
                "export": None, "eeoap": None, "digest": None,
                "error": f"{type(exc).__name__}: {exc}",
            })
    return records
