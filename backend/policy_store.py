"""File-backed policy store.

AGT resolves a policy's ``extends`` parents *relative to that policy's own
directory*, and refuses any parent that resolves outside it. Inheritance
therefore cannot work against scattered temp files: every policy has to live
in one directory under a stable filename. Persistence across restarts falls
out of the same change.

Two representations exist deliberately:

  * the **authored** document — exactly what the user wrote, returned by
    ``read()`` and rendered by the editor;
  * the **resolved** policy — what AGT produces after merging parents,
    returned by ``resolve()``.

They differ whenever ``extends`` is used, and the editor has to show both:
inherited rules are not editable in the child, and a child rule that tries to
weaken a parent ``deny`` is dropped by AGT with only a log line.
"""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml

from agentmesh.governance.policy import Policy

API_VERSION = "governance.toolkit/v1"

#: Conflict-resolution strategies AGT's PolicyEngine accepts.
CONFLICT_STRATEGIES = (
    "deny_overrides",
    "allow_overrides",
    "priority_first_match",
    "most_specific_wins",
)

#: Scopes AGT's conflict resolver understands. Only consulted by
#: ``most_specific_wins`` — under any other strategy, scope is inert.
POLICY_SCOPES = ("global", "organization", "tenant", "agent")

DEFAULT_STRATEGY = "deny_overrides"

# Policy names become filenames, so they are restricted rather than escaped.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PolicyError(ValueError):
    """Raised for a malformed policy, a bad name, or an unresolvable parent."""


def validate_name(name: str) -> str:
    """Reject anything that would not be a safe, predictable filename."""
    if not _NAME_RE.match(name or "") or name in (".", "..") or name.endswith(".yaml"):
        raise PolicyError(
            f"Invalid policy name {name!r}. Use letters, digits, dot, dash or "
            "underscore, starting with a letter or digit, max 64 characters."
        )
    return name


class PolicyStore:
    """Every policy as one YAML file in a single directory."""

    def __init__(self, directory: "str | Path") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    # ── paths and naming ────────────────────────────────────────────────

    def path(self, name: str) -> Path:
        return self.dir / f"{validate_name(name)}.yaml"

    def exists(self, name: str) -> bool:
        return self.path(name).is_file()

    def names(self) -> list[str]:
        return sorted(p.stem for p in self.dir.glob("*.yaml") if not p.name.startswith("."))

    # ── documents ───────────────────────────────────────────────────────

    def read(self, name: str) -> dict:
        """The authored document, with ``extends`` given back as policy names."""
        path = self.path(name)
        if not path.is_file():
            raise PolicyError(f"Policy '{name}' not found")
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        doc["extends"] = [_to_name(ref) for ref in doc.get("extends", [])]
        return doc

    def write(self, name: str, doc: dict) -> dict:
        """Persist a policy, translating ``extends`` names to filenames.

        Written to a temp file and moved into place, so a failure part-way
        through cannot leave a half-written policy that AGT would then load.
        """
        validate_name(name)
        stored = dict(doc)
        stored["apiVersion"] = stored.get("apiVersion") or API_VERSION
        stored["name"] = name
        stored["extends"] = [f"{_to_name(ref)}.yaml" for ref in doc.get("extends", [])]

        tmp = self.dir / f".{uuid.uuid4().hex}.tmp"
        try:
            tmp.write_text(
                yaml.safe_dump(stored, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
            os.replace(tmp, self.path(name))
        finally:
            tmp.unlink(missing_ok=True)
        return stored

    def delete(self, name: str) -> None:
        dependents = self.dependents(name)
        if dependents:
            raise PolicyError(
                f"Policy '{name}' is extended by: {', '.join(dependents)}. "
                "Delete or detach those first."
            )
        self.path(name).unlink(missing_ok=True)

    def dependents(self, name: str) -> list[str]:
        """Policies whose ``extends`` names this one."""
        out = []
        for other in self.names():
            if other == name:
                continue
            try:
                if name in self.read(other).get("extends", []):
                    out.append(other)
            except PolicyError:
                continue
        return sorted(out)

    def descendants(self, name: str) -> list[str]:
        """Every policy that inherits from *name*, directly or transitively.

        ``dependents`` answers "who names this as a parent". A grandchild names
        the child, not this policy, yet AGT still merges this policy's rules
        into it — so anything holding a compiled copy of the subtree has to be
        invalidated across the whole closure, not just one level of it.

        Walked with a visited set rather than trusting ``validate``'s cycle
        check: this runs against whatever is on disk, and a loop here would
        hang the request that is trying to save a policy.
        """
        seen: set[str] = set()
        frontier = [name]
        while frontier:
            for child in self.dependents(frontier.pop()):
                if child not in seen:
                    seen.add(child)
                    frontier.append(child)
        return sorted(seen)

    def yaml_text(self, name: str) -> str:
        return self.path(name).read_text(encoding="utf-8")

    # ── AGT resolution ──────────────────────────────────────────────────

    def resolve(self, name: str) -> Policy:
        """The merged policy AGT will actually enforce."""
        try:
            return Policy.from_yaml_file(str(self.path(name)))
        except FileNotFoundError as e:
            raise PolicyError(str(e)) from e
        except ValueError as e:                      # circular extends, bad apiVersion
            raise PolicyError(str(e)) from e

    def validate(self, name: str, doc: dict) -> Policy:
        """Parse a candidate document without committing it.

        Written into the policy directory under a dotted temp name so that
        ``extends`` resolves against the real siblings; AGT rejects parents
        outside the directory, so validating anywhere else would fail.
        """
        validate_name(name)
        strategy = doc.get("conflict_strategy", DEFAULT_STRATEGY)
        if strategy not in CONFLICT_STRATEGIES:
            raise PolicyError(
                f"Unknown conflict_strategy {strategy!r}. "
                f"Expected one of: {', '.join(CONFLICT_STRATEGIES)}"
            )
        scope = doc.get("scope", "global")
        if scope not in POLICY_SCOPES:
            raise PolicyError(
                f"Unknown scope {scope!r}. Expected one of: {', '.join(POLICY_SCOPES)}"
            )
        for ref in doc.get("extends", []):
            parent = _to_name(ref)
            if parent == name:
                raise PolicyError(f"Policy '{name}' cannot extend itself")
            if not self.exists(parent):
                raise PolicyError(f"Parent policy '{parent}' does not exist")
        self._check_cycle(name, [_to_name(r) for r in doc.get("extends", [])])

        stored = dict(doc)
        stored["apiVersion"] = stored.get("apiVersion") or API_VERSION
        stored["name"] = name
        stored["extends"] = [f"{_to_name(r)}.yaml" for r in doc.get("extends", [])]

        probe = self.dir / f".validate-{uuid.uuid4().hex}.yaml"
        try:
            probe.write_text(yaml.safe_dump(stored, sort_keys=False), encoding="utf-8")
            return Policy.from_yaml_file(str(probe))
        except (ValueError, FileNotFoundError, yaml.YAMLError) as e:
            raise PolicyError(str(e)) from e
        finally:
            probe.unlink(missing_ok=True)

    def _check_cycle(self, name: str, parents: list[str]) -> None:
        """Reject an edit that would close a loop in the extends graph.

        AGT detects cycles when it resolves a file, but only against what is
        already on disk. An edit that *would* create a loop has to be caught
        before it is written, so the graph is walked with the candidate's
        parents substituted for the stored ones.
        """
        def walk(current: str, seen: tuple) -> None:
            if current == name:
                raise PolicyError(
                    "Circular policy extends: "
                    + " -> ".join([*seen, current])
                )
            if current in seen:
                return
            try:
                ancestors = self.read(current).get("extends", [])
            except PolicyError:
                return
            for ancestor in ancestors:
                walk(_to_name(ancestor), (*seen, current))

        for parent in parents:
            walk(parent, (name,))

    # ── inheritance detail, for the editor ──────────────────────────────

    def resolved_detail(self, name: str) -> dict:
        """The merged rule set, each rule tagged with where it came from.

        Origins are inferred by comparing AGT's merged output against each
        authored document, rather than by reimplementing the merge. Doing the
        merge a second time here is exactly how two representations drift.
        """
        merged = self.resolve(name)
        chain = self._chain(name)
        authored = {p: self.read(p).get("rules", []) or [] for p in chain}

        def origin_of(rule) -> str:
            for policy_name in chain:                # parents first
                for candidate in authored[policy_name]:
                    if (candidate.get("name") == rule.name
                            and candidate.get("condition") == rule.condition
                            and candidate.get("action", "deny") == rule.action):
                        return policy_name
            return name

        merged_rules = [
            {
                "name": r.name, "condition": r.condition, "action": r.action,
                "description": r.description or "", "priority": r.priority,
                "stage": r.stage, "enabled": r.enabled,
                "limit": r.limit, "approvers": list(r.approvers),
                "origin": origin_of(r),
                "inherited": origin_of(r) != name,
            }
            for r in merged.rules
        ]

        # A child rule AGT dropped for weakening a parent deny is absent from
        # the merged set under its own action.
        surviving = {(r["name"], r["action"], r["condition"]) for r in merged_rules}
        parent_denies = {
            c.get("name")
            for p in chain if p != name
            for c in authored[p] if c.get("action") == "deny"
        }
        dropped = []
        for candidate in authored.get(name, []):
            key = (candidate.get("name"), candidate.get("action", "deny"),
                   candidate.get("condition"))
            if key in surviving:
                continue
            reason = (
                f"AGT drops this rule: '{candidate.get('name')}' is a deny rule in an "
                "inherited policy, and inheritance is additive-only — a child cannot "
                "weaken a parent deny."
                if candidate.get("name") in parent_denies
                else "Not present in the merged policy."
            )
            dropped.append({**candidate, "reason": reason})

        return {
            "name": name,
            "chain": chain,
            "default_action": merged.default_action,
            "scope": merged.scope,
            "conflict_strategy": self.read(name).get("conflict_strategy", DEFAULT_STRATEGY),
            "rules": merged_rules,
            "dropped_rules": dropped,
        }

    def _chain(self, name: str, _seen: Optional[list] = None) -> list[str]:
        """Ancestors first, then *name* — the order AGT merges in."""
        _seen = _seen or []
        if name in _seen:
            return []
        _seen = [*_seen, name]
        out: list[str] = []
        try:
            parents = self.read(name).get("extends", [])
        except PolicyError:
            parents = []
        for parent in parents:
            for ancestor in self._chain(parent, _seen):
                if ancestor not in out:
                    out.append(ancestor)
        out.append(name)
        return out


def _to_name(ref: Any) -> str:
    """Accept either a policy name or a bare filename; return the name."""
    text = str(ref).strip()
    return text[:-5] if text.endswith(".yaml") else text
