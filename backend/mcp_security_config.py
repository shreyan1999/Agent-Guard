"""The MCP detection rule set, as a file rather than as library defaults.

AGT asks for this in as many words. Constructing ``MCPSecurityScanner()``
without a config emits a warning that its built-in rules "may not cover all MCP
tool poisoning techniques" and points at ``load_mcp_security_config()``; the
``PromptInjectionDetector`` it builds internally emits the same warning about
its own rules. This module supplies both, from ``config/mcp-security.yaml`` and
``config/prompt-injection.yaml``, so the patterns that decide whether a
descriptor is hostile are reviewable, diffable and version-controlled next to
the code instead of frozen inside a dependency.

Three things it does that AGT's loaders do not.

**It validates.** ``load_mcp_security_config`` accepts whatever YAML it is
given; the *scanner* then compiles each pattern and, on a bad regex, logs a
warning and skips it. The result is a config that reports as healthy while
silently missing a detection — the worst shape a security control can take. So
every pattern is compiled here first, with the flags the scanner will use, and a
file containing an invalid regex is rejected whole.

**It keeps the last good config.** A rejected reload leaves the running rule set
in place rather than falling back to defaults, because a failed edit should not
quietly change what the platform detects.

**It reaches the nested detector.** ``MCPSecurityScanner.__init__`` takes
``config=`` but builds its ``PromptInjectionDetector()`` with no arguments and
offers no parameter for one, so the injection rules are unreachable through the
constructor. The configured detector is assigned onto the scanner afterwards,
which is the only way in. That is a deliberate reach into a private attribute
and is marked as such where it happens.

Paths come from ``AGT_MCP_SECURITY_CONFIG`` and ``AGT_PROMPT_INJECTION_CONFIG``,
defaulting to the two files in ``backend/config/``. A missing file is reported
as *using built-in defaults* rather than passed over in silence: the whole point
of the file is that an operator can see which rules are in force.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from agent_os.mcp_security import (
    MCPSecurityConfig, load_mcp_security_config,
)
from agent_os.prompt_injection import (
    PromptInjectionConfig, PromptInjectionDetector, load_prompt_injection_config,
)

CONFIG_DIR = Path(__file__).parent / "config"
MCP_RULES = "mcp-security.yaml"
INJECTION_RULES = "prompt-injection.yaml"

# The flags MCPSecurityScanner._compile_patterns uses. Validating with anything
# else would pass patterns the scanner then rejects, which is the failure this
# module exists to prevent.
_FLAGS = re.IGNORECASE | re.DOTALL

# Fields on each config dataclass that hold regex strings. `excessive_whitespace`
# and `base64_pattern` are single strings rather than lists.
_MCP_PATTERN_LISTS = (
    "invisible_unicode_patterns", "hidden_comment_patterns",
    "hidden_instruction_patterns", "encoded_payload_patterns",
    "exfiltration_patterns", "privilege_escalation_patterns",
    "role_override_patterns",
)
_MCP_PATTERN_SCALARS = ("excessive_whitespace_pattern",)
_INJECTION_PATTERN_LISTS = (
    "direct_override_patterns", "delimiter_patterns", "role_play_patterns",
    "context_manipulation_patterns", "multi_turn_patterns", "encoding_patterns",
)
_INJECTION_PATTERN_SCALARS = ("base64_pattern",)


class RuleSetInvalid(Exception):
    """Raised when a rule file contains a pattern the scanner could not use."""

    def __init__(self, path: str, problems: list[dict]) -> None:
        super().__init__(f"{len(problems)} invalid pattern(s) in {path}")
        self.path = path
        self.problems = problems


def _path(env: str, filename: str) -> Path:
    override = os.getenv(env, "").strip()
    return Path(override) if override else (CONFIG_DIR / filename)


def _validate(config, lists, scalars, path: str) -> None:
    """Compile every pattern, or refuse the whole file.

    Refusing the file rather than the pattern is the point. AGT drops the bad
    entry and carries on, so a single typo silently narrows detection while
    everything still reports healthy.
    """
    problems = []
    for field in lists:
        for index, pattern in enumerate(getattr(config, field, []) or []):
            try:
                re.compile(pattern, _FLAGS)
            except re.error as exc:
                problems.append({"field": field, "index": index,
                                 "pattern": str(pattern)[:120], "error": str(exc)})
    for field in scalars:
        pattern = getattr(config, field, "")
        if pattern:
            try:
                re.compile(pattern, _FLAGS)
            except re.error as exc:
                problems.append({"field": field, "index": 0,
                                 "pattern": str(pattern)[:120], "error": str(exc)})
    if problems:
        raise RuleSetInvalid(path, problems)


def _counts(config, lists, scalars, defaults) -> dict:
    """How many rules are in force, and how many are additions to AGT's set."""
    body = {}
    for field in lists:
        loaded = list(getattr(config, field, []) or [])
        shipped = list(getattr(defaults, field, []) or [])
        body[field] = {
            "total": len(loaded),
            "from_toolkit": sum(1 for p in loaded if p in shipped),
            "added": sum(1 for p in loaded if p not in shipped),
            "missing_from_toolkit": sum(1 for p in shipped if p not in loaded),
        }
    for field in scalars:
        body[field] = {"total": 1 if getattr(config, field, "") else 0,
                       "from_toolkit": int(getattr(config, field, "")
                                           == getattr(defaults, field, "")),
                       "added": 0, "missing_from_toolkit": 0}
    return body


class RuleSet:
    """The loaded detection rules, and everything an operator should see of them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._mcp = MCPSecurityConfig()
        self._injection = PromptInjectionConfig()
        self._status: dict = {}
        self.reload()

    # ── loading ──────────────────────────────────────────────────────────

    def reload(self) -> dict:
        """Read both files. On any failure the running rule set is left alone.

        Returns a status report rather than raising, because this is called at
        start-up as well as from an endpoint: a bad file should leave the
        platform running on known-good rules and *say so*, not refuse to boot
        and not quietly revert to defaults.
        """
        mcp_path = _path("AGT_MCP_SECURITY_CONFIG", MCP_RULES)
        inj_path = _path("AGT_PROMPT_INJECTION_CONFIG", INJECTION_RULES)

        mcp, mcp_status = self._read(
            mcp_path, load_mcp_security_config, MCPSecurityConfig,
            _MCP_PATTERN_LISTS, _MCP_PATTERN_SCALARS)
        inj, inj_status = self._read(
            inj_path, load_prompt_injection_config, PromptInjectionConfig,
            _INJECTION_PATTERN_LISTS, _INJECTION_PATTERN_SCALARS)

        with self._lock:
            if mcp is not None:
                self._mcp = mcp
            if inj is not None:
                self._injection = inj
            # A half that failed to load keeps the rules it already had, so its
            # status has to carry *those* counts. Leaving them out made the
            # report claim fewer rules than were actually running — the same
            # class of lie this module exists to stop, in the other direction.
            if mcp is None:
                mcp_status["counts"] = _counts(
                    self._mcp, _MCP_PATTERN_LISTS, _MCP_PATTERN_SCALARS,
                    MCPSecurityConfig())
            if inj is None:
                inj_status["counts"] = _counts(
                    self._injection, _INJECTION_PATTERN_LISTS,
                    _INJECTION_PATTERN_SCALARS, PromptInjectionConfig())
            self._status = {"mcp_security": mcp_status,
                            "prompt_injection": inj_status}
            return dict(self._status)

    @staticmethod
    def _read(path: Path, loader, default_cls, lists, scalars) -> tuple:
        """Load and validate one file. Returns (config or None, status)."""
        if not path.exists():
            return None, {
                "path": str(path), "loaded": False, "source": "toolkit defaults",
                "reason": "No rule file at this path, so AGT's built-in rules "
                          "are in force. They are the ones the toolkit itself "
                          "warns may not cover every technique.",
                "counts": _counts(default_cls(), lists, scalars, default_cls()),
            }
        try:
            config = loader(str(path))
            _validate(config, lists, scalars, str(path))
        except RuleSetInvalid as invalid:
            return None, {
                "path": str(path), "loaded": False, "source": "unchanged",
                "reason": f"{len(invalid.problems)} pattern(s) would not "
                          f"compile. The previously loaded rules are still in "
                          f"force; the toolkit would have skipped these and "
                          f"reported success.",
                "problems": invalid.problems,
            }
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return None, {
                "path": str(path), "loaded": False, "source": "unchanged",
                "reason": f"Could not read the rule file: {exc}",
            }
        return config, {
            "path": str(path), "loaded": True, "source": "file",
            "disclaimer": getattr(config, "disclaimer", "") or "",
            "counts": _counts(config, lists, scalars, default_cls()),
        }

    # ── use ──────────────────────────────────────────────────────────────

    @property
    def mcp(self) -> MCPSecurityConfig:
        with self._lock:
            return self._mcp

    def injection_detector(self) -> PromptInjectionDetector:
        """A detector built from the configured injection rules."""
        with self._lock:
            return PromptInjectionDetector(injection_config=self._injection)

    # ── reporting ────────────────────────────────────────────────────────

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def describe(self) -> dict:
        with self._lock:
            status = dict(self._status)
        rules = 0
        gaps = 0
        for half in status.values():
            for entry in (half.get("counts") or {}).values():
                rules += entry["total"]
                gaps += entry["missing_from_toolkit"]
            if half.get("problems"):
                gaps += len(half["problems"])
        return {
            "control": "agent_os.mcp_security.MCPSecurityConfig",
            "files": [half.get("path") for half in status.values()],
            "loaded": all(half.get("loaded") for half in status.values()),
            "rules": rules,
            # A rule AGT ships that this file does not carry is a detection the
            # platform has given up, so it is counted and surfaced rather than
            # left for someone to notice.
            "toolkit_rules_dropped": gaps,
            "detail": status,
        }


def validate_text(text: str, kind: str = "mcp") -> dict:
    """Dry-run a candidate rule file without installing it.

    Writes to a temporary path because AGT's loaders take a filename rather than
    a string. Nothing in the running configuration is touched.
    """
    import tempfile

    loader, default_cls, lists, scalars = (
        (load_mcp_security_config, MCPSecurityConfig,
         _MCP_PATTERN_LISTS, _MCP_PATTERN_SCALARS)
        if kind == "mcp" else
        (load_prompt_injection_config, PromptInjectionConfig,
         _INJECTION_PATTERN_LISTS, _INJECTION_PATTERN_SCALARS))

    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False,
                                         encoding="utf-8")
    try:
        handle.write(text)
        handle.close()
        config = loader(handle.name)
        _validate(config, lists, scalars, "<submitted>")
    except RuleSetInvalid as invalid:
        return {"valid": False, "problems": invalid.problems,
                "reason": "One or more patterns would not compile. The toolkit "
                          "would have skipped them and reported success."}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"valid": False, "problems": [], "reason": str(exc)}
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass

    counts = _counts(config, lists, scalars, default_cls())
    dropped = sum(e["missing_from_toolkit"] for e in counts.values())
    return {
        "valid": True, "kind": kind, "counts": counts,
        "toolkit_rules_dropped": dropped,
        "reason": ("Every pattern compiles."
                   + (f" {dropped} rule(s) the toolkit ships are not present in "
                      f"this file — those detections would be given up."
                      if dropped else "")),
    }
