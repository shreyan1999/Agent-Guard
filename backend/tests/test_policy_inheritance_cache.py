"""Editing a policy has to reach the policies that inherit from it.

AGT compiles a policy exactly once, in ``GovernedCallable.__init__``, so this
dashboard caches governed callables per (tool, policy, agent, ring, strategy).
Eviction used to drop only the edited policy's own entries — which meant a
child policy went on enforcing the merge it was built with. An operator who
added a deny rule to a shared base policy would see it enforced on the base and
silently ignored by everything extending it, for as long as the process lived.

That is a fail-open on precisely the edit someone makes to tighten a policy, so
these tests pin it in that direction: a parent gains a deny, and the child has
to start denying.
"""

import tempfile
from pathlib import Path

import pytest

from policy_store import PolicyStore


# ── The closure itself ───────────────────────────────────────────────────────

@pytest.fixture
def store():
    return PolicyStore(tempfile.mkdtemp(prefix="agt-descendants-"))


def _write(store, name, extends=()):
    store.write(name, {"name": name, "default_action": "allow",
                       "rules": [], "extends": list(extends)})


def test_descendants_is_empty_for_a_leaf(store):
    _write(store, "base")
    assert store.descendants("base") == []


def test_descendants_walks_past_the_first_level(store):
    _write(store, "base")
    _write(store, "child", extends=["base"])
    _write(store, "grandchild", extends=["child"])
    # A grandchild names the child, never the base — but AGT still merges the
    # base into it, so it belongs to the base's closure.
    assert store.dependents("base") == ["child"]
    assert store.descendants("base") == ["child", "grandchild"]


def test_descendants_covers_every_branch(store):
    _write(store, "base")
    _write(store, "left", extends=["base"])
    _write(store, "right", extends=["base"])
    _write(store, "leaf", extends=["left"])
    assert store.descendants("base") == ["leaf", "left", "right"]


def test_descendants_terminates_on_a_cycle_on_disk(store):
    """`validate` rejects cycles; this walks whatever is actually there.

    The API cannot create this, but a hand-edited directory can, and a walk
    that looped would hang the request trying to save a policy rather than
    fail it.
    """
    _write(store, "a", extends=["b"])
    _write(store, "b", extends=["a"])
    assert store.descendants("a") == ["a", "b"]


def test_descendants_ignores_an_unrelated_policy(store):
    _write(store, "base")
    _write(store, "child", extends=["base"])
    _write(store, "unrelated")
    assert "unrelated" not in store.descendants("base")


# ── The behaviour that closure exists to protect ─────────────────────────────

def _policy(client, name, *, extends=(), rules=(), method="post", path=None):
    body = {"name": name, "default_action": "allow",
            "extends": list(extends), "rules": list(rules)}
    if method == "post":
        return client.post("/policies", json=body)
    return client.put(path or f"/policies/{name}", json=body)


DENY_READ = {"name": "no-read", "condition": "action.type == 'read'",
             "action": "deny", "priority": 10}


def _call(client, policy, agent="research-agent"):
    return client.post("/tools/call", json={
        "tool_name": "db_query", "action": "read",
        "agent_id": agent, "policy_name": policy,
    }).json()


def test_parent_edit_is_enforced_through_the_child(client):
    """The regression: the child was compiled before the parent changed."""
    assert _policy(client, "base").status_code == 200
    assert _policy(client, "child", extends=["base"]).status_code == 200

    # Warm the cache: this is what used to go stale.
    assert _call(client, "child")["allowed"] is True

    assert _policy(client, "base", rules=[DENY_READ],
                   method="put").status_code == 200

    denied = _call(client, "child")
    assert denied["allowed"] is False, "child kept enforcing the pre-edit merge"
    assert denied["denied_by"] == "policy"
    assert denied["rule"] == "no-read"


def test_parent_edit_reaches_a_grandchild(client):
    _policy(client, "base")
    _policy(client, "child", extends=["base"])
    _policy(client, "grandchild", extends=["child"])
    assert _call(client, "grandchild")["allowed"] is True

    _policy(client, "base", rules=[DENY_READ], method="put")

    denied = _call(client, "grandchild")
    assert denied["allowed"] is False
    assert denied["rule"] == "no-read"


def test_parent_edit_evicts_the_childs_cached_callables(app_module, client):
    _policy(client, "base")
    _policy(client, "child", extends=["base"])
    _call(client, "child")
    assert any(k[1] == "child" for k in app_module._governed_tools)

    _policy(client, "base", rules=[DENY_READ], method="put")

    assert not any(k[1] == "child" for k in app_module._governed_tools), \
        "the child's compiled copy of the parent survived the parent's edit"


def test_relaxing_the_parent_also_propagates(client):
    """Eviction is not a one-way ratchet — a loosened parent propagates too."""
    _policy(client, "base", rules=[DENY_READ])
    _policy(client, "child", extends=["base"])
    assert _call(client, "child")["allowed"] is False

    _policy(client, "base", rules=[], method="put")

    assert _call(client, "child")["allowed"] is True


def test_the_edited_policy_itself_still_updates(client):
    """The original one-level eviction, still working."""
    _policy(client, "solo")
    assert _call(client, "solo")["allowed"] is True
    _policy(client, "solo", rules=[DENY_READ], method="put")
    assert _call(client, "solo")["allowed"] is False
