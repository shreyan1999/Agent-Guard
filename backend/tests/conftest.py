"""Shared fixtures.

Every test gets a freshly-seeded process: `main.reset_state()` rebuilds each
module-level store, so a test that suspends an agent or rewrites a trust score
cannot leak into the next one.

Policies are file-backed, so the suite points AGT_POLICY_DIR at a temp
directory *before* importing the app — the store is constructed at import time,
and pointing it at the real `backend/policies/` would let tests scribble on a
developer's saved policies.

The app is driven without entering TestClient as a context manager. Entering it
runs the lifespan, which seeds a *second* set of demo agents on top of the ones
the fixture just created.
"""

import os
import sys
import tempfile
import warnings
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# Silence only AGT's package-consolidation DeprecationWarning (see main.py);
# genuine deprecations from elsewhere stay visible in test output.
warnings.filterwarnings(
    "ignore",
    message=r".*is deprecated\. Use agent-governance-toolkit-",
)

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))

# Must precede `import main`: PolicyStore is built at module scope.
_POLICY_DIR = tempfile.mkdtemp(prefix="agt-test-policies-")
os.environ["AGT_POLICY_DIR"] = _POLICY_DIR

import main  # noqa: E402


@pytest.fixture
def app_module():
    """The backend module, freshly seeded and torn down after the test."""
    main.reset_state()
    yield main
    main.teardown_state(clear_policies=True)


@pytest.fixture
def client(app_module):
    """A TestClient over the freshly-seeded app."""
    return TestClient(app_module.app)


@pytest.fixture
def policy_dir():
    """The temp directory backing the policy store during tests."""
    return Path(_POLICY_DIR)


@pytest.fixture(scope="session")
def frontend_src():
    """Path to the frontend source, for tests that check UI claims."""
    return REPO / "frontend" / "src"
