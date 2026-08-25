"""Single-container packaging: the backend can serve a built frontend.

The container sets AGT_STATIC_DIR so the API and the dashboard share one origin.
The mount must serve index.html at the root without shadowing any API route, and
must stay off in dev/tests (no AGT_STATIC_DIR), which the whole suite relies on.
"""
from fastapi import FastAPI
from starlette.testclient import TestClient

import main


def test_mount_returns_false_without_a_build(tmp_path):
    app = FastAPI()
    assert main._mount_spa(app, str(tmp_path / "does-not-exist")) is False


def test_spa_is_served_without_shadowing_the_api(tmp_path):
    app = FastAPI()

    @app.get("/stats")
    def stats():
        return {"ok": True}

    (tmp_path / "index.html").write_text("<html>AGT Dashboard</html>", encoding="utf-8")
    assert main._mount_spa(app, str(tmp_path)) is True

    client = TestClient(app)
    # The API route registered before the mount still resolves.
    assert client.get("/stats").json() == {"ok": True}
    # The SPA is served at the root.
    assert "AGT Dashboard" in client.get("/").text


def test_default_app_has_no_spa_mount():
    # With AGT_STATIC_DIR unset (the test environment), nothing is mounted, so
    # the API owns the root path and the rest of the suite is unaffected.
    assert not any(getattr(r, "name", None) == "spa" for r in main.app.router.routes)
