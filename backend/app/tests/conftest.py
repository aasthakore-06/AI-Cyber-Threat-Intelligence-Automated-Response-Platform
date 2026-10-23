import os
import tempfile

# use a throw-away sqlite file for tests (must be set before the app is imported)
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test_soc.db"
# decoys come from the environment, same as in docker compose
os.environ["HONEYTOKENS"] = "HONEYTOKEN_AWS_DEV_KEY_9921,decoy_admin_token_alpha,/admin/backup-keys"

import pytest
from fastapi.testclient import TestClient

from app.main import app, seed_defaults
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.db.models import SettingModel


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    init_db()
    seed_defaults()


@pytest.fixture()
def client():
    c = TestClient(app)
    token = c.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {token}"})
    c.delete("/api/admin/reset")                       # clean slate for every test
    db = SessionLocal()
    db.query(SettingModel).delete()
    db.commit()
    db.close()
    return c


from pathlib import Path

TEST_LOGS = Path(__file__).resolve().parents[3] / "test_logs"
KIND_FILES = [("network-log", "network.csv"), ("web-log", "access.log"), ("auth-log", "auth.log"), ("url-list", "urls.txt")]


def upload_test_logs(client):
    """Uploads the four files in /test_logs through the normal upload endpoint (same as the UI)."""
    out = []
    for kind, name in KIND_FILES:
        r = client.post(f"/api/upload/{kind}", files={"file": (name, (TEST_LOGS / name).read_text(), "text/plain")})
        assert r.status_code == 200, r.text
        out.append(r.json())
    return out
