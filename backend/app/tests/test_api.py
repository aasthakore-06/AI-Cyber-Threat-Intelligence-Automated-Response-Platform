from fastapi.testclient import TestClient
from app.main import app


def test_health_is_open():
    assert TestClient(app).get("/api/health").json()["status"] == "healthy"


def test_login_and_protected_routes():
    c = TestClient(app)
    assert c.get("/api/alerts").status_code == 401
    assert c.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    tok = c.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
    assert c.get("/api/alerts", headers={"Authorization": f"Bearer {tok}"}).status_code == 200


def test_phishing_endpoint_creates_alert(client):
    r = client.post("/api/detect/phishing-url", json={"url": "http://192.168.1.105/login/bank-verify.php"})
    assert r.status_code == 200 and r.json()["alert_generated"] is True


def test_login_events_must_come_from_log_upload(client):
    r = client.post("/api/events/ingest", json={"event_type": "login_attempt", "source_ip": "1.1.1.1", "user_id": "x"})
    assert r.status_code == 422


def test_upload_auth_log_file(client):
    log = "\n".join(
        f"Oct 14 10:00:{i:02d} web01 sshd[1]: Failed password for root from 198.51.100.45 port 40{i:02d} ssh2"
        for i in range(10))
    r = client.post("/api/upload/auth-log", files={"file": ("auth.log", log, "text/plain")})
    assert r.status_code == 200
    body = r.json()
    assert body["lines_parsed"] == 10 and body["alerts_created"] >= 1
    assert any(a["detector"] == "login" for a in client.get("/api/alerts").json())


def test_upload_rejects_wrong_file(client):
    r = client.post("/api/upload/auth-log", files={"file": ("x.log", "hello world\nnothing here", "text/plain")})
    assert r.status_code == 422
    assert client.post("/api/upload/bogus", files={"file": ("x", "y")}).status_code == 404


def test_honeytoken_webhook_is_open_and_scores_high(client):
    r = TestClient(app).post("/api/detect/honeytoken", json={"token": "HONEYTOKEN_AWS_DEV_KEY_9921", "source_ip": "7.7.7.7"})
    assert r.status_code == 200 and r.json()["alerts"] == 1
    inc = client.get("/api/incidents").json()[0]
    assert inc["risk_score"] >= 90 and inc["risk_tier"] == "Malicious"


def test_decoy_route_triggers_honeytoken(client):
    TestClient(app).get("/admin/backup-keys")
    assert any(a["detector"] == "honeytoken" for a in client.get("/api/alerts").json())
