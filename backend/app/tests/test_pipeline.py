"""End to end: upload the four test log files and check the whole story comes out right."""


from app.tests.conftest import upload_test_logs


def _load_demo(client):
    return upload_test_logs(client)


def test_demo_data_creates_alerts_from_every_module(client):
    uploads = _load_demo(client)
    assert {u["source_type"] for u in uploads} == {"auth_log", "web_log", "network_log", "url_list"}
    detectors = {a["detector"] for a in client.get("/api/alerts?limit=200").json()}
    assert {"login", "port_scan", "web_attack", "honeytoken", "phishing"} <= detectors


def test_primary_correlation_then_networkx_merge(client):
    _load_demo(client)
    before = client.get("/api/incidents").json()
    big = max(before, key=lambda i: i["risk_score"])
    assert big["risk_tier"] == "Malicious"

    res = client.post("/api/jobs/graph").json()
    assert res["merged"] >= 1                         # the sqlmap user agent links the two IPs
    after = client.get("/api/incidents").json()
    assert len(after) < len(before)
    merged = [i for i in after if i["correlation_method"] == "networkx_batch"]
    assert merged
    m = merged[0]
    assert len(m["related_entities"]["ips"]) >= 3     # .45, .9 and .88 are one campaign now
    assert any(a["detector"] == "honeytoken" for a in m["linked_alerts"])
    assert "honeytoken" in m["incident_narrative"].lower()
    assert m["explanation"]


def test_manual_response_flow(client):
    _load_demo(client)
    client.post("/api/jobs/graph")
    inc = max(client.get("/api/incidents").json(), key=lambda i: i["risk_score"])
    assert inc["response_mode"] is None
    r = client.post(f"/api/incidents/{inc['incident_id']}/respond", json={"action_type": "BLOCK_IP"})
    assert r.status_code == 200 and r.json()["mode"] == "manual"
    detail = client.get(f"/api/incidents/{inc['incident_id']}").json()
    assert detail["status"] == "contained" and detail["response_mode"] == "manual"
    assert len(client.get("/api/blocklist").json()) >= 3


def test_auto_response_toggle(client):
    assert client.get("/api/settings").json()["auto_response_enabled"] is False
    client.put("/api/settings/auto-response", json={"enabled": True})
    _load_demo(client)
    incs = client.get("/api/incidents").json()
    auto = [i for i in incs if i["response_mode"] == "auto"]
    assert auto, "with auto mode on, Malicious incidents are handled without a click"
    assert all(i["risk_score"] >= 71 for i in auto)
    assert client.get("/api/blocklist").json()


def test_manual_mode_leaves_incidents_waiting(client):
    _load_demo(client)
    assert all(i["response_mode"] is None for i in client.get("/api/incidents").json())


def test_false_positive_logs_feedback(client):
    _load_demo(client)
    inc = client.get("/api/incidents").json()[0]
    client.post(f"/api/incidents/{inc['incident_id']}/respond", json={"action_type": "MARK_FALSE_POSITIVE"})
    d = client.get(f"/api/incidents/{inc['incident_id']}").json()
    assert d["status"] == "false_positive" and d["analyst_feedback"]["verdict"] == "false_positive"


def test_decay_job_fast_forward(client):
    _load_demo(client)
    before = {i["incident_id"]: i["risk_score"] for i in client.get("/api/incidents").json()}
    changed = client.post("/api/jobs/decay?hours_ahead=24").json()["incidents_changed"]
    assert changed >= 1
    after = client.get("/api/incidents").json()
    assert all(i["risk_score"] <= before[i["incident_id"]] for i in after)
    dropped = [i for i in after if i["decay_history"]]
    assert dropped and dropped[0]["base_risk_score"] > dropped[0]["risk_score"]


def test_dashboard_stats(client):
    _load_demo(client)
    s = client.get("/api/stats/dashboard").json()
    assert s["total_events"] > 100 and s["total_alerts"] > 5
    assert set(s["risk_tier_distribution"]) == {"Safe", "Suspicious", "Malicious"}
    assert abs(sum(v["percent"] for v in s["alerts_by_type"].values()) - 100) < 1


def test_graph_component_points_to_surviving_incident_and_blocks_all_ips(client):
    _load_demo(client)
    res = client.post("/api/jobs/graph").json()
    comp = [c for c in res["components"] if c["merged"]][0]
    inc_id = comp["incident_ids"][0]
    assert client.get(f"/api/incidents/{inc_id}").status_code == 200      # not a deleted incident
    r = client.post(f"/api/incidents/{inc_id}/respond",
                    json={"action_type": "BLOCK_IP", "parameters": {"ips": comp["ips"]}})
    assert r.status_code == 200
    blocked = {b["value"] for b in client.get("/api/blocklist").json()}
    assert set(comp["ips"]) <= blocked and len(comp["ips"]) >= 3


def test_all_statuses_can_be_set(client):
    _load_demo(client)
    ids = [i["incident_id"] for i in client.get("/api/incidents").json()][:3]
    for iid, action, status in zip(ids, ["ESCALATE", "CLOSE_INCIDENT", "MARK_FALSE_POSITIVE"],
                                   ["escalated", "closed", "false_positive"]):
        assert client.post(f"/api/incidents/{iid}/respond", json={"action_type": action}).status_code == 200
        assert client.get(f"/api/incidents/{iid}").json()["status"] == status
    s = client.get("/api/stats/dashboard").json()["incident_status"]
    assert s["escalated"] == 1 and s["closed"] == 1 and s["false_positive"] == 1
