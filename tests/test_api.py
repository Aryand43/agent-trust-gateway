"""End-to-end tests through the HTTP API."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.services.scenarios import SCENARIOS


def test_health(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["demo_only"] is True


def test_full_authorisation_flow(client: TestClient) -> None:
    user = client.post("/api/users", json={"name": "Sam Lee", "email": "sam@example.com"}).json()
    merchant = client.post("/api/merchants", json={"name": "Acme"}).json()
    agent = client.post("/api/agents", json={"name": "Helper", "id": "agt_helper"}).json()

    res = client.post("/api/authorisations", json={
        "user_id": user["id"], "merchant_id": merchant["id"], "agent_id": agent["id"],
        "scopes": ["browse", "search"], "ttl_seconds": 300,
    })
    assert res.status_code == 201
    issued = res.json()["issued"]
    token, cred_id = issued["token"], issued["credential"]["id"]
    assert set(issued["claims"]) >= {"cid", "sub", "mid", "aid", "iat", "exp", "scope"}
    assert issued["claims"]["exp"] - issued["claims"]["iat"] == 300

    payload = {
        "credential": token, "merchant_id": merchant["id"], "user_id": user["id"], "agent_id": agent["id"],
        "action": "search", "ip_address": "203.0.113.7", "user_agent": "Helper/1.0", "declared_agent": True,
        "metadata": {"q": "shoes"},
    }
    ok = client.post("/api/gateway/evaluate", json=payload).json()
    assert ok["decision"] == "allow" and ok["event_id"].startswith("evt_")
    assert 0 <= ok["risk_score"] <= 100

    denied = client.post("/api/gateway/evaluate", json={**payload, "action": "purchase"}).json()
    assert denied["decision"] == "review"

    revoked = client.post(f"/api/credentials/{cred_id}/revoke", json={"reason": "user request"})
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert client.post(f"/api/credentials/{cred_id}/revoke").status_code == 409

    blocked = client.post("/api/gateway/evaluate", json=payload).json()
    assert blocked["decision"] == "block" and blocked["credential_status"] == "revoked"

    events = client.get("/api/events").json()
    assert [e["id"] for e in events[:3]] == [blocked["event_id"], denied["event_id"], ok["event_id"]]
    detail = client.get(f"/api/events/{blocked['event_id']}").json()
    assert any(f["code"] == "credential_revoked" for f in detail["risk_factors"])

    creds = client.get("/api/credentials", params={"status": "revoked"}).json()
    assert [c["id"] for c in creds] == [cred_id]

    summary = client.get("/api/dashboard/summary").json()
    assert (summary["total_requests"], summary["allowed"], summary["review"], summary["blocked"]) == (3, 1, 1, 1)
    assert summary["revoked_credentials"] == 1


def test_token_is_never_persisted_in_events(client: TestClient) -> None:
    client.post("/api/users", json={"name": "A", "id": "usr_a"})
    client.post("/api/merchants", json={"name": "M", "id": "mer_m"})
    client.post("/api/agents", json={"name": "G", "id": "agt_g"})
    token = client.post("/api/authorisations", json={
        "user_id": "usr_a", "merchant_id": "mer_m", "agent_id": "agt_g", "scopes": ["browse"]}).json()["issued"]["token"]
    client.post("/api/gateway/evaluate", json={"credential": token, "merchant_id": "mer_m", "action": "browse",
                                               "ip_address": "10.0.0.1"})
    assert token not in client.get("/api/events").text
    assert token not in client.get("/api/credentials").text


def test_validation_errors_use_envelope(client: TestClient) -> None:
    res = client.post("/api/gateway/evaluate", json={"merchant_id": "x", "action": "delete", "ip_address": "nope"})
    assert res.status_code == 422
    err = res.json()["error"]
    assert err["code"] == "validation_error"
    assert {tuple(d["loc"])[-1] for d in err["details"]} >= {"action", "ip_address"}


def test_unknown_resources_404(client: TestClient) -> None:
    assert client.post("/api/credentials/cred_missing/revoke").json()["error"]["code"] == "not_found"
    res = client.post("/api/authorisations", json={"user_id": "usr_x", "merchant_id": "mer_x",
                                                   "agent_id": "agt_x", "scopes": ["browse"]})
    assert res.status_code == 404
    res = client.post("/api/gateway/evaluate", json={"merchant_id": "mer_nope", "action": "browse", "ip_address": "10.0.0.1"})
    assert res.status_code == 404


def test_seed_data(seeded_client: TestClient) -> None:
    c = seeded_client
    assert [m["name"] for m in c.get("/api/merchants").json()] == ["DemoShop"]
    assert [u["name"] for u in c.get("/api/users").json()] == ["Alex Tan"]
    assert [a["name"] for a in c.get("/api/agents").json()] == ["Shopping Assistant"]
    auths = c.get("/api/authorisations").json()
    assert len(auths) == 1 and auths[0]["scopes"] == ["browse", "search"]
    decisions = {e["decision"] for e in c.get("/api/events?limit=200").json()}
    assert decisions == {"allow", "review", "block"}


def test_every_demo_scenario_matches_expected_decision(seeded_client: TestClient) -> None:
    for key, info in SCENARIOS.items():
        res = seeded_client.post(f"/api/demo/scenarios/{key}")
        assert res.status_code == 200, key
        assert res.json()["final"]["decision"] == info.expected, key
    assert seeded_client.post("/api/demo/scenarios/nope").status_code == 404


def test_protected_merchant_endpoint_enforces_decision(seeded_client: TestClient) -> None:
    c = seeded_client
    token = c.post("/api/authorisations/auth_alex_shopping_assistant/credentials").json()["token"]
    headers = {"Authorization": f"AgentCredential {token}", "X-Agent-Id": "agt_shopping_assistant",
               "X-User-Id": "usr_alex_tan", "X-Declared-Agent": "true", "User-Agent": "ShoppingAssistant/1.0",
               "X-Forwarded-For": "203.0.113.99"}
    ok = c.post("/api/merchant/mer_demoshop/search", headers=headers)
    assert ok.status_code == 200 and ok.json()["data"]["items"]
    assert c.post("/api/merchant/mer_demoshop/purchase", headers=headers).status_code == 428
    bad = {**headers, "Authorization": "AgentCredential atg1.bogus.token"}
    assert c.post("/api/merchant/mer_demoshop/search", headers=bad).status_code == 403


def test_public_key_endpoint(client: TestClient) -> None:
    body = client.get("/api/keys/public").json()
    assert body["alg"] == "Ed25519" and "BEGIN PUBLIC KEY" in body["public_key_pem"]
    assert "PRIVATE" not in body["public_key_pem"]
