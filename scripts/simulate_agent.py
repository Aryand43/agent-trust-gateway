"""Command-line simulated agent that calls the protected merchant API over HTTP.

    python scripts/simulate_agent.py                # legitimate agent, then misuse attempts
    python scripts/simulate_agent.py --base-url http://localhost:8000

Uses only the standard library so it runs anywhere the server does.
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request

AUTH_ID = "auth_alex_shopping_assistant"
MERCHANT = "mer_demoshop"


def call(base: str, method: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(f"{base}{path}", method=method, headers=headers or {}, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def report(label: str, status: int, body: dict) -> None:
    g = body.get("gateway", {})
    factors = ", ".join(f"{f['code']}({f['points']:+d})" for f in g.get("risk_factors", []))
    print(f"{label:<38} HTTP {status}  {g.get('decision', '?'):<6} score={g.get('risk_score', '?'):<3} {factors}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    base = parser.parse_args().base_url.rstrip("/")

    status, issued = call(base, "POST", f"/api/authorisations/{AUTH_ID}/credentials")
    if status != 201:
        raise SystemExit(f"Could not mint credential: {issued}")
    token, cred_id = issued["token"], issued["credential"]["id"]
    print(f"Minted {cred_id} (scope={issued['claims']['scope']}); token not printed.\n")

    agent = {
        "Authorization": f"AgentCredential {token}",
        "X-Agent-Id": "agt_shopping_assistant",
        "X-User-Id": "usr_alex_tan",
        "X-Declared-Agent": "true",
        "User-Agent": "ShoppingAssistant/1.0",
        "X-Forwarded-For": "203.0.113.50",
    }
    report("search (in scope)", *call(base, "POST", f"/api/merchant/{MERCHANT}/search", agent))
    report("purchase (out of scope)", *call(base, "POST", f"/api/merchant/{MERCHANT}/purchase", agent))
    other_account = {**agent, "X-User-Id": "usr_mallory"}
    report("search on another user's account", *call(base, "POST", f"/api/merchant/{MERCHANT}/search", other_account))
    call(base, "POST", f"/api/credentials/{cred_id}/revoke")
    report("search after revocation", *call(base, "POST", f"/api/merchant/{MERCHANT}/search", agent))
    scraper = {"User-Agent": "python-requests/2.31", "X-Forwarded-For": "198.51.100.77"}
    for i in range(12):
        result = call(base, "POST", f"/api/merchant/{MERCHANT}/browse", {**scraper, "X-User-Id": f"usr_c{i}"})
    report("scraper burst (12 req, final)", *result)


if __name__ == "__main__":
    main()
