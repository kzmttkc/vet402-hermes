"""Read vet402's public decision for a paid URL. Standard library only, no key."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = os.environ.get("VET402_API", "https://vet402.com").rstrip("/")
TIMEOUT_S = float(os.environ.get("VET402_TIMEOUT_S", "6"))
CACHE_S = 300  # the API itself reuses a decision for up to 5 minutes

_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


def _get(path: str) -> dict[str, Any]:
    req = urllib.request.Request(API + path, headers={"Accept": "application/json", "User-Agent": "vet402-hermes/0.1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 404 bodies are JSON too (an unknown resource); anything else is an outage.
        if e.code == 404:
            return json.loads(e.read().decode("utf-8") or "{}")
        raise


def lookup(url: str, method: str = "GET") -> dict[str, Any]:
    """Return a small, stable summary of vet402's pre-payment decision for one URL.

    status: "ALLOW" | "WARN" | "BLOCK" (vet402's recommendation), "unknown" (not in
    vet402's catalog), or "unavailable" (vet402 could not be reached; nothing was checked).
    """
    key = (method.upper(), url)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_S:
            return hit[1]
    try:
        resolved = _get("/api/v1/resolve?q=" + urllib.parse.quote(url, safe=""))
        res = resolved.get("resource")
        if not res:
            out = {"status": "unknown", "url": url,
                   "why": (resolved.get("not_found") or {}).get("note") or "vet402 has no record of this URL."}
        else:
            d = _get(f"/api/v1/resources/{res['resource_id']}/decision?role=payer")
            l1 = (d.get("facts") or {}).get("l1") or {}
            out = {
                "status": d.get("recommendation") or "unavailable",
                "url": res.get("canonical_url") or url,
                "reasons": d.get("reason_codes") or [],
                "paid_attempts": l1.get("n_attempts"),
                "settled": l1.get("n_settled"),
                "delivered": l1.get("n_delivered"),
                "rules_version": d.get("rules_version"),
                "page": f"{API}/observatory/e/{res['observatory_id']}" if res.get("observatory_id") else None,
            }
    except Exception as e:  # network, JSON, or an unexpected shape
        return {"status": "unavailable", "url": url, "why": f"vet402 could not be reached ({type(e).__name__})."}
    with _lock:
        _cache[key] = (now, out)
    return out


def describe(r: dict[str, Any]) -> str:
    """One line a person can read in an approval prompt."""
    s = r["status"]
    if s in ("unknown", "unavailable"):
        return f"vet402: {r['why']} ({r['url']})"
    counts = ""
    if r.get("paid_attempts"):
        n = r["paid_attempts"]
        times = "once" if n == 1 else f"{n} times"
        counts = f" vet402 paid it {times}: {r.get('settled') or 0} settled, {r.get('delivered') or 0} delivered."
    reasons = ", ".join(r.get("reasons") or []) or "none"
    page = f" Details: {r['page']}" if r.get("page") else ""
    return f"vet402 says {s} for {r['url']}.{counts} Reasons: {reasons}.{page}"
