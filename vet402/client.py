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
CACHE_S = 300  # the API may also reuse a decision for up to 5 minutes, so an answer can be 10 minutes old

# Reason codes that are evidence against the seller (vet402 rules 2026-09-29.4). A WARN without one of
# these usually means vet402 has not bought from the endpoint yet, which is not a finding.
ADVERSE = {
    "l0_unverified_single_fail": "its 402 failed vet402's latest check",
    "l1_paid_not_delivered": "vet402 paid and got nothing back",
    "l1_never_delivered": "it has never delivered to vet402",
    "l1_latest_failed": "vet402's latest purchase failed",
    "l1_empty_2xx_settlement_unknown": "it answered with an empty success and the payment could not be confirmed",
    "l2_mismatch_unexplained": "its answer did not match what it declares",
    "l0_fail": "its 402 offer failed vet402's checks",
}

_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


def bare_url(url: str) -> str:
    """Drop the query string and fragment (they can carry search terms or keys) and lower-case the host."""
    p = urllib.parse.urlsplit(url.strip())
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))


def _get(path: str) -> dict[str, Any]:
    req = urllib.request.Request(API + path, headers={"Accept": "application/json", "User-Agent": "vet402-hermes/0.1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # A resolve miss answers 404 with a JSON body. Anything else is an outage or a rate limit.
        if e.code == 404 and path.startswith("/api/v1/resolve"):
            return json.loads(e.read().decode("utf-8") or "{}")
        raise


def _fetch(url: str) -> dict[str, Any]:
    resolved = _get("/api/v1/resolve?q=" + urllib.parse.quote(url, safe=""))
    res = resolved.get("resource")
    if not res:
        host_eps = resolved.get("endpoints") or []
        why = ("vet402 knows other endpoints on this host, but not this path."
               if host_eps else "vet402 has no record of this URL or its host.")
        return {"status": "unknown", "url": url, "why": why}
    d = _get(f"/api/v1/resources/{res['resource_id']}/decision?role=payer")
    rec = d.get("recommendation")
    if rec not in ("ALLOW", "WARN", "BLOCK"):
        raise ValueError("vet402 returned no recommendation")  # not cached; the caller treats it as unavailable
    l1 = (d.get("facts") or {}).get("l1") or {}
    reasons = d.get("reason_codes") or []
    return {
        "status": rec,
        "url": res.get("canonical_url") or url,
        "reasons": reasons,
        "adverse": [ADVERSE[c] for c in reasons if c in ADVERSE],
        "paid_attempts": l1.get("n_attempts"),
        "settled": l1.get("n_settled"),
        "delivered": l1.get("n_delivered"),
        "rules_version": d.get("rules_version"),
        "page": f"{API}/observatory/e/{res['observatory_id']}" if res.get("observatory_id") else None,
    }


def lookup(url: str, method: str = "GET") -> dict[str, Any]:
    """vet402's pre-payment decision for one URL, as a small stable dict.

    status: "ALLOW" | "WARN" | "BLOCK" (vet402's recommendation), "unknown" (not in vet402's
    catalog), or "unavailable" (vet402 could not be reached or gave no decision; nothing was checked).
    """
    url = bare_url(url)
    key = (method.upper(), url)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_S:
            return hit[1]
    try:
        out = _fetch(url)
    except Exception as e:  # network, rate limit, JSON, or an unexpected shape
        return {"status": "unavailable", "url": url, "why": f"vet402 gave no decision ({type(e).__name__})."}
    with _lock:
        _cache[key] = (now, out)
    return out


def describe(r: dict[str, Any]) -> str:
    """One line a person can read in an approval prompt."""
    s = r.get("status", "unavailable")
    url = r.get("url", "")
    if s not in ("ALLOW", "WARN", "BLOCK"):
        return f"vet402: {r.get('why', 'vet402 gave no decision.')} ({url})"
    parts = [f"vet402 says {s} for {url}."]
    n = r.get("paid_attempts")
    if n:
        times = "once" if n == 1 else f"{n} times"
        parts.append(f"vet402 paid it {times}: {r.get('settled') or 0} settled, {r.get('delivered') or 0} delivered.")
    elif s == "WARN":
        parts.append("vet402 has not bought from it yet.")
    if r.get("adverse"):
        parts.append("Why: " + ", ".join(r["adverse"]) + ".")
    if r.get("page"):
        parts.append(f"Evidence: {r['page']}")
    return " ".join(parts)
