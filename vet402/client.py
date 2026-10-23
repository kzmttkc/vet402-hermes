"""Read vet402's public decision for one paid URL and one HTTP method. Standard library only, no key."""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = os.environ.get("VET402_API", "https://vet402.com").rstrip("/")
TIMEOUT_S = float(os.environ.get("VET402_TIMEOUT_S", "6"))
CACHE_S = 300  # the API may also reuse a decision for up to 5 minutes, so an answer can be 10 minutes old

# Reason codes that are evidence against the seller (vet402 rules 2026-09-29.4).
ADVERSE = {
    "l0_unverified_single_fail": "its 402 failed vet402's latest check",
    "l1_paid_not_delivered": "vet402 paid and got nothing back",
    "l1_never_delivered": "it has never delivered to vet402",
    "l1_latest_failed": "vet402's latest purchase failed",
    "l1_empty_2xx_settlement_unknown": "it answered with an empty success and the payment could not be confirmed",
    "l2_mismatch_unexplained": "its answer did not match what it declares",
    "l0_fail": "its 402 offer failed vet402's checks",
}

# Other payer WARN codes. A WARN with one of these is not "vet402 has not bought here yet".
ASK_ALSO = {
    "l1_stale": "the purchase record is older than 30 days",
    "l0_unverified": "vet402 has not verified a live 402 for this URL",
    "l2_not_checked": "vet402 has not checked a delivery against the declared schema",
    "l1_inconclusive": "paid attempts in the window did not produce a counted result",
    "l2_mismatch": "the delivered body did not match the declared schema",
    "offer_drifting": "the price, asset, or payee changed repeatedly in a day",
    "dialect_mismatch": "the 402 version does not match the caller",
    "data_thin": "little data is behind the answer",
}

# A WARN may run only when every reason is in this set and l1_not_attempted is one of them.
# l1_not_attempted means vet402 has not signed a paid attempt. The others do not themselves warn.
NOT_BOUGHT_WITH = frozenset({"l1_not_attempted", "l1_delivered", "l2_undeclared", "l2_conform", "l0_pass"})

_DECISIONS = frozenset({"ALLOW", "WARN", "BLOCK"})
_HEX_ID = re.compile(r"^[0-9a-f]{64}$")
_OBS_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_METHOD = re.compile(r"^[A-Z]{1,10}$")

_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx from the API is not a decision. Do not request the Location."""

    def http_error_302(self, req, fp, code, msg, headers):  # noqa: ARG002
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_OPENER = urllib.request.build_opener(_NoRedirect())


class _NoDecision(Exception):
    """The check did not finish or the body had no recommendation. Not cached. status unavailable."""

    def __init__(self, why: str) -> None:
        self.why = why
        super().__init__(why)


class _RejectedStatus(Exception):
    """The API sent a recommendation outside ALLOW, WARN, and BLOCK. Not a grant, and not an outage."""

    def __init__(self, status: str, why: str) -> None:
        self.status = status
        self.why = why
        super().__init__(why)


def bare_url(url: str) -> str:
    """Keep scheme, host, port and path. Drop user:password, the query string and the fragment,
    which can carry credentials, search terms or keys."""
    p = urllib.parse.urlsplit(url.strip())
    host = (p.hostname or "") + (f":{p.port}" if p.port else "")
    return urllib.parse.urlunsplit((p.scheme.lower(), host, p.path or "/", "", ""))


def normalize_method(method: str | None) -> str | None:
    """Uppercase HTTP method name, or None when vet402 would reject it (400 invalid_method)."""
    cleaned = (method or "GET").strip().upper()
    if _METHOD.fullmatch(cleaned):
        return cleaned
    return None


def _why_for_exception(exc: BaseException) -> str:
    """Name the failure. Do not copy the exception text. It can carry a redirect target."""
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        if code in (301, 302, 303, 307, 308):
            return "vet402 redirected the lookup. Redirects are not followed, so there is no decision."
        if code == 429:
            return "vet402 rate limited the lookup (HTTP 429)."
        if code == 400:
            return "vet402 rejected the lookup (HTTP 400)."
        if code == 404:
            return "vet402 has no decision document for this record (HTTP 404)."
        return f"vet402 returned HTTP {code} for the lookup."
    if isinstance(exc, json.JSONDecodeError):
        return "vet402 returned a body that is not JSON."
    if isinstance(exc, urllib.error.URLError):
        return _why_for_url_reason(exc.reason)
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "vet402 did not answer before the timeout."
    if isinstance(exc, ConnectionRefusedError):
        return "vet402 refused the connection."
    return f"vet402 gave no decision ({type(exc).__name__})."


def _why_for_url_reason(reason: object) -> str:
    """Classify a transport failure. The returned sentence never includes the reason text."""
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "vet402 did not answer before the timeout."
    if isinstance(reason, ConnectionRefusedError):
        return "vet402 refused the connection."
    if isinstance(reason, OSError) and getattr(reason, "errno", None) == errno.ECONNREFUSED:
        return "vet402 refused the connection."
    if isinstance(reason, str):
        lowered = reason.lower()
        if "timed out" in lowered or "timeout" in lowered:
            return "vet402 did not answer before the timeout."
        if "connection refused" in lowered:
            return "vet402 refused the connection."
    return "vet402 could not be reached."


def _hard_refusal(exc: BaseException) -> bool:
    """A redirect or an HTTP 400 is not an outage the allow switch may skip.

    A 3xx can name another host. An HTTP 400 is an old API rejecting the method query.
    Neither one is a grant, and neither one is a reason to pay.
    """
    return isinstance(exc, urllib.error.HTTPError) and (300 <= exc.code < 400 or exc.code == 400)


def _read_json(response: Any) -> dict[str, Any]:
    body = response.read()
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise json.JSONDecodeError("not json", "", 0) from exc
    if not isinstance(parsed, dict):
        raise _NoDecision("vet402 gave no decision.")
    return parsed


def _get(path: str) -> dict[str, Any]:
    req = urllib.request.Request(
        API + path,
        headers={"Accept": "application/json", "User-Agent": "vet402-hermes/0.2.0"},
    )
    try:
        with _OPENER.open(req, timeout=TIMEOUT_S) as response:
            return _read_json(response)
    except urllib.error.HTTPError as exc:
        try:
            # A resolve miss answers 404 with a JSON body. Anything else is an outage or a refusal.
            # Redirects are refused by _NoRedirect and must not be read as a decision.
            if exc.code == 404 and path.startswith("/api/v1/resolve"):
                try:
                    return _read_json(exc)
                except (json.JSONDecodeError, _NoDecision):
                    return {}
            raise
        finally:
            exc.close()


def _phrases(reasons: list[Any]) -> list[str]:
    found: list[str] = []
    for code in reasons:
        if not isinstance(code, str):
            continue
        if code in ADVERSE:
            found.append(ADVERSE[code])
        elif code in ASK_ALSO:
            found.append(ASK_ALSO[code])
        elif code.startswith("l0_unverified_"):
            found.append(ASK_ALSO["l0_unverified"])
    return found


def _format_amount(amount: str, decimals: int) -> str | None:
    if not amount.isdigit() or isinstance(decimals, bool) or not isinstance(decimals, int):
        return None
    if not 0 <= decimals <= 18:
        return None
    if decimals == 0:
        whole = amount.lstrip("0") or "0"
        return whole
    if len(amount) <= decimals:
        whole, frac = "0", amount.zfill(decimals)
    else:
        whole, frac = amount[:-decimals], amount[-decimals:]
    whole = whole.lstrip("0") or "0"
    frac = frac.rstrip("0")
    return whole if not frac else f"{whole}.{frac}"


def _plain(value: object, limit: int = 80) -> str:
    """One line for a card. Drop control characters and overlong values instead of printing them."""
    if not isinstance(value, str):
        return ""
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > limit:
        return ""
    return cleaned


def _price_sentence(terms: object) -> str:
    missing = "No verified price is on record, so the amount would be whatever the seller asks."
    if not isinstance(terms, dict) or not isinstance(terms.get("amount"), str):
        return missing
    decimals = terms.get("decimals")
    shown = _format_amount(terms["amount"], decimals) if not isinstance(decimals, bool) else None
    if shown is None:
        return "vet402 sent a price that could not be read, so the amount would be whatever the seller asks."
    bits = [f"The last price vet402 verified was {shown}"]
    asset = _plain(terms.get("asset"))
    network = _plain(terms.get("network"))
    if asset:
        bits.append(f"of asset {asset}")
    if network:
        bits.append(f"on {network}")
    return " ".join(bits) + "."


def _method_matches(resource: dict[str, Any], method: str) -> bool:
    """A record counts only for its own method.

    A body with no method is the legacy GET record (the API used to answer GET, then POST,
    when the query omitted method). It is not a record for POST or any other method.
    """
    raw = resource.get("method")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return method == "GET"
    if not isinstance(raw, str):
        return False
    return raw.strip().upper() == method


def _unknown(url: str, method: str, why: str) -> dict[str, Any]:
    return {"status": "unknown", "url": url, "method": method, "reasons": [], "adverse": [], "why": why,
            "price": _price_sentence(None)}


def _fetch(url: str, method: str) -> dict[str, Any]:
    quoted = urllib.parse.quote(url, safe="")
    resolved = _get("/api/v1/resolve?q=" + quoted + "&method=" + method)
    res = resolved.get("resource")
    if not isinstance(res, dict):
        host_eps = resolved.get("endpoints") or []
        why = ("vet402 knows other endpoints on this host, but not this path."
               if host_eps else "vet402 has no record of this URL or its host.")
        return _unknown(url, method, why)
    if not _method_matches(res, method):
        return _unknown(url, method, f"vet402 has no {method} record for this URL.")
    resource_id = res.get("resource_id")
    if not isinstance(resource_id, str) or not _HEX_ID.fullmatch(resource_id):
        return _unknown(url, method, "vet402's record id was not usable, so this method has no record.")
    decision = _get(f"/api/v1/resources/{resource_id}/decision?role=payer&method={method}")
    rec = decision.get("recommendation")
    if rec not in _DECISIONS:
        shown = rec.strip() if isinstance(rec, str) else ""
        if not shown or len(shown) > 40:
            raise _NoDecision("vet402 gave no decision.")
        # Keep the raw token off the allow list. Do not call it unavailable, or an explicit
        # VET402_UNKNOWN=allow would pay on a lowercase block.
        raise _RejectedStatus(shown, f"vet402 returned {shown!r}, which is not ALLOW, WARN, or BLOCK.")
    reasons = decision.get("reason_codes") if isinstance(decision.get("reason_codes"), list) else []
    l1 = (decision.get("facts") or {}).get("l1") if isinstance(decision.get("facts"), dict) else {}
    l1 = l1 or {}
    obs = res.get("observatory_id")
    page = f"{API}/observatory/e/{obs}" if isinstance(obs, str) and _OBS_ID.fullmatch(obs) else None
    price_terms = decision.get("verified_terms") if isinstance(decision.get("verified_terms"), dict) else None
    return {
        "status": rec,
        "url": url,
        "method": method,
        "reasons": [c for c in reasons if isinstance(c, str)],
        "adverse": _phrases(reasons),
        "paid_attempts": l1.get("n_attempts"),
        "settled": l1.get("n_settled"),
        "delivered": l1.get("n_delivered"),
        "rules_version": decision.get("rules_version"),
        "page": page,
        "price": _price_sentence(price_terms),
        "why": "",
    }


def lookup(url: str, method: str = "GET") -> dict[str, Any]:
    """vet402's pre-payment decision for one URL and one method.

    status is exactly "ALLOW", "WARN", or "BLOCK" when the API said so for this method.
    "unknown" means this method has no record. "unavailable" means the check did not finish.
    A recommendation outside those three words is returned as its own status string and is not a grant.
    """
    url = bare_url(url)
    normalized = normalize_method(method)
    if normalized is None:
        return _unknown(url, (method or "").strip().upper()[:20],
                        "The HTTP method is not a name vet402 can record.")
    key = (normalized, url)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_S:
            return hit[1]
    try:
        out = _fetch(url, normalized)
    except _RejectedStatus as exc:
        return {"status": exc.status, "url": url, "method": normalized, "reasons": [], "adverse": [],
                "why": exc.why, "price": _price_sentence(None)}
    except _NoDecision as exc:
        return {"status": "unavailable", "url": url, "method": normalized, "reasons": [], "adverse": [],
                "why": exc.why, "price": _price_sentence(None)}
    except Exception as exc:
        why = _why_for_exception(exc)
        # rejected is not cached and is not an outage, so VET402_UNKNOWN=allow does not pay it.
        status = "rejected" if _hard_refusal(exc) else "unavailable"
        return {"status": status, "url": url, "method": normalized, "reasons": [], "adverse": [],
                "why": why, "price": _price_sentence(None)}
    if out.get("status") not in _DECISIONS | {"unknown"}:
        return out
    with _lock:
        _cache[key] = (now, out)
    return out


def describe(r: dict[str, Any], method: str = "") -> str:
    """One paragraph a person can read on an approval card: what, the price, and why."""
    status = r.get("status", "unavailable")
    url = r.get("url", "")
    verb = (method or r.get("method") or "").strip().upper()
    target = f"{verb} {url}".strip()
    price = r.get("price") or "No verified price is on record, so the amount would be whatever the seller asks."
    if status not in _DECISIONS:
        why = r.get("why") or "vet402 gave no decision."
        return f"About to pay {target}. {price} {why}"
    parts = [f"vet402 says {status} for {target}.", price]
    n = r.get("paid_attempts")
    if n:
        times = "once" if n == 1 else f"{n} times"
        parts.append(f"vet402 paid it {times}: {r.get('settled') or 0} settled, {r.get('delivered') or 0} delivered.")
    elif status == "WARN" and only_not_bought(r):
        parts.append("vet402 has not bought from it yet.")
    adverse = r.get("adverse") or []
    if adverse:
        parts.append("Why: " + ", ".join(str(item) for item in adverse) + ".")
    elif status == "WARN" and not only_not_bought(r):
        codes = [c for c in (r.get("reasons") or []) if isinstance(c, str)]
        if codes:
            parts.append("Why: " + ", ".join(codes) + ".")
        else:
            parts.append("Why: vet402 returned WARN without a reason code.")
    elif status != "ALLOW" and r.get("why"):
        parts.append(str(r["why"]))
    if r.get("page"):
        parts.append(f"Evidence: {r['page']}")
    return " ".join(parts)


def only_not_bought(r: dict[str, Any]) -> bool:
    reasons = [c for c in (r.get("reasons") or []) if isinstance(c, str)]
    return bool(reasons) and "l1_not_attempted" in reasons and all(c in NOT_BOUGHT_WITH for c in reasons)
