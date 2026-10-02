"""vet402 for Hermes: look a paid API up in vet402's public record before the agent pays it.

- Tool `vet402_check`: the model can ask about any URL.
- Hook `pre_tool_call`: before a paying tool runs (by default `mpp_fetch` from hermes-mpp),
  vet402's BLOCK stops the call. A WARN with evidence against the seller goes to the human-approval
  gate. ALLOW runs. Everything else (a WARN only because vet402 has not bought there yet, an unknown
  URL, a vet402 outage) runs unless VET402_UNKNOWN=approve.

Limit: hermes-mpp can also pay 402s inside core HTTPX traffic, which does not pass through
any tool. Hooks cannot see those payments. MPP_ALLOWED_ORIGINS is the control for them.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from . import client

logger = logging.getLogger(__name__)

SCHEMA = {
    "name": "vet402_check",
    "description": (
        "Before paying an x402 or MPP API, look the URL up in vet402's public record of real "
        "purchases. Returns vet402's recommendation (ALLOW, WARN or BLOCK) with the reasons, how "
        "many times vet402 paid that endpoint and how often it delivered, and a link to the evidence. "
        "Returns status 'unknown' when vet402 has never seen the URL. Read-only, free, no key."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute URL of the paid endpoint."},
            "method": {"type": "string", "description": "HTTP method, default GET."},
        },
        "required": ["url"],
    },
}


def _guarded_tools() -> set[str]:
    raw = os.environ.get("VET402_GUARD_TOOLS", "mpp_fetch")
    return {t.strip() for t in raw.split(",") if t.strip()}


def vet402_check(args: dict, **kwargs: Any) -> str:
    url = str(args.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return json.dumps({"error": "url must be an absolute http(s) URL"})
    try:
        return json.dumps(client.lookup(url, str(args.get("method") or "GET")))
    except Exception as e:
        return json.dumps({"status": "unavailable", "url": url, "why": str(e)})


def _approve(r: dict, method: str) -> dict:
    # rule_key keeps Hermes's "allow for this session / always" per URL. Without it Hermes keys the
    # approval by tool name, and one approved WARN would let every later WARN pay unasked.
    return {
        "action": "approve",
        "message": client.describe(r) + " Approve to pay anyway.",
        "rule_key": f"vet402:{r.get('status')}:{method.upper()} {r.get('url')}",
    }


def before_tool(tool_name: str, args: dict, task_id: str = "", **kwargs: Any):
    if tool_name not in _guarded_tools():
        return None
    args = args or {}
    url = str(args.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None
    method = str(args.get("method") or "GET")
    try:
        r = client.lookup(url, method)
    except Exception:
        logger.warning("vet402: lookup failed for %s; the call runs unchecked", url)
        return None
    if r.get("status") == "BLOCK":
        return {"action": "block", "message": client.describe(r) + " The payment was not made."}
    if r.get("status") == "WARN" and r.get("adverse"):
        return _approve(r, method)
    # ALLOW runs. A WARN with no evidence against the seller (usually: vet402 has not bought from it
    # yet), an unknown URL and an outage follow VET402_UNKNOWN.
    if r.get("status") != "ALLOW":
        if os.environ.get("VET402_UNKNOWN", "allow").strip().lower() == "approve":
            return _approve(r, method)
        logger.info("%s", client.describe(r))
    return None


def register(ctx: Any) -> None:
    ctx.register_tool(name="vet402_check", toolset="vet402", schema=SCHEMA, handler=vet402_check)
    ctx.register_hook("pre_tool_call", before_tool)
