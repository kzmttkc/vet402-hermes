"""vet402 for Hermes: look a paid API up in vet402's public record before the agent pays it.

- Tool `vet402_check`: the model can ask about any URL.
- Hook `pre_tool_call`: before a paying tool runs (by default `mpp_fetch` from hermes-mpp),
  vet402's BLOCK stops the call, WARN sends it to the human-approval gate, ALLOW lets it run.
  Unknown sellers and vet402 outages let the call run unless VET402_UNKNOWN=approve.

Limit: hermes-mpp can also pay 402s inside core HTTPX traffic, which does not pass through
any tool. Hooks cannot see those payments; MPP_ALLOWED_ORIGINS is the control for them.
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


def before_tool(tool_name: str, args: dict, task_id: str = "", **kwargs: Any):
    if tool_name not in _guarded_tools():
        return None
    url = str((args or {}).get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None
    try:
        r = client.lookup(url, str((args or {}).get("method") or "GET"))
    except Exception:
        logger.warning("vet402: lookup failed for %s; the call runs unchecked", url)
        return None
    if r["status"] == "BLOCK":
        return {"action": "block", "message": client.describe(r) + " The payment was not made."}
    if r["status"] == "WARN":
        return {"action": "approve", "message": client.describe(r) + " Approve to pay anyway."}
    if r["status"] in ("unknown", "unavailable"):
        if os.environ.get("VET402_UNKNOWN", "allow").strip().lower() == "approve":
            return {"action": "approve", "message": client.describe(r) + " Approve to pay anyway."}
        logger.info("vet402: %s", client.describe(r))
    return None


def register(ctx: Any) -> None:
    ctx.register_tool(name="vet402_check", toolset="vet402", schema=SCHEMA, handler=vet402_check)
    ctx.register_hook("pre_tool_call", before_tool)
