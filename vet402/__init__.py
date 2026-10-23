"""vet402 for Hermes: look a paid API up in vet402's public record before the agent pays it.

- Tool `vet402_check`: the model can ask about any URL.
- Hook `pre_tool_call`: before a paying tool runs (by default `mpp_fetch` from hermes-mpp),
  the hook reads the record for that URL and that HTTP method.
  ALLOW for that method runs. BLOCK stops the call.
  WARN runs only for the reason code l1_not_attempted (vet402 has not bought there yet).
  Every other WARN, a missing record, an unknown status, and an outage ask a person.
  yolo, approvals off, cron, and any session with nobody to answer deny the call instead.
  VET402_UNKNOWN=allow is the only opt-in that lets a missing record or an outage pay.
  A redirect or an HTTP 400 is not an outage. Those still ask, or deny when nobody can answer.

Limit: hermes-mpp can also pay 402s inside core HTTPX traffic, which does not pass through
any tool. Hooks cannot see those payments. MPP_ALLOWED_ORIGINS is the control for them.
The hook reads the paid address from url, uri, endpoint or any other URL argument.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path
from typing import Any

from . import client

logger = logging.getLogger(__name__)

_SKILL_DESCRIPTION = (
    "Check a seller in vet402 before paying, buying, or calling a paid API. "
    "Use this when asked whether to pay, whether the seller delivered, or to look up a paid URL before paying."
)

SCHEMA = {
    "name": "vet402_check",
    "description": (
        "Check before paying, to buy, or to call a paid API: should you pay this seller, and has it delivered. "
        "Looks the URL up in vet402's public record of real purchases. "
        "Returns ALLOW, WARN, or BLOCK with the reasons, how many times vet402 paid that endpoint and how often it delivered, "
        "and a link to the evidence. Returns status unknown when vet402 has no record for that method. "
        "Read-only, free, no key."
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

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_UNATTENDED_PLATFORMS = frozenset({"webhook", "msgraph_webhook", "api_server"})
_APPROVAL_KEYS = ("mode", "cron_mode", "single_query_mode", "unattended_mode")


_warned_empty_guard = False


def _guarded_tools() -> set[str]:
    global _warned_empty_guard
    raw = os.environ.get("VET402_GUARD_TOOLS", "mpp_fetch")
    tools = {t.strip() for t in raw.split(",") if t.strip()}
    if not tools and not _warned_empty_guard:
        _warned_empty_guard = True
        logger.warning("vet402: VET402_GUARD_TOOLS is empty, so no tool call is checked before it pays")
    return tools


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUTHY


def _loaded(name: str) -> Any:
    """A Hermes module only when the host already imported it. Do not import it from here."""
    return sys.modules.get(name)


def _call_loaded(module: str, fn_name: str) -> Any:
    mod = _loaded(module)
    fn = getattr(mod, fn_name, None) if mod is not None else None
    if fn is None:
        return None
    try:
        return fn()
    except Exception:
        return None


def _yolo() -> bool:
    if _truthy(os.environ.get("HERMES_YOLO_MODE")):
        return True
    mod = _loaded("tools.approval")
    fn = getattr(mod, "_yolo_active", None) if mod is not None else None
    if fn is None:
        return False
    try:
        return bool(fn())
    except Exception:
        # If the host's yolo flag cannot be read, do not ask. Asking would pay under yolo.
        return True


def _approval_mode() -> str:
    """'off' when Hermes would skip the prompt. Empty when this process cannot tell."""
    loaded = _call_loaded("tools.approval_context", "_get_approval_mode")
    if isinstance(loaded, str) and loaded:
        return loaded.strip().lower()
    return _approval_mode_from_home()


def _approval_mode_from_home() -> str:
    """Read approvals.mode from $HERMES_HOME/config.yaml and nothing else.

    An unset HERMES_HOME is not looked up, so the default home is never opened.
    A config path that resolves outside that home is not opened.
    """
    home_raw = os.environ.get("HERMES_HOME", "").strip()
    if not home_raw:
        return ""
    home = Path(home_raw)
    try:
        home_resolved = home.resolve()
    except OSError:
        return ""
    path = home_resolved / "config.yaml"
    try:
        if not path.is_file():
            return ""
        resolved = path.resolve()
    except OSError:
        return ""
    if resolved != home_resolved and home_resolved not in resolved.parents:
        return ""
    try:
        return _parse_approval_mode(_iter_config_lines(resolved))
    except OSError:
        return ""


def _iter_config_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= 4000:
                break
            if len(line) > 200:
                continue
            yield line


def _indent(line: str) -> int:
    expanded = line.expandtabs(2)
    return len(expanded) - len(expanded.lstrip(" "))


def _yaml_word(value: str) -> str:
    text = value.split("#", 1)[0].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1].strip()
    return text.lower()


def _parse_approval_mode(lines) -> str:
    in_block = False
    block_indent = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent(line)
        if not in_block:
            if stripped == "approvals:" or stripped.startswith("approvals:"):
                rest = stripped[len("approvals:"):].strip()
                if rest.startswith("{") and rest.endswith("}"):
                    return _mode_from_inline(rest)
                in_block = True
                block_indent = indent
            continue
        if indent <= block_indent:
            return ""
        name, sep, value = stripped.partition(":")
        if sep and name.strip() in _APPROVAL_KEYS and name.strip() == "mode":
            word = _yaml_word(value)
            if word in {"off", "false", "no"}:
                return "off"
            return word
    return ""


def _mode_from_inline(body: str) -> str:
    inner = body[1:-1]
    for part in inner.split(","):
        name, sep, value = part.partition(":")
        if sep and name.strip() == "mode":
            word = _yaml_word(value)
            return "off" if word in {"off", "false", "no"} else word
    return ""


def _cron() -> bool:
    loaded = _call_loaded("tools.approval_context", "_is_cron_approval_context")
    if loaded is not None:
        return bool(loaded)
    return _truthy(os.environ.get("HERMES_CRON_SESSION"))


def _single_query() -> bool:
    loaded = _call_loaded("tools.approval_context", "_is_single_query_approval_context")
    if loaded is not None:
        return bool(loaded)
    return _truthy(os.environ.get("HERMES_SINGLE_QUERY_SESSION"))


def _kanban() -> bool:
    return bool(os.environ.get("HERMES_KANBAN_TASK", "").strip())


def _platform() -> str:
    loaded = _call_loaded("tools.approval_context", "_get_session_platform")
    if isinstance(loaded, str) and loaded.strip():
        return loaded.strip().lower()
    session = os.environ.get("HERMES_SESSION_PLATFORM", "").strip().lower()
    if session:
        return session
    # Older name. Only an unattended value counts, so a desktop label cannot look like a person is here.
    other = os.environ.get("HERMES_PLATFORM", "").strip().lower()
    if other in _UNATTENDED_PLATFORMS:
        return other
    return ""


def _interactive() -> bool:
    loaded = _call_loaded("tools.approval_context", "_is_interactive_cli")
    if loaded is not None:
        return bool(loaded)
    return _truthy(os.environ.get("HERMES_INTERACTIVE"))


def _gateway() -> bool:
    loaded = _call_loaded("tools.approval_context", "_is_gateway_approval_context")
    if loaded is not None:
        return bool(loaded)
    if _cron() or _platform() in _UNATTENDED_PLATFORMS:
        return False
    return _truthy(os.environ.get("HERMES_GATEWAY_SESSION")) or _truthy(os.environ.get("HERMES_EXEC_ASK"))


def person_can_answer() -> bool:
    """False when Hermes would turn an approve action into a payment with nobody asked."""
    if _yolo() or _approval_mode() == "off":
        return False
    if _cron() or _single_query() or _kanban() or _platform() in _UNATTENDED_PLATFORMS:
        return False
    if _interactive() or _gateway():
        return True
    platform = _platform()
    return bool(platform) and platform not in _UNATTENDED_PLATFORMS


def why_nobody() -> str:
    if _yolo():
        return "HERMES_YOLO_MODE is on, so a prompt would be skipped."
    if _approval_mode() == "off":
        return "Approvals are off, so a prompt would be skipped."
    if _cron():
        return "This is a cron session, so nobody is here to approve it."
    if _single_query():
        return "This is a single query session, so nobody is here to approve it."
    if _kanban():
        return "This is a kanban session, so nobody is here to approve it."
    if _platform() in _UNATTENDED_PLATFORMS:
        return "This session has no person to approve a payment."
    return "Nobody is here to approve a payment."


def _explicit_allow() -> bool:
    return os.environ.get("VET402_UNKNOWN", "").strip().lower() == "allow"


def _http_url(value: Any) -> str:
    """An absolute http(s) URL with the scheme lowercased, or "". HTTPS://x and https://x pay the same seller,
    so the scheme is compared without case (2026-10-24 review: an uppercase scheme skipped the hook)."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return ""
    return urlunsplit((parts.scheme.lower(),) + tuple(parts[1:]))


def vet402_check(args: dict, **kwargs: Any) -> str:
    url = _http_url((args or {}).get("url"))
    if not url:
        return json.dumps({"error": "url must be an absolute http(s) URL"})
    try:
        return json.dumps(client.lookup(url, str((args or {}).get("method") or "GET")))
    except Exception as exc:
        return json.dumps({"status": "unavailable", "url": url,
                           "why": f"vet402 gave no decision ({type(exc).__name__})."})


def _ask(r: dict, method: str) -> dict:
    # rule_key keeps Hermes's "allow for this session / always" per method and URL.
    # Without it Hermes keys the approval by tool name, and one approved WARN would let every later WARN pay.
    return {
        "action": "approve",
        "message": client.describe(r, method) + " Refusing pays nothing.",
        # The reason codes are part of the key, so an "always" given for one WARN does not cover a later,
        # different WARN on the same URL (2026-10-24 review).
        "rule_key": f"vet402:{r.get('status')}:{','.join(sorted(str(c) for c in (r.get('adverse') or [])))}:{method} {r.get('url')}",
    }


def _deny(r: dict, method: str, *, unattended: bool) -> dict:
    message = client.describe(r, method)
    if unattended:
        message += " " + why_nobody()
    message += " The payment was not made."
    return {"action": "block", "message": message}


_URL_KEYS = ("url", "uri", "endpoint", "href", "target", "resource", "link")


def _paid_url(args: dict) -> str:
    """The URL a guarded tool is about to pay. A guarded tool may name it url, uri, endpoint and so on,
    so the known keys come first and then any other top-level string that is an http(s) URL (2026-10-24 audit, hole 8)."""
    for key in _URL_KEYS:
        url = _http_url(args.get(key))
        if url:
            return url
    for value in args.values():
        url = _http_url(value)
        if url:
            return url
    return ""


def before_tool(tool_name: str, args: dict, task_id: str = "", **kwargs: Any):
    if tool_name not in _guarded_tools():
        return None
    try:
        return _check(tool_name, args)
    except Exception as exc:
        # Anything this hook did not expect refuses the payment instead of letting it run unchecked.
        logger.warning("vet402: the check failed (%s)", type(exc).__name__)
        return {"action": "block",
                "message": f"vet402 could not check this call ({type(exc).__name__}). The payment was not made."}


def _check(tool_name: str, args: Any):
    if not isinstance(args, dict):
        args = {}
    url = _paid_url(args)
    if not url:
        return None
    method = str(args.get("method") or "GET")
    try:
        record = client.lookup(url, method)
    except Exception as exc:
        logger.warning("vet402: lookup failed (%s)", type(exc).__name__)
        record = {"status": "unavailable", "url": url, "method": method,
                  "why": f"vet402 gave no decision ({type(exc).__name__})."}
    status = record.get("status")
    paying = (record.get("method") or method or "GET")
    paying = paying.strip().upper() if isinstance(paying, str) else "GET"
    if status == "ALLOW":
        return None
    if status == "BLOCK":
        return _deny(record, paying, unattended=False)
    if status == "WARN" and client.only_not_bought(record):
        return None
    # allow is an explicit opt-in for a missing record or an outage only.
    # It does not let a WARN, a BLOCK, or a status outside the list pay.
    if _explicit_allow() and status in ("unknown", "unavailable"):
        logger.info("%s", client.describe(record, paying))
        return None
    if person_can_answer():
        return _ask(record, paying)
    return _deny(record, paying, unattended=True)


def register(ctx: Any) -> None:
    ctx.register_tool(name="vet402_check", toolset="vet402", schema=SCHEMA, handler=vet402_check)
    ctx.register_hook("pre_tool_call", before_tool)
    skill = Path(__file__).with_name("SKILL.md")
    register_skill = getattr(ctx, "register_skill", None)
    if register_skill is not None and skill.is_file():
        register_skill("vet402", skill, description=_SKILL_DESCRIPTION)
