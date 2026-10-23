# vet402 for Hermes

hermes-mpp can pay a 402 inside Hermes HTTPX traffic, and this plugin never sees that payment. `MPP_ALLOWED_ORIGINS` is the control for it. The hook below checks only a tool named in `VET402_GUARD_TOOLS`, and only the argument named `url`.

Before that tool pays an x402 or MPP API, the plugin looks the URL and the HTTP method up in vet402's public record of real purchases.

vet402 (https://vet402.com) buys from x402 and MPP sellers with its own USDC, checks each payment on chain, and publishes whether the seller delivered. The plugin reads that record and acts on it:

| vet402's record for this method | What happens |
|---|---|
| ALLOW | The call runs. |
| BLOCK | The call stops. Nothing is paid. |
| WARN whose reason codes are only `l1_not_attempted` plus any of `l1_delivered`, `l2_undeclared`, `l2_conform`, `l0_pass` | The call runs. `l1_not_attempted` means vet402 has not bought there yet. |
| Any other WARN, including `l1_stale`, `l0_unverified`, and `l2_not_checked` | A person is asked. Refusing pays nothing. |
| No record for this method | A person is asked. Refusing pays nothing. |
| vet402 cannot be reached (timeout, refused connection, HTTP 500, HTTP 429, or a body that is not JSON) | A person is asked. Refusing pays nothing. |
| A redirect, an HTTP 400, or a status other than ALLOW, WARN, or BLOCK | A person is asked. Refusing pays nothing. |

When nobody can answer, every row that would ask becomes a refusal and nothing is paid. That covers `HERMES_YOLO_MODE`, `approvals.mode` off, a cron session, a single query session, a kanban task, and a session with no person (`webhook`, `msgraph_webhook`, `api_server`).

Setting `VET402_UNKNOWN=allow` lets the payment run when vet402 has no record for that method or cannot be reached (timeout, refused connection, HTTP 500, HTTP 429, or a body that is not JSON), which skips the check. It does not let a redirect, an HTTP 400, a WARN, a BLOCK, or any other status pay.

## Approval card

The host card shows the tool name and the server name. The detail is in the approval message: the method, the URL with the query and userinfo removed, the price on record or the fact that no verified price is on record, and why the question is being asked (which record is missing, or which state came back). Refusing pays nothing, and `mpp_fetch` does not run.

## Install

```bash
hermes plugins install vet402
hermes plugins enable vet402
```

No key and no wallet. The manifest asks for Hermes 0.19.0 or newer. That floor was not re-run for this release.

## What it adds

- **`pre_tool_call` hook.** It runs before a tool listed in `VET402_GUARD_TOOLS`. The default list is `mpp_fetch` from [hermes-mpp](https://github.com/tempoxyz/hermes-mpp). The hook checks the paid address whatever argument carries it: `url` first, then `uri`, `endpoint`, `href`, `target`, `resource` or `link`, then any other top-level argument that is an http or https URL. A tool that is not in the list is not checked. An empty `VET402_GUARD_TOOLS` checks no tool, and the plugin logs one warning when that happens.
- **`vet402_check` tool.** The model can ask about any URL before it decides to pay. It returns the recommendation for that method, the reason codes in vet402's words, how many times vet402 paid that endpoint and how often it delivered, and a link to the public page.
- **`vet402` skill.** It tells the model to write the URL, the method, the verdict, the reason codes, and the evidence link into the approval body before asking.

## Limits

- hermes-mpp can also pay 402 challenges inside Hermes HTTPX traffic, outside any tool. Hooks do not see those payments. `MPP_ALLOWED_ORIGINS` is the control for them.
- vet402 only knows endpoints listed in public x402 and MPP discovery. For an unlisted URL the answer is "no record", which says nothing about the seller. The hook then asks, or refuses when nobody can answer.
- Endpoints listed with a path parameter (for example `/:chainId/quote`) match only their listed path, so a call to `/1/quote` gets no record for that path.
- A record with no method is treated as a GET record. A POST payment does not pass on it.
- Decisions follow vet402's published rules (https://vet402.com/observatory/methodology). The plugin keeps an ALLOW, WARN, BLOCK, or unknown answer for 5 minutes and vet402 may reuse one for 5 more, so an answer can be up to 10 minutes old. Outages and rejected lookups are not kept.
- Without a key, vet402 answers 10 decisions per minute per IP. Past that, a lookup counts as cannot be reached.

## Network and data

The plugin makes up to two HTTPS GET requests to vet402.com for each new URL and method. Both requests include the method: `/api/v1/resolve?q=<url>&method=<METHOD>` and `/api/v1/resources/<id>/decision?role=payer&method=<METHOD>`. It sends the URL the agent is about to pay, with any userinfo, query string, and fragment removed, and nothing else: no wallet address, no key, no request body. Redirects are not followed. `VET402_API` and `VET402_TIMEOUT_S` are read when the plugin is imported. Changing them later in the same process does not change the client. Answers stay in memory for 5 minutes. No telemetry, no files written, no shell commands, no background processes.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `VET402_GUARD_TOOLS` | `mpp_fetch` | Comma-separated tools to check before they run. Only the argument named `url` is read. |
| `VET402_UNKNOWN` | ask a person | `allow` is the only opt-in that pays with no record or during an outage. See the sentence above for what that choice skips. |
| `VET402_API` | `https://vet402.com` | API base, read at import |
| `VET402_TIMEOUT_S` | `6` | Request timeout in seconds, read at import |

## Tests

From the repository root:

```bash
python3 -m pytest -q
```

MIT license.
