# vet402 for Hermes

Before your Hermes agent pays an x402 or MPP API, this plugin looks the URL up in vet402's public record of real purchases.

vet402 (https://vet402.com) buys from x402 and MPP sellers with its own USDC, checks each payment on chain, and publishes whether the seller delivered. The plugin reads that record and acts on it:

| vet402's record | What happens |
|---|---|
| BLOCK | The tool call is stopped and no payment is made. The message gives the reasons and a link to the evidence. |
| WARN with evidence against the seller (vet402 paid and got nothing, its latest purchase failed, the answer didn't match the seller's own declaration) | Hermes asks you to approve the call. Approving it for the session or always applies to that URL only. |
| ALLOW | The call runs. |
| WARN only because vet402 hasn't bought there yet, no record, or vet402 unreachable | The call runs. Set `VET402_UNKNOWN=approve` to be asked instead. |

## Install

```bash
hermes plugins install vet402
hermes plugins enable vet402
```

No key and no wallet. Requires Hermes 0.19.0 or newer.

## What it adds

- **`pre_tool_call` hook.** It runs before a paying tool: `mpp_fetch` from [hermes-mpp](https://github.com/tempoxyz/hermes-mpp) by default. Add more tools with `VET402_GUARD_TOOLS=mpp_fetch,other_tool`. Any tool whose arguments carry a `url` works.
- **`vet402_check` tool.** The model can ask about any URL before it decides to pay. It returns the recommendation, the reason codes in vet402's words, how many times vet402 paid that endpoint and how often it delivered, and a link to the public page.

## Limits

- hermes-mpp can also pay 402 challenges inside Hermes's own HTTPX traffic, outside any tool. Hooks don't see those payments. `MPP_ALLOWED_ORIGINS` is the control for them.
- vet402 only knows endpoints listed in public x402 and MPP discovery. For an unlisted URL the answer is "no record", which says nothing about the seller.
- Decisions follow vet402's published rules (https://vet402.com/observatory/methodology). The plugin keeps an answer for 5 minutes and vet402 may reuse one for 5 more, so an answer can be up to 10 minutes old.
- Without a key, vet402 answers 10 decisions per minute per IP. Past that, a lookup counts as unreachable.

## Network and data

The plugin makes up to two HTTPS GET requests to vet402.com for each new URL: `/api/v1/resolve?q=<url>` and `/api/v1/resources/<id>/decision?role=payer`. It sends the URL your agent is about to pay, with the query string and fragment removed, and nothing else: no wallet address, no key, no request body. Answers stay in memory for 5 minutes. No telemetry, no files written, no shell commands, no background processes.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `VET402_GUARD_TOOLS` | `mpp_fetch` | Comma-separated tools to check before they run |
| `VET402_UNKNOWN` | `allow` | `approve` also asks you before paying a URL vet402 has no evidence about |
| `VET402_API` | `https://vet402.com` | API base |
| `VET402_TIMEOUT_S` | `6` | Request timeout in seconds |

## Tests

From the repository root:

```bash
python3 -m unittest discover -s tests
```

MIT license.
