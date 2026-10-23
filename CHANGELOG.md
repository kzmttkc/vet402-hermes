# Changelog

## 0.2.0

A missing record for the paying method, and an outage, now ask a person. A WARN other than the reason code `l1_not_attempted` asks a person too. When nobody can answer (yolo, approvals off, cron, or a session with no person), those calls are refused and nothing is paid.

`VET402_UNKNOWN=allow` is no longer the default. Setting it lets the payment run when vet402 has no record for that method or cannot be reached (timeout, refused connection, HTTP 500, HTTP 429, or a body that is not JSON), which skips the check. It does not let a redirect, an HTTP 400, a WARN, a BLOCK, or any other status pay.

Lookups send the paying HTTP method on both requests and use only the record for that method. Redirects are not followed.

The hook finds the paid address under `uri`, `endpoint` and any other URL argument, not only `url`. An empty `VET402_GUARD_TOOLS` logs one warning.

An uppercase scheme such as `HTTPS://` is checked like `https://`. An "always" approval covers only the same WARN reasons on the same URL and method. An error inside the check refuses the payment.

## 0.1.0

First release. The plugin checks a paid URL in vet402's public record before `mpp_fetch` runs.
