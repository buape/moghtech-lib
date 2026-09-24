# Mogh Error

De/serialize `anyhow` errors as json (`{ "error": "...", "trace": [...] }`),
and return them from axum handlers with a customizable status code.

```rust
use mogh_error::AddStatusCode as _;

fn fallible() -> mogh_error::Result<()> {
  let user = get_user().await.status_code(http::StatusCode::UNAUTHORIZED)?;
  ...
  Ok(())
}
```

## Server errors send the full trace by default

An `Error` response body carries the top-level message and the whole
context chain as `trace`, for every status. Every `?` on a foreign error
gives a `500`, so by default callers can see internal details such as
database driver messages, request urls, internal hostnames and file paths.

Apps can opt in to hiding these for server errors (5xx), typically once at
startup (feature `axum`):

```rust
// Top-level message only, empty trace.
mogh_error::set_server_error_detail(mogh_error::ServerErrorDetail::Message);
// Or the status code's reason ("Internal Server Error"), empty trace.
mogh_error::set_server_error_detail(mogh_error::ServerErrorDetail::Generic);
```

Client errors (4xx) keep their full message and trace. When details are
hidden, the response carries the full error in a `HiddenServerError`
extension (never sent to the caller), so a middleware can log it. This is a
process wide app setting: libraries should not call it.

## Receiving errors

`deserialize_error` / `deserialize_error_bytes` rebuild the anyhow chain from
a peer's json. The rebuilt chain is capped at `MAX_TRACE_DEPTH` (64) trace
entries: deeper entries are folded into the last one, joined with `": "`, so
`{:#}` renders the same text. anyhow drops a chain recursively, so an
unbounded trace from a peer could otherwise overflow the stack.

## Features

- `axum`: `Error`, `Result`, `Json` and the `AddStatusCode` / `AddHeaders`
  helpers for axum handlers.
- `utoipa`: derives `utoipa::ToSchema` for `Serror`. Since 1.0.6 this is
  **utoipa 6**. Apps still on utoipa 5 need `mogh_error = "=1.0.5"` until they
  move to utoipa 6.
