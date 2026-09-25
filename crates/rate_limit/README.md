# Mogh Rate Limit

Add configurable rate limiting to fallible async requests.

Only failures count. A failed attempt returns its own error (status and
headers included) with a `FailedAttempt` context noting the attempts left,
displayed as `Invalid login credentials | You have 2 attempts remaining`.
The original error stays in the chain, so `error.downcast_ref::<T>()` still
finds its types. The note displays the error with its causes, except for a
server error (5xx) when the app hides server error details
(`mogh_error::set_server_error_detail`): then only its top-level message, as
the response carries that message alone. Once the attempts are used up,
requests from the client are refused with `429 Too Many Requests` until the
window passes.

```rust
use mogh_rate_limit::{RateLimiter, WithFailureRateLimit};

// 5 failed attempts per client every 15 minutes.
let limiter = RateLimiter::new(false, 5, Duration::from_secs(15 * 60));

// Guessable secrets (passwords, TOTP codes): strict.
login(body)
  .with_strict_failure_rate_limit_using_ip(&limiter, &ip)
  .await?;

// Parallel requests with unguessable credentials: best effort.
authenticate(headers)
  .with_failure_rate_limit_using_ip(&limiter, &ip)
  .await?;
```

## Strict or best effort

- `with_strict_failure_rate_limit_using_ip` (and `_using_headers`) counts
  the attempts in flight against the budget, so no more than `max_attempts`
  attempts from a client can fail within the window, however many it sends
  at once. Attempts in flight never cause a refusal, only recorded failures
  do: once they use up the budget, every attempt is refused with `429`, as
  with best effort. While the remaining attempts are all reserved by
  attempts in flight, the next one waits for one of them to finish (a
  success gives its reservation back without using up an attempt). No more
  than `max_attempts` attempts per client run at the same time. Use it for
  secrets which can be guessed.
- `with_failure_rate_limit_using_ip` (and `_using_headers`) only counts the
  failures recorded so far. It never holds a request back, but a burst of
  attempts sent at the same time all run before any of them is recorded, so
  it does **not** bound a burst. Use it where requests legitimately run in
  parallel and the credentials can't be guessed, like checking the api key
  or JWT of every authenticated request.

Both share the budget of a client on the same `RateLimiter`.

## Clients

Attempts are counted per IPv4 address, and per IPv6 `/64` prefix: an IPv6
host usually controls a whole `/64`, and could otherwise use a fresh address
for every attempt. The clients sharing a `/64` share a budget, the way the
users behind one IPv4 address (NAT) do. IPv4-mapped IPv6 addresses count as
their IPv4 address. Change the prefix with `RateLimiter::builder`:

```rust
let limiter = RateLimiter::builder(5, Duration::from_secs(15 * 60))
  // Coarser, for clients assigned a /56. Or 128 for one budget per address.
  .ipv6_prefix_len(56)
  .build();
```

The `_using_headers` variants find the client address with `get_client_ip`,
believing forwarding headers only from the trusted proxies.

## Memory

Only clients with failures within the window (or strict attempts in flight)
are tracked. A task removes the rest once a minute, and at most
`max_entries` clients (default 100,000) are kept: past that, the clients
whose failures have all left the window are removed, then the ones whose last
failure is the oldest.
