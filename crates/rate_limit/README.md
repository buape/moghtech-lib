# Mogh Rate Limit

Add configurable rate limiting to fallible async requests.

Only failures count. A failed attempt returns its own error (status and
headers included) with a `FailedAttempt` context noting the attempts left,
displayed as `Invalid login credentials | You have 2 attempts remaining`.
The original error stays in the chain, so `error.downcast_ref::<T>()` still
finds its types. Once the attempts are used up, requests from the ip are
refused with `429 Too Many Requests` until the window passes.
