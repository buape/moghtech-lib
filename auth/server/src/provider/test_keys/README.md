# Test keys

RSA keys used only by unit tests to mint signed tokens
(`provider/token_exchange.rs`). They were generated for this
repository with `openssl genrsa -traditional 2048`, protect
nothing, and are only compiled into test builds.

- `rsa_a.pem`: the key the test provider publishes.
- `rsa_b.pem`: a key it doesn't publish, to test rejected signatures.
