# Mogh Auth Library

Provides trait-driven server and client implementations for robust application authentication.

- Local login with usernames and passwords
- OIDC / social login
- Two factor authentication with webauthn passkey or TOTP code
- JWT token generation and validation utilities
- Request rate limiting by IP for brute force mitigation
- CIDR whitelisting of source IPs, per user and per API key
- Client IP resolution which only trusts forwarding headers from configured proxies
- Typescript types / client to layer with app-specific typescript client.