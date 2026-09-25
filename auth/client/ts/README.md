# mogh_auth_client

Typescript client for a `mogh_auth_server` auth api: the request and
response types, a typed client, the login token store of the browser,
and the passkey helpers.

```ts
import * as MoghAuth from "mogh_auth_client";

const auth = MoghAuth.MoghAuthClient(
  "https://example.com/auth",
  MoghAuth.LOGIN_TOKENS?.jwt(),
);
const options = await auth.login("GetLoginOptions", {});
```

## Errors

Every request rejects with `{ status, result, error? }`
(`MoghAuth.RequestError`):

- `status` is the http status, or `1` when the server wasn't reached
  (network / CORS failure).
- `result` is the error body of the server: `{ error, trace }`, where
  `error` is always a string and `trace` a list of strings. When the body
  isn't json (eg. a proxy's `502` page), or is json of another shape (eg.
  a gateway's `{"error":{"code":403}}`), `error` names the status and
  `trace` holds the start of the body. A `200` with an invalid body
  rejects with `Invalid response body`.
- `error` is the caught error, if any.

`isReauthenticationRequired(e)` tells whether a manage request needs the
user to log in again. It takes anything that was caught, never throws,
and is `false` for any other value.

`tokenExchange` rejects the same way, with the OAuth error
`{ error, error_description }` as `result`. A body which isn't an OAuth
error is `server_error`, with the status and the start of the body as
`error_description`. `temporarily_unavailable` means retry later: `429`
after too many failed requests, `503` while a login provider or trusted
issuer of the token's issuer can't be loaded.

## Login tokens

`LOGIN_TOKENS` keeps the tokens of the signed in users in `localStorage`
(key `mogh-auth-tokens-v1`). It is `undefined` where `localStorage` is
unavailable: in node, or in a browser blocking site data.

- The stored tokens are shared by every tab of the origin: a login or a
  logout in one tab applies to all of them. Every call reads the latest
  stored state, so tabs never undo each other's changes.
- The current user is kept per tab. A tab starts with the user chosen
  last (in any tab), and only changes it by its own `add_and_change`,
  `change` or `remove`. Signing in another user or switching the user
  in one tab leaves the other tabs with their user, so a tab never
  starts sending the token of another user than the one it shows.
- When a tab's user signs out in another tab, that tab is signed out:
  `jwt()` gives `""`. It resumes when the user signs in again.
- `LOGIN_TOKENS.subscribe(listener)` calls `listener` after a change in
  this or another tab, eg. to show the login page and drop the cached
  data when the user signed out in another tab. It fits React's
  `useSyncExternalStore(LOGIN_TOKENS.subscribe, LOGIN_TOKENS.jwt)`.
- Apps served from the same origin (several apps behind one host, or
  `localhost` in development) share the default key. Give each app its
  own store with `createLoginTokens({ key: "my-app-tokens" })`, unless
  it uses the auth pages and hooks of `mogh_ui`: they always use the
  default `LOGIN_TOKENS`, so the app has to use it too (a store of its
  own would stay empty after every login).

## Passkeys

```ts
navigator.credentials
  .get(MoghAuth.Passkey.prepareRequestChallengeResponse(challenge))
  .then((credential) =>
    auth.login("CompletePasskeyLogin", {
      credential: MoghAuth.Passkey.credentialToJSON(credential),
    }),
  );
```

`credentialToJSON` base64url encodes the binary fields of the credential
where the browser (or a password manager extension) has no
`PublicKeyCredential.toJSON`. The client applies it to
`CompletePasskeyLogin` and `ConfirmPasskeyEnrollment` itself.

## Redirects

`safeBackto()` gives the `backto` query of the login page when it is a
path on the current origin, otherwise `/`. Check `backto` with it before
navigating there after a login. `externalLogin` uses it too. The result
is a normalized path which never starts with `//`, even for input like
`/.//evil.example`, so it can be passed to `location.replace` or a
router as is.

## Development

```sh
npm run build   # tsc, into dist
npm test        # build, then the node tests in test/
```

`src/types.ts` is generated from the rust types:
`node auth/client/ts/generate_types.mjs` (needs `typeshare`), which
fails when typeshare fails.
