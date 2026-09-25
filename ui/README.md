# mogh_ui

Common UI components and styling used across Mogh apps
([Mantine](https://mantine.dev) + React), including the pages and
components of [mogh_auth](../auth) (login, profile, login providers,
trusted issuers).

## Requirements

mogh_ui is published as ESM source for a bundler, and is built and tested
with [Vite](https://vite.dev). It can't be loaded by Node directly (and has
no CommonJS build):

- Components import `.module.scss` files, so the app needs a Sass compiler:
  `sass-embedded` (or `sass`) in its dev dependencies.
- The Monaco editor loads its workers with Vite's `?worker` imports.
- Relative imports are extensionless, left for the bundler to resolve.

Install the peer dependencies next to it (npm does this by default),
`prettier` included: the editor formats yaml / typescript with it
(Alt + Shift + F, not in a read only editor), loaded only when used.

```ts
import "mogh_ui/index.scss";
import { ThemeProvider } from "mogh_ui";
```

## Notes

- The auth pages and hooks (`LoginPage`, `useAuthState`, `authClient`,
  ...) keep the user's tokens in the default `MoghAuth.LOGIN_TOKENS`
  store of `mogh_auth_client`, and the app has to read them from there.
  A store with its own key (`createLoginTokens({ key })`) isn't used by
  them.
- The login page's `backto` (`backtoPath`) is only followed to a path on
  the app's origin, and without the query params an external login
  returns with (`redeem_ready`, `totp`, `passkey`, `login_error`,
  `link_error`): the server adds its own to the url the provider sends
  the user back to, and `useAuthState` would take one already there for
  the server's. `externalLogin` drops them from the current url too.
- `Config` shows one confirm dialog behind all of its Save buttons.
  Ctrl / Cmd + Enter (outside of text inputs) opens it while there are
  changes, and Enter in the open dialog saves (it opens with its Save
  button focused). `ConfirmUpdate` does the same for a single Save button,
  and with `confirmKeyListener={false}` Enter doesn't save: the dialog
  opens with its close button focused. When several are mounted, only
  the first one takes a key press, and none opens while a confirm dialog
  is open.
- `ConfirmModal` starts every open with an empty input: text typed for an
  earlier open doesn't confirm the next one.
- `useKeyListener` / `useShiftKeyListener` / `useCtrlKeyListener`: a
  handler returning `false` declines the press, which then keeps its
  browser default (eg. Enter on a focused button).

## Development

```sh
npm install
npm run typecheck
npm test        # unit tests (node --test)
npm run build
```

The [example app](../example) uses the local build (`file:` dependency),
and its Playwright suite exercises the auth pages end to end.
