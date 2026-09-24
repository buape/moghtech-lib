// State of the external login / link flows, shared by the auth
// hooks and the login page. Not exported from the package.

/**
 * Whether an external login failed on this page load: the server
 * sent the browser back with `login_error`, or redeeming the login
 * for a token failed. The login page then doesn't auto redirect to
 * the provider again, which would only fail again, in a loop.
 */
export const externalLoginState = { failed: false };

const EXTERNAL_FLOW_KEY = "mogh-ui-external-flow-v1";

/** Longer than any login at a provider is expected to take. */
const EXTERNAL_FLOW_MAX_AGE_MS = 30 * 60_000;

/**
 * Notes that this tab is leaving for an external login or link. The
 * reason the server sends back when it fails (`login_error` /
 * `link_error`) is only shown after a flow the tab started.
 */
export function markExternalFlow() {
  try {
    sessionStorage.setItem(EXTERNAL_FLOW_KEY, String(Date.now()));
  } catch {
    // Storage blocked: failed flows show a generic reason.
  }
}

// The back button at the provider can show an earlier page of the app
// as it was (back / forward cache), without loading the app again, and
// so without taking the mark ([takeExternalFlowReturn]). The provider
// always sends the tab back to a new page load, so any page shown from
// the cache means the flow was dropped: a later link mustn't be taken
// for its return. Every page of the app listens, not only the one
// which left: both flows leave with `location.replace`, so back never
// shows that one, it shows the page before it (eg. the page which sent
// the user to `/login` to log in again).
globalThis.addEventListener?.("pageshow", (event) => {
  if (event.persisted) takeExternalFlow();
});

/**
 * Whether this tab recently started an external login or link.
 * Clears the mark, it vouches for one return from the provider.
 */
export function takeExternalFlow(): boolean {
  try {
    const started = Number(sessionStorage.getItem(EXTERNAL_FLOW_KEY));
    sessionStorage.removeItem(EXTERNAL_FLOW_KEY);
    const age = Date.now() - started;
    return started > 0 && age >= 0 && age < EXTERNAL_FLOW_MAX_AGE_MS;
  } catch {
    return false;
  }
}

let return_checked = false;

/**
 * Whether this page load is the return from an external login or
 * link the tab started. The provider sends the tab back to a new page
 * load of the app, so only the first call of a page load takes the
 * mark ([takeExternalFlow]), later ones give `false`.
 *
 * It takes the mark whatever the tab came back with: a failure, a
 * token to redeem, a second factor to ask for, or a finished link
 * (which comes back without any query). The flow is over either way,
 * a later link carrying `login_error` isn't vouched for.
 */
export function takeExternalFlowReturn(): boolean {
  if (return_checked) return false;
  return_checked = true;
  return takeExternalFlow();
}
