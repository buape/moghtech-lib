// State of the external login / link flows, and the url handling they
// need, shared by the auth hooks and the login page. Not exported from
// the package. No imports: the unit tests load it in Node.

/**
 * Whether an external login failed on this page load: the server
 * sent the browser back with `login_error`, or redeeming the login
 * for a token (`redeem_ready`) failed. The login page then doesn't
 * auto redirect to the provider again, which would only fail again,
 * in a loop.
 */
export const externalLoginState = { failed: false };

const EXTERNAL_FLOW_KEY = "mogh-ui-external-flow-v1";

/**
 * Longer than any login at a provider is expected to take. A return
 * after it isn't vouched for (a failure isn't shown as the server's).
 */
const EXTERNAL_FLOW_MAX_AGE_MS = 30 * 60_000;

/**
 * Notes that this tab is leaving for an external login or link. The
 * mark is per tab (`sessionStorage`) and vouches for the page load the
 * provider sends the tab back to ([takeExternalFlowReturn]), within
 * [EXTERNAL_FLOW_MAX_AGE_MS]. Only then does `useAuthState` show:
 * - the reason the server sends back when the flow fails
 *   (`login_error` / `link_error`);
 * - the server's error when redeeming a `redeem_ready` fails (it is
 *   redeemed either way, without the mark a failure is only logged).
 */
export function markExternalFlow() {
  try {
    sessionStorage.setItem(EXTERNAL_FLOW_KEY, String(Date.now()));
  } catch {
    // Storage blocked: failed flows show a generic reason, and a
    // failed redeem is only logged.
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

/**
 * The query params the server adds to the url an external login / link
 * returns to (read by `useAuthState`). A successful login returns with
 * one of `redeem_ready`, `totp` or `passkey`, a failed one with
 * `login_error` / `link_error` (sent to the page configured for it).
 */
const FLOW_RETURN_PARAMS = [
  "redeem_ready",
  "totp",
  "passkey",
  "login_error",
  "link_error",
];

/** The params only a login which went through returns with. */
const FLOW_SUCCESS_PARAMS = ["redeem_ready", "totp", "passkey"];

/**
 * `path` (a path on this origin, eg. from `sameOriginPath`) without the
 * query params an external login returns with ([FLOW_RETURN_PARAMS]).
 *
 * The provider sends the tab back to this path, and the server adds its
 * params after the query already there. One already in the path would
 * be read as the server's: eg. a `login_error` made up by whoever wrote
 * the link (`/login?backto=/?login_error=...`), shown as the reason
 * after the tab's own flow, or a `redeem_ready=0` which drops the login.
 * The rest of the path is kept as it is.
 */
export function withoutFlowReturnParams(path: string): string {
  const hashStart = path.indexOf("#");
  const hash = hashStart === -1 ? "" : path.slice(hashStart);
  const beforeHash = hashStart === -1 ? path : path.slice(0, hashStart);
  const queryStart = beforeHash.indexOf("?");
  if (queryStart === -1) return path;
  const pairs = beforeHash.slice(queryStart + 1).split("&");
  // Each pair's name as the page reads it (decoded, `+` for a space).
  const kept = pairs.filter((pair) => {
    const [name] = new URLSearchParams(pair).keys();
    return name === undefined || !FLOW_RETURN_PARAMS.includes(name);
  });
  if (kept.length === pairs.length) return path;
  const query = kept.filter((pair) => pair.length).join("&");
  return beforeHash.slice(0, queryStart) + (query ? `?${query}` : "") + hash;
}

/**
 * A query param the server added to the url an external login returned
 * to: its last value, the server adds its own after the query the url
 * already had.
 */
export function flowReturnParam(
  search: URLSearchParams,
  name: string,
): string | null {
  const values = search.getAll(name);
  return values.length ? values[values.length - 1] : null;
}

/** Why an external login / link failed, as the url says. */
export interface FlowReturnError {
  /** A link failed (`link_error`), rather than a login (`login_error`). */
  link: boolean;
  /** The reason in the url. Anyone can put text in a link. */
  text: string;
  /**
   * - `server`: the server's own reason. The page load is the return
   *   from a flow this tab started ([takeExternalFlowReturn]), and the
   *   url carries only the one reason the server adds.
   * - `unverified`: anyone could have written it, show a generic reason.
   * - `stray`: the url also carries what a login which went through
   *   returns with (`redeem_ready`, `totp`, `passkey`), which the
   *   server's failure never does: not a failure, ignore it.
   */
  source: "server" | "unverified" | "stray";
}

/**
 * The `login_error` / `link_error` of the page's query, and how far it
 * can be trusted. Pass the query as the page loaded, before any of it
 * is removed.
 * @param flowReturn Whether the page load is the return from a flow the
 * tab started ([takeExternalFlowReturn]).
 */
export function flowReturnError(
  search: URLSearchParams,
  flowReturn: boolean,
): FlowReturnError | undefined {
  const logins = search.getAll("login_error");
  const links = search.getAll("link_error");
  const link = !logins.length;
  const text = (link ? links : logins)[0];
  if (!text) return undefined;
  let source: FlowReturnError["source"];
  if (FLOW_SUCCESS_PARAMS.some((param) => search.has(param))) {
    source = "stray";
  } else if (flowReturn && logins.length + links.length === 1) {
    source = "server";
  } else {
    source = "unverified";
  }
  return { link, text, source };
}

/**
 * Whether `pathname` is the login page's own route, `/login` (or
 * `/login/`). Not any path starting with it, like an app's
 * `/login-providers/:id`, where the login page is also shown (for the
 * second factor of an external login which returned there).
 */
export function isLoginPath(pathname: string): boolean {
  return pathname === "/login" || pathname === "/login/";
}

/**
 * Replaces the page's url without a reload (which would drop the
 * notifications). `url` must be absolute and on this origin: a relative
 * path starting with `//` (the app opened at `https://app//x`) would
 * be read as another host, which `replaceState` refuses by throwing.
 *
 * Never throws: it runs while rendering, where a throw would take the
 * app down, and the url is only being tidied up.
 */
export function replaceUrl(url: string) {
  try {
    history.replaceState(history.state, "", url);
  } catch (error) {
    console.warn("Couldn't update the url:", error);
  }
}

/**
 * Removes query params from the page's url, keeping the rest of it
 * (fragment included), without a reload ([replaceUrl]).
 */
export function removeQueryParams(...params: string[]) {
  const url = new URL(location.href);
  if (!params.some((param) => url.searchParams.has(param))) return;
  for (const param of params) url.searchParams.delete(param);
  replaceUrl(url.href);
}
