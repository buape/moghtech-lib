import { notifications } from "@mantine/notifications";
import {
  useMutation,
  UseMutationOptions,
  useQuery,
} from "@tanstack/react-query";
import * as MoghAuth from "mogh_auth_client";
import { useState } from "react";
import {
  externalLoginState,
  flowReturnError,
  flowReturnParam,
  markExternalFlow,
  takeExternalFlowReturn,
  withoutFlowReturnParams,
} from "./external-flow";
import { guardJwt, SEND_REJECTED_ONCE, sendableJwt } from "./rejected-jwt";
import { backtoPath, sanitizeQueryInner } from "./utils";

export * from "./issuers";
export * from "./login";
export * from "./profile";
export * from "./providers";
export * from "./utils";

export let AUTH_URL: string;

/**
 * Set the global auth url.
 * Make sure to call this before first render.
 * @param url The global url
 */
export function setAuthUrl(url: string) {
  AUTH_URL = url;
}

export function authClient() {
  return MoghAuth.MoghAuthClient(AUTH_URL, MoghAuth.LOGIN_TOKENS!.jwt());
}

/**
 * Log in with an external login provider: redirects to it, like
 * `authClient().externalLogin`. From the login page the provider
 * sends the user back to [backtoPath], which never leaves the app,
 * from anywhere else back to the current page. Either way without the
 * query params the login returns with (see [useAuthState]), which only
 * the server adds.
 *
 * Also notes that this tab started the login, so the reason a failed
 * login comes back with is shown (see [useAuthState]).
 *
 * @param providerSlug The provider `slug` from `GetLoginOptions`.
 */
export function externalLogin(providerSlug: string) {
  // The client builds the redirect from the url (on the login page
  // from its `backto`), only hand it a checked one.
  const current = location.pathname + location.search + location.hash;
  let url = current;
  const search = new URLSearchParams(location.search);
  if (search.has("backto")) {
    search.set("backto", backtoPath());
    url = `${location.pathname}?${search}${location.hash}`;
  }
  url = withoutFlowReturnParams(url);
  if (url !== current) {
    history.replaceState(history.state, "", url);
  }
  markExternalFlow();
  authClient().externalLogin(providerSlug);
}

/**
 * Called when a manage request is refused because it needs a recent login
 * (`MoghAuth.isReauthenticationRequired`). By default the user is sent to
 * `/login`, and comes back to the current page after logging in.
 */
let onReauthenticationRequired = () => {
  const backto = encodeURIComponent(location.pathname + location.search);
  // Leaves time to read the notification.
  setTimeout(() => location.assign(`/login?backto=${backto}`), 2_000);
};

/** Replace what happens when a change needs the user to log in again. */
export function setOnReauthenticationRequired(handler: () => void) {
  onReauthenticationRequired = handler;
}

export function useLoginOptions() {
  return useQuery({
    queryKey: ["GetLoginOptions"],
    queryFn: () => authClient().login("GetLoginOptions", {}),
  });
}

/**
 * Runs a manage query. A token the server refuses with one of
 * `rejectedOn` isn't sent again by the queries here (`sendableJwt`):
 * every request which fails auth counts against the server's per IP
 * auth rate limit, which logging in shares.
 */
function manageQuery<T>(
  rejectedOn: number[],
  query: (client: ReturnType<typeof authClient>) => Promise<T>,
): Promise<T> {
  const jwt = MoghAuth.LOGIN_TOKENS!.jwt();
  return guardJwt(jwt, rejectedOn, () =>
    query(MoghAuth.MoghAuthClient(AUTH_URL, jwt)),
  );
}

/**
 * List all the external login providers, including disabled ones.
 * Only available to admin users.
 */
export function useExternalLoginProviders(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ListExternalLoginProviders"],
    queryFn: () =>
      manageQuery([401], (client) =>
        client.manage("ListExternalLoginProviders", {}),
      ),
    enabled:
      (options?.enabled ?? true) && sendableJwt(MoghAuth.LOGIN_TOKENS!.jwt()),
    // A user who isn't an admin gets the same answer every time
    retry: false,
  });
}

/**
 * List the token issuers trusted for workload
 * identity. Only available to admin users.
 */
export function useTrustedIssuers(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ListTrustedIssuers"],
    queryFn: () =>
      manageQuery([401], (client) => client.manage("ListTrustedIssuers", {})),
    enabled:
      (options?.enabled ?? true) && sendableJwt(MoghAuth.LOGIN_TOKENS!.jwt()),
    // A user who isn't an admin gets the same answer every time
    retry: false,
  });
}

export function useLogin<
  T extends MoghAuth.Types.LoginRequest["type"],
  R extends Extract<MoghAuth.Types.LoginRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.LoginResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    // Spread first: a caller's `onError` extends the
    // notification below instead of replacing it.
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => authClient().login<T, R>(type, params),
    onError: (
      e: { result?: { error?: string; trace?: string[] } },
      ...args
    ) => {
      console.log("Login error:", e);
      const msg = e.result?.error ?? "Unknown error. See console.";
      // Skip the causes the message already shows, eg. a failed
      // attempt's error under the rate limit's attempts remaining note.
      const detail = e.result?.trace
        ?.filter((cause) => !msg.includes(cause))
        .map((msg) => msg[0].toUpperCase() + msg.slice(1))
        .join(" | ");
      let msg_log = msg ? msg[0].toUpperCase() + msg.slice(1) + " | " : "";
      if (detail) {
        msg_log += detail + " | ";
      }
      notifications.show({
        title: `Login request ${type} failed`,
        message: `${msg_log}See console for details`,
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
  });
}

/**
 * Look up the signed in user's id.
 *
 * Pass `enabled: false` where the host app already knows the answer
 * from its own session query. Every request which fails auth counts
 * against the server's per IP auth rate limit, so a token the server
 * rejects is only ever sent once: it isn't retried or refetched
 * (whatever the host's query client defaults), and the query stays
 * disabled until there is another token.
 */
export function useUserId(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["GetUserId"],
    queryFn: () =>
      manageQuery([401, 403], (client) => client.manage("GetUserId", {})),
    enabled:
      (options?.enabled ?? true) && sendableJwt(MoghAuth.LOGIN_TOKENS!.jwt()),
    // The server would refuse the token again
    ...SEND_REJECTED_ONCE,
  });
}

export function useManageAuth<
  T extends MoghAuth.Types.ManageRequest["type"],
  R extends Extract<MoghAuth.Types.ManageRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.ManageResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    // Spread first: a caller's `onError` extends the
    // notification below instead of replacing it.
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => authClient().manage<T, R>(type, params),
    onError: (
      e: { result?: { error?: string; trace?: string[] } },
      ...args
    ) => {
      console.log("Manage auth error:", e);
      // Not a failure of the request itself: changes to how the
      // user logs in are only accepted shortly after logging in.
      if (MoghAuth.isReauthenticationRequired(e)) {
        notifications.show({
          title: "Log in again to continue",
          message:
            "For your security this change needs a recent login. Taking you to the login page...",
          color: "yellow",
        });
        onReauthenticationRequired();
        config?.onError && config.onError(e, ...args);
        return;
      }
      const msg = e.result?.error ?? "Unknown error. See console.";
      // Skip the causes the message already shows, eg. a failed
      // attempt's error under the rate limit's attempts remaining note.
      const detail = e.result?.trace
        ?.filter((cause) => !msg.includes(cause))
        .map((msg) => msg[0].toUpperCase() + msg.slice(1))
        .join(" | ");
      let msg_log = msg ? msg[0].toUpperCase() + msg.slice(1) + " | " : "";
      if (detail) {
        msg_log += detail + " | ";
      }
      notifications.show({
        title: `Manage auth request ${type} failed`,
        message: `${msg_log}See console for details`,
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
  });
}

let jwt_redeem_sent = false;
let passkey_sent = false;
let external_error_shown = false;

/** The longest reason from the url shown in the notification. */
const MAX_EXTERNAL_ERROR_LENGTH = 300;

/**
 * Removes params from the url without a reload,
 * which would drop the notifications.
 */
function removeQueryParams(...params: string[]) {
  const search = new URLSearchParams(location.search);
  for (const param of params) search.delete(param);
  const query = search.toString();
  history.replaceState(
    history.state,
    "",
    `${location.pathname}${query.length ? "?" + query : ""}${location.hash}`,
  );
}

/**
 * Handles what an external login redirects back to the app with.
 * Call it at the top of the app, before (outside) its router:
 * - `redeem_ready`: redeems the login for a token.
 * - `passkey`: asks for the passkey, the login's second factor.
 * - `login_error` / `link_error`: shows why an external login / link
 *   failed (`AuthImpl::external_login_error_redirect` on the server).
 *   Anyone can put text in a link, so the server's reason is only
 *   shown after an external login / link this tab started through
 *   mogh_ui ([externalLogin], `LoginPage`, `LinkedLogins`), on the
 *   page load it came back to, when the url carries only the one reason
 *   the server adds. Otherwise the notification says the login didn't
 *   complete, and the text is only logged to the console. Next to what
 *   a login which went through returns with (`redeem_ready`, `totp`,
 *   `passkey`) it isn't the server's at all, and is only logged.
 *
 * The server adds its params after the query already in the url, so
 * `redeem_ready`, `totp` and `passkey` are read from their last value.
 *
 * The first page load after leaving for the provider ends the flow,
 * whatever it came back with (also a successful login or link, or a
 * second factor to ask for). So call this on every page of the app.
 *
 * Returns whether to show a loader while the token is redeemed
 * (`jwt_redeem_ready`, false again if that fails), or the login page
 * for the second factor (`passkey_pending`, `totp`).
 */
export function useAuthState() {
  // A failed redeem falls back to the app, eg. its login page.
  const [redeemFailed, setRedeemFailed] = useState(false);
  const onSuccess = ({ jwt }: MoghAuth.Types.JwtResponse) => {
    MoghAuth.LOGIN_TOKENS!.add_and_change(jwt);
    sanitizeQueryInner(search);
  };
  const { mutate: redeemJwt } = useLogin("ExchangeForJwt", {
    onSuccess,
    onError: () => {
      // Retrying can't help, the server has ended the login.
      externalLoginState.failed = true;
      removeQueryParams("redeem_ready");
      setRedeemFailed(true);
    },
  });
  const { mutate: completePasskeyLogin } = useLogin("CompletePasskeyLogin", {
    onSuccess,
  });
  const search = new URLSearchParams(location.search);
  // Whether the tab is back from an external login / link it started.
  const external_flow_return = takeExternalFlowReturn();
  // Judged on the url as it loaded, before any of it is removed.
  const external_error = flowReturnError(search, external_flow_return);

  // A link can carry anything here: a challenge which can't be
  // read must not crash the app, which renders this on every page.
  const _passkey = flowReturnParam(search, "passkey");
  let passkeyRequest:
    | ReturnType<typeof MoghAuth.Passkey.prepareRequestChallengeResponse>
    | undefined;
  if (_passkey) {
    try {
      passkeyRequest = MoghAuth.Passkey.prepareRequestChallengeResponse(
        JSON.parse(MoghAuth.Passkey.base64UrlDecode(_passkey)),
      );
    } catch (e) {
      console.error("Invalid passkey challenge:", e);
      search.delete("passkey");
      removeQueryParams("passkey");
      if (!passkey_sent) {
        passkey_sent = true;
        notifications.show({
          title: "Invalid passkey challenge",
          message: "Log in again to continue.",
          color: "red",
        });
      }
    }
  }

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (passkeyRequest && !passkey_sent) {
    passkey_sent = true;
    navigator.credentials
      .get(passkeyRequest)
      .then((credential) => completePasskeyLogin({ credential }))
      .catch((e) => {
        console.error(e);
        notifications.show({
          title: "Failed to select passkey",
          message: "See console for details",
          color: "red",
        });
      });
  }

  // An external login / link which failed comes back with the reason
  // (`AuthImpl::external_login_error_redirect` on the server).
  if (external_error && !external_error_shown) {
    external_error_shown = true;
    const { link, text, source } = external_error;
    const param = link ? "link_error" : "login_error";
    if (source === "stray") {
      // Next to a login which went through: not the server's.
      console.warn(`Ignored ${param} in the url:`, text);
    } else {
      if (!link) {
        // Don't auto redirect to the provider again, it would loop.
        externalLoginState.failed = true;
      }
      let message: string;
      if (source === "server") {
        message =
          text.length > MAX_EXTERNAL_ERROR_LENGTH
            ? text.slice(0, MAX_EXTERNAL_ERROR_LENGTH) + "..."
            : text;
      } else {
        // Not a flow started here, the text may come from anyone.
        console.warn(`Unverified ${param} in the url:`, text);
        message = link
          ? "Linking the external login didn't complete."
          : "The external login didn't complete.";
      }
      notifications.show({
        title: link ? "Failed to link login" : "Login failed",
        message,
        color: "red",
        autoClose: 10_000,
      });
    }
    search.delete("login_error");
    search.delete("link_error");
    removeQueryParams("login_error", "link_error");
  }

  const jwt_redeem_ready = flowReturnParam(search, "redeem_ready") === "true";

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (jwt_redeem_ready && !jwt_redeem_sent) {
    redeemJwt({});
    jwt_redeem_sent = true;
  }

  return {
    jwt_redeem_ready: jwt_redeem_ready && !redeemFailed,
    passkey_pending: !!passkeyRequest,
    totp: flowReturnParam(search, "totp") === "true",
  };
}
