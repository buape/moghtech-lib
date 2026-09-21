import { notifications } from "@mantine/notifications";
import {
  useMutation,
  UseMutationOptions,
  useQuery,
} from "@tanstack/react-query";
import * as MoghAuth from "mogh_auth_client";
import { sanitizeQueryInner } from "./utils";

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
 * List all the external login providers, including disabled ones.
 * Only available to admin users.
 */
export function useExternalLoginProviders(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["ListExternalLoginProviders"],
    queryFn: () => authClient().manage("ListExternalLoginProviders", {}),
    enabled: (options?.enabled ?? true) && !!MoghAuth.LOGIN_TOKENS!.jwt(),
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
    queryFn: () => authClient().manage("ListTrustedIssuers", {}),
    enabled: (options?.enabled ?? true) && !!MoghAuth.LOGIN_TOKENS!.jwt(),
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
    onError: (e: { result?: { error?: string; trace?: string[] } }, ...args) => {
      console.log("Login error:", e);
      const msg = e.result?.error ?? "Unknown error. See console.";
      const detail = e.result?.trace
        ?.map((msg) => msg[0].toUpperCase() + msg.slice(1))
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
 * rejects should only ever be sent once.
 */
export function useUserId(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["GetUserId"],
    queryFn: () => authClient().manage("GetUserId", {}),
    enabled: (options?.enabled ?? true) && !!MoghAuth.LOGIN_TOKENS!.jwt(),
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
    onError: (e: { result?: { error?: string; trace?: string[] } }, ...args) => {
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
      const detail = e.result?.trace
        ?.map((msg) => msg[0].toUpperCase() + msg.slice(1))
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

/// returns whether to show login / loading screen depending on state of exchange token loop
export function useAuthState() {
  const onSuccess = ({ jwt }: MoghAuth.Types.JwtResponse) => {
    MoghAuth.LOGIN_TOKENS!.add_and_change(jwt);
    sanitizeQueryInner(search);
  };
  const { mutate: redeemJwt } = useLogin("ExchangeForJwt", {
    onSuccess,
  });
  const { mutate: completePasskeyLogin } = useLogin("CompletePasskeyLogin", {
    onSuccess,
  });
  const search = new URLSearchParams(location.search);

  const _passkey = search.get("passkey");
  const passkey = _passkey
    ? JSON.parse(MoghAuth.Passkey.base64UrlDecode(_passkey))
    : null;

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (passkey && !passkey_sent) {
    navigator.credentials
      .get(MoghAuth.Passkey.prepareRequestChallengeResponse(passkey))
      .then((credential) => completePasskeyLogin({ credential }))
      .catch((e) => {
        console.error(e);
        notifications.show({
          title: "Failed to select passkey",
          message: "See console for details",
          color: "red",
        });
      });
    passkey_sent = true;
  }

  // An external login / link which failed comes back with the reason
  // (`AuthImpl::external_login_error_redirect` on the server).
  const external_error =
    search.get("login_error") ?? search.get("link_error");
  if (external_error && !external_error_shown) {
    external_error_shown = true;
    notifications.show({
      title: search.has("link_error") ? "Failed to link login" : "Login failed",
      message: external_error,
      color: "red",
      autoClose: 10_000,
    });
    // Without a reload, which would drop the notification.
    search.delete("login_error");
    search.delete("link_error");
    const query = search.toString();
    history.replaceState(
      history.state,
      "",
      `${location.pathname}${query.length ? "?" + query : ""}`,
    );
  }

  const jwt_redeem_ready = search.get("redeem_ready") === "true";

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (jwt_redeem_ready && !jwt_redeem_sent) {
    redeemJwt({});
    jwt_redeem_sent = true;
  }

  return {
    jwt_redeem_ready,
    passkey_pending: !!passkey,
    totp: search.get("totp") === "true",
  };
}
