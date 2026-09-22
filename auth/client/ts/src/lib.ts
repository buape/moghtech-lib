import { LoginResponses, ManageResponses } from "./responses.js";
import type {
  LoginRequest,
  ManageRequest,
  TokenExchangeError,
  TokenExchangeResponse,
} from "./types.js";

export * as Types from "./types.js";
export * as Passkey from "./passkey.js";
export { LOGIN_TOKENS, extractUserIdFromJwt } from "./tokens.js";
export type { LoginResponses, ManageResponses };

/**
 * The error message of a manage request refused with `403` because it
 * needs a recent login starts with this. Requests which change how a user
 * can log in (password, 2fa, linked logins, new api keys, ...) are only
 * accepted with a token issued a short while ago. Send the user to
 * log in again, and retry.
 */
export const REAUTHENTICATION_REQUIRED = "Reauthentication required";

/** Whether a rejected request (`{ status, result }`) needs the user to log in again. */
export function isReauthenticationRequired(e: unknown): boolean {
  const { status, result } = (e ?? {}) as {
    status?: number;
    result?: { error?: string };
  };
  return (
    status === 403 && !!result?.error?.startsWith(REAUTHENTICATION_REQUIRED)
  );
}

/** RFC 8693 identifiers used by the token endpoint. */
export const TOKEN_EXCHANGE = {
  GRANT_TYPE: "urn:ietf:params:oauth:grant-type:token-exchange",
  ID_TOKEN: "urn:ietf:params:oauth:token-type:id_token",
  JWT: "urn:ietf:params:oauth:token-type:jwt",
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
} as const;

export function MoghAuthClient(url: string, jwt?: string) {
  const request = <Params, Res>(
    path: "/login" | "/manage",
    type: string,
    params: Params
  ): Promise<Res> =>
    new Promise(async (res, rej) => {
      try {
        let response = await fetch(`${url}${path}/${type}`, {
          method: "POST",
          body: JSON.stringify(params),
          headers: {
            "content-type": "application/json",
            ...(jwt ? { authorization: jwt } : {}),
          },
          credentials: "include",
        });
        if (response.status === 200) {
          const body: Res = await response.json();
          res(body);
        } else {
          try {
            const result = await response.json();
            rej({ status: response.status, result });
          } catch (error) {
            rej({
              status: response.status,
              result: {
                error: "Failed to get response body",
                trace: [JSON.stringify(error)],
              },
              error,
            });
          }
        }
      } catch (error) {
        rej({
          status: 1,
          result: {
            error: "Request failed with error",
            trace: [JSON.stringify(error)],
          },
          error,
        });
      }
    });

  const login = async <
    T extends LoginRequest["type"],
    Req extends Extract<LoginRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], LoginResponses[Req["type"]]>(
      "/login",
      type,
      params
    );

  const manage = async <
    T extends ManageRequest["type"],
    Req extends Extract<ManageRequest, { type: T }>
  >(
    type: T,
    params: Req["params"]
  ) =>
    await request<Req["params"], ManageResponses[Req["type"]]>(
      "/manage",
      type,
      params
    );

  /**
   * Redirect to log in with an external login provider.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLogin = (providerSlug: string) => {
    const _redirect = location.pathname.startsWith("/login")
      ? location.origin +
        (new URLSearchParams(location.search).get("backto") ?? "")
      : location.href;
    const redirect = encodeURIComponent(_redirect);
    location.replace(
      `${url}/external/${encodeURIComponent(providerSlug)}/login?redirect=${redirect}`
    );
  };

  /**
   * The url to redirect to in order to link the signed in user to an
   * external login provider. `BeginExternalLoginLink` must be called first.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLinkUrl = (providerSlug: string) =>
    `${url}/external/${encodeURIComponent(providerSlug)}/link`;

  /**
   * Link the signed in user to an external login provider.
   * Begins the link on the session, then redirects to the provider.
   * @param providerSlug The provider `slug` from `GetLoginOptions`.
   */
  const externalLink = async (providerSlug: string) => {
    await manage("BeginExternalLoginLink", {});
    location.replace(externalLinkUrl(providerSlug));
  };

  /**
   * RFC 8693 Token Exchange: exchange a token issued by an external
   * login provider (an ID token / JWT) for an app token, without
   * sending the user through the browser.
   *
   * The provider must have token exchange enabled,
   * and the user must already exist.
   *
   * Rejects with `{ status, result }`, where `result` is the
   * OAuth error: `{ error, error_description }`.
   *
   * @param subjectToken The token issued by the provider.
   * @param subjectTokenType `TOKEN_EXCHANGE.ID_TOKEN` (default) or `TOKEN_EXCHANGE.JWT`.
   */
  const tokenExchange = (
    subjectToken: string,
    subjectTokenType:
      | typeof TOKEN_EXCHANGE.ID_TOKEN
      | typeof TOKEN_EXCHANGE.JWT = TOKEN_EXCHANGE.ID_TOKEN
  ): Promise<TokenExchangeResponse> =>
    new Promise(async (res, rej) => {
      try {
        // The RFC requires a form, not json.
        const response = await fetch(`${url}/token`, {
          method: "POST",
          body: new URLSearchParams({
            grant_type: TOKEN_EXCHANGE.GRANT_TYPE,
            subject_token: subjectToken,
            subject_token_type: subjectTokenType,
          }),
        });
        if (response.status === 200) {
          res(await response.json());
        } else {
          let result: TokenExchangeError;
          try {
            result = await response.json();
          } catch {
            result = { error: "server_error" };
          }
          rej({ status: response.status, result });
        }
      } catch (error) {
        rej({
          status: 1,
          result: {
            error: "server_error",
            error_description: "Request failed with error",
          } satisfies TokenExchangeError,
          error,
        });
      }
    });

  return {
    login,
    manage,
    tokenExchange,
    externalLogin,
    externalLinkUrl,
    externalLink,
  };
}
