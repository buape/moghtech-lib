import { credentialToJSON } from "./passkey.js";
import type { LoginResponses, ManageResponses } from "./responses.js";
import type {
  LoginRequest,
  ManageRequest,
  TokenExchangeError,
  TokenExchangeResponse,
} from "./types.js";

export * as Types from "./types.js";
export * as Passkey from "./passkey.js";
export {
  LOGIN_TOKENS,
  createLoginTokens,
  extractUserIdFromJwt,
} from "./tokens.js";
export type { LoginToken, LoginTokensStore } from "./tokens.js";
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

/**
 * The path to return to after logging in: `backto` when it is a path
 * on `origin`, otherwise `/`. Check the `backto` query of the login
 * page with it before navigating there, it comes from the url and can
 * be anything (`//evil.example`, `javascript:...`).
 *
 * Only a relative path starting with a single `/` is accepted. The
 * result is the normalized path, and one which only resolves to
 * `//...` (`/.//host`, `/%2e//host`) has its leading slashes
 * collapsed, so it can't be read as a protocol relative url.
 * @param backto Default: the `backto` query of the current location.
 * @param origin Default: the current origin.
 */
export function safeBackto(
  backto: string | null = new URLSearchParams(location.search).get(
    "backto",
  ),
  origin: string = location.origin,
): string {
  // Only a path: not a scheme, host or `//host`.
  if (!backto?.startsWith("/") || /^\/[\/\\]/.test(backto)) return "/";
  try {
    const base = new URL(origin);
    const target = new URL(backto, base);
    if (target.origin !== base.origin) return "/";
    // Removing dot segments can give `//host`.
    const path = target.pathname.replace(/^[\/\\]+/, "/");
    return path + target.search + target.hash;
  } catch {
    return "/";
  }
}

/** A failed request, as the promises of `MoghAuthClient` reject. */
export type RequestError = {
  /**
   * The http status. `1` when the server wasn't reached
   * (network / CORS failure).
   */
  status: number;
  /** The error body: `{ error, trace }` (`{ error, error_description }` for `tokenExchange`). */
  result: { error?: string; trace?: string[] } & Record<string, unknown>;
  /** The caught error, if any. */
  error?: unknown;
};

/** The requests which send a passkey credential. */
const PASSKEY_CREDENTIAL_REQUESTS = [
  "CompletePasskeyLogin",
  "ConfirmPasskeyEnrollment",
];

/**
 * A readable message for a caught error and its causes.
 * `JSON.stringify` gives `{}` for an `Error`.
 */
function describeError(error: unknown): string[] {
  const messages: string[] = [];
  let current = error;
  for (let depth = 0; depth < 5 && current != null; depth++) {
    if (current instanceof Error) {
      messages.push(
        [current.name, current.message].filter(Boolean).join(": "),
      );
      current = current.cause;
    } else {
      messages.push(String(current));
      break;
    }
  }
  const filtered = messages.filter(Boolean);
  return filtered.length ? filtered : ["Unknown error"];
}

/** The start of a response body which isn't the expected json. */
function bodySnippet(text: string): string[] {
  const snippet = text.replace(/\s+/g, " ").trim();
  if (!snippet) return [];
  return [snippet.length > 500 ? snippet.slice(0, 500) + "..." : snippet];
}

/**
 * The params to send. A passkey credential is sent in its JSON form,
 * see `Passkey.credentialToJSON`.
 */
function encodeParams(type: string, params: unknown) {
  if (!PASSKEY_CREDENTIAL_REQUESTS.includes(type)) return params;
  const credential = (params as { credential?: unknown } | undefined)
    ?.credential;
  if (!credential || typeof credential !== "object") return params;
  try {
    return {
      ...(params as object),
      credential: credentialToJSON(credential),
    };
  } catch {
    // Not a credential this can encode, the server reports it.
    return params;
  }
}

function statusMessage({ status, statusText }: Response) {
  return `Request failed with status ${status} ${statusText}`.trim();
}

type Body =
  /** Reading the body failed. */
  | { read: false; error: unknown }
  | { read: true; text: string; parsed: true; json: unknown }
  | { read: true; text: string; parsed: false; parseError: unknown };

/** The response body, parsed when it is json. */
async function readBody(response: Response): Promise<Body> {
  let text: string;
  try {
    text = await response.text();
  } catch (error) {
    return { read: false, error };
  }
  try {
    return { read: true, text, parsed: true, json: JSON.parse(text) };
  } catch (parseError) {
    return { read: true, text, parsed: false, parseError };
  }
}

export function MoghAuthClient(url: string, jwt?: string) {
  const request = async <Params, Res>(
    path: "/login" | "/manage",
    type: string,
    params: Params
  ): Promise<Res> => {
    let response: Response;
    try {
      response = await fetch(`${url}${path}/${type}`, {
        method: "POST",
        body: JSON.stringify(encodeParams(type, params)),
        headers: {
          "content-type": "application/json",
          ...(jwt ? { authorization: jwt } : {}),
        },
        credentials: "include",
      });
    } catch (error) {
      throw {
        status: 1,
        result: {
          error: "Request failed with error",
          trace: describeError(error),
        },
        error,
      } satisfies RequestError;
    }
    const body = await readBody(response);
    if (!body.read) {
      throw {
        status: response.status,
        result: {
          error: "Failed to get response body",
          trace: describeError(body.error),
        },
        error: body.error,
      } satisfies RequestError;
    }
    if (response.status === 200) {
      if (body.parsed) return body.json as Res;
      throw {
        status: response.status,
        result: {
          error: "Invalid response body",
          trace: [
            ...describeError(body.parseError),
            ...bodySnippet(body.text),
          ],
        },
        error: body.parseError,
      } satisfies RequestError;
    }
    if (body.parsed && body.json && typeof body.json === "object") {
      throw { status: response.status, result: body.json };
    }
    // Not an error of the auth server, eg. a proxy's 502 page.
    throw {
      status: response.status,
      result: {
        error: statusMessage(response),
        trace: bodySnippet(body.text),
      },
    } satisfies RequestError;
  };

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
      ? location.origin + safeBackto()
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
  const tokenExchange = async (
    subjectToken: string,
    subjectTokenType:
      | typeof TOKEN_EXCHANGE.ID_TOKEN
      | typeof TOKEN_EXCHANGE.JWT = TOKEN_EXCHANGE.ID_TOKEN
  ): Promise<TokenExchangeResponse> => {
    let response: Response;
    try {
      // The RFC requires a form, not json.
      response = await fetch(`${url}/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: TOKEN_EXCHANGE.GRANT_TYPE,
          subject_token: subjectToken,
          subject_token_type: subjectTokenType,
        }),
      });
    } catch (error) {
      throw {
        status: 1,
        result: {
          error: "server_error",
          error_description: [
            "Request failed with error",
            ...describeError(error),
          ].join(" | "),
        } satisfies TokenExchangeError,
        error,
      };
    }
    const body = await readBody(response);
    if (!body.read) {
      throw {
        status: response.status,
        result: {
          error: "server_error",
          error_description: [
            "Failed to get response body",
            ...describeError(body.error),
          ].join(" | "),
        } satisfies TokenExchangeError,
        error: body.error,
      };
    }
    if (body.parsed) {
      if (response.status === 200) {
        return body.json as TokenExchangeResponse;
      }
      if (body.json && typeof body.json === "object") {
        throw { status: response.status, result: body.json };
      }
    }
    const description =
      response.status === 200 && !body.parsed
        ? ["Invalid response body", ...describeError(body.parseError)]
        : [statusMessage(response)];
    throw {
      status: response.status,
      result: {
        error: "server_error",
        error_description: [...description, ...bodySnippet(body.text)].join(
          " | ",
        ),
      } satisfies TokenExchangeError,
      ...(body.parsed ? {} : { error: body.parseError }),
    };
  };

  return {
    login,
    manage,
    tokenExchange,
    externalLogin,
    externalLinkUrl,
    externalLink,
  };
}
