import { jwtDecode } from "jwt-decode";

export const extractUserIdFromJwt = (jwt: string) => {
  return jwtDecode<{ sub: string | undefined }>(jwt).sub;
};

type LoginToken = { user_id: string; jwt: string };

type LoginTokens = {
  /** Current User ID */
  current: string | undefined;
  /** Array of logged in user ids / tokens */
  tokens: Array<LoginToken>;
};

const LOGIN_TOKENS_KEY = "mogh-auth-tokens-v1";

export const LOGIN_TOKENS = (() => {
  // Early return in environments which don't support it (eg. node).
  // Note. An undeclared global has to be checked with `typeof`,
  // using it directly throws a ReferenceError on import.
  if (typeof localStorage === "undefined" || !localStorage) return;

  let tokens: LoginTokens = { current: undefined, tokens: [] };
  try {
    const stored = localStorage.getItem(LOGIN_TOKENS_KEY);
    const parsed = stored ? JSON.parse(stored) : undefined;
    // Anything else than what this module stored is dropped,
    // rather than failing every page load until it is cleared.
    if (parsed && Array.isArray(parsed.tokens)) {
      tokens = {
        current:
          typeof parsed.current === "string" ? parsed.current : undefined,
        tokens: parsed.tokens.filter(
          (token: Partial<LoginToken> | undefined) =>
            typeof token?.user_id === "string" &&
            typeof token?.jwt === "string",
        ),
      };
    }
  } catch (error) {
    console.warn("Invalid stored login tokens, starting without any.", error);
  }

  const update_local_storage = () => {
    localStorage.setItem(LOGIN_TOKENS_KEY, JSON.stringify(tokens));
  };

  const accounts = () => {
    const current = tokens.tokens.find((t) => t.user_id === tokens.current);
    const filtered = tokens.tokens.filter((t) => t.user_id !== tokens.current);
    return current ? [current, ...filtered] : filtered;
  };

  const add_and_change = (jwt: string) => {
    const user_id = extractUserIdFromJwt(jwt);
    if (!user_id) return;
    const filtered = tokens.tokens.filter((t) => t.user_id !== user_id);
    filtered.push({ user_id, jwt });
    filtered.sort((a, b) => a.user_id.localeCompare(b.user_id));
    tokens = {
      current: user_id,
      tokens: filtered,
    };
    update_local_storage();
  };

  const remove = (user_id: string) => {
    const filtered = tokens.tokens.filter((t) => t.user_id !== user_id);
    tokens = {
      current:
        tokens.current === user_id ? filtered[0]?.user_id : tokens.current,
      tokens: filtered,
    };
    update_local_storage();
  };

  const remove_all = () => {
    tokens = {
      current: undefined,
      tokens: [],
    };
    update_local_storage();
  };

  const change = (to_id: string) => {
    tokens = {
      current: to_id,
      tokens: tokens.tokens,
    };
    update_local_storage();
  };

  return {
    jwt: () =>
      tokens.current
        ? tokens.tokens.find((t) => t.user_id === tokens.current)?.jwt ?? ""
        : "",
    accounts,
    add_and_change,
    remove,
    remove_all,
    change,
  };
})();
