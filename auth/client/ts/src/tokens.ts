import { jwtDecode } from "jwt-decode";

export const extractUserIdFromJwt = (jwt: string) => {
  return jwtDecode<{ sub: string | undefined }>(jwt).sub;
};

export type LoginToken = { user_id: string; jwt: string };

type LoginTokens = {
  /** The user chosen last, in any tab. New tabs (and reloads) start with it. */
  current: string | undefined;
  /** Array of logged in user ids / tokens */
  tokens: Array<LoginToken>;
};

/** The login tokens of the signed in users, kept in `localStorage`. */
export type LoginTokensStore = {
  /** The token of this tab's current user, or `""` when signed out. */
  jwt: () => string;
  /** The signed in users, this tab's current one first. */
  accounts: () => Array<LoginToken>;
  /**
   * Add (or replace) the token's user, and make it the current one
   * of this tab, and of the tabs opened next.
   */
  add_and_change: (jwt: string) => void;
  /**
   * Sign out a user, in every tab. When it is this tab's current one,
   * another signed in user (if any) becomes current here. Other tabs
   * with that user are signed out.
   */
  remove: (user_id: string) => void;
  /** Sign out every user, in every tab. */
  remove_all: () => void;
  /**
   * Make another signed in user the current one of this tab, and of
   * the tabs opened next.
   */
  change: (to_id: string) => void;
  /**
   * Call `listener` after the login tokens change, in this tab or in
   * another one (the browser's `storage` event). When this tab's user
   * signs out in another tab, `jwt()` gives `""` from then on: use it
   * to show the login page and drop the data cached for the user.
   * Another tab's change is notified when its `storage` event arrives,
   * even when this tab already read it (eg. `jwt()` in a render).
   * Returns the function to unsubscribe.
   *
   * Fits React's `useSyncExternalStore(store.subscribe, store.jwt)`.
   */
  subscribe: (listener: () => void) => () => void;
};

/** The `localStorage` key used by `LOGIN_TOKENS`. */
const LOGIN_TOKENS_KEY = "mogh-auth-tokens-v1";

/**
 * Keep the login tokens in `localStorage` under `key`.
 *
 * The stored tokens are shared by every tab of the origin: a login or
 * logout in one tab applies to all of them. Each call reads the latest
 * stored value and each change is applied onto it, so tabs never undo
 * each other's changes.
 *
 * The current user is kept per tab (per store). A tab starts with the
 * user chosen last in any tab, and only its own `add_and_change`,
 * `change` and `remove` change it: signing in another user or
 * switching the user in one tab leaves the other tabs with their user.
 * So a tab never starts sending the token of another user than the one
 * it shows. When a tab's user signs out in another tab, the tab is
 * signed out (`jwt()` gives `""`), use `subscribe` to react to that.
 *
 * Every app on the same origin (eg. several apps behind one host with
 * path routing, or on `localhost` in development) shares the default
 * key, and so one token list and the user chosen last. Such apps
 * should each pass their own `key`. Create one store per key, eg. at
 * module level. Apps using the auth pages and hooks of `mogh_ui` can't:
 * those always use the default `LOGIN_TOKENS`.
 *
 * Returns `undefined` where `localStorage` is unavailable: in node, or
 * in a browser blocking site data for the origin.
 */
export function createLoginTokens(options?: {
  /** The `localStorage` key. Default: `mogh-auth-tokens-v1`. */
  key?: string;
}): LoginTokensStore | undefined {
  const key = options?.key ?? LOGIN_TOKENS_KEY;
  const storage = resolveStorage(key);
  if (!storage) return;

  let read_failed = false;
  const read = () => {
    try {
      const stored = storage.getItem(key);
      read_failed = false;
      return stored;
    } catch (error) {
      // Once, not on every call while it keeps failing.
      if (!read_failed) {
        console.warn("Failed to read the stored login tokens.", error);
      }
      read_failed = true;
      return undefined;
    }
  };

  // The stored value last seen, and its parsed state.
  let raw = read() ?? null;
  let state = parseLoginTokens(raw);

  /** The latest stored state. Only parsed again after it changed. */
  const load = () => {
    const stored = read();
    // Keep the state known to this page when reading fails.
    if (stored !== undefined && stored !== raw) {
      raw = stored;
      state = parseLoginTokens(stored);
    }
    return state;
  };

  // This tab's current user. It stays set when the user signs out in
  // another tab, which signs out this tab rather than switching it to
  // another user, and resumes when the user signs in again.
  let selected = state.current;

  const listeners = new Set<() => void>();

  // The stored value listeners were last notified of. Kept apart from
  // `raw`, which every read updates: the browser updates this tab's
  // `localStorage` as soon as another tab changes it, and fires the
  // `storage` event in a later task, so a read in between (a render, a
  // polling request) already sees the change.
  let notified_raw = raw;

  const notify = () => {
    notified_raw = raw;
    for (const listener of [...listeners]) {
      try {
        listener();
      } catch (error) {
        console.error("Login tokens listener failed.", error);
      }
    }
  };

  const save = (next: LoginTokens) => {
    state = next;
    const json = JSON.stringify(next);
    try {
      storage.setItem(key, json);
      raw = json;
    } catch (error) {
      // Eg. QuotaExceededError. The login still works for this page.
      console.warn(
        "Failed to store the login tokens, they are lost when the page is closed.",
        error,
      );
    }
    notify();
  };

  // Changes made by other tabs. `key` is null after `localStorage.clear()`.
  const onStorage = (event: StorageEvent) => {
    if (event.key !== null && event.key !== key) return;
    load();
    if (raw !== notified_raw) notify();
  };

  const subscribe = (listener: () => void) => {
    listeners.add(listener);
    if (listeners.size === 1 && typeof window !== "undefined") {
      window.addEventListener?.("storage", onStorage);
    }
    return () => {
      if (
        listeners.delete(listener) &&
        listeners.size === 0 &&
        typeof window !== "undefined"
      ) {
        window.removeEventListener?.("storage", onStorage);
      }
    };
  };

  const jwt = () => {
    const { tokens } = load();
    return selected
      ? (tokens.find((t) => t.user_id === selected)?.jwt ?? "")
      : "";
  };

  const accounts = () => {
    const { tokens } = load();
    const current_token = tokens.find((t) => t.user_id === selected);
    const filtered = tokens.filter((t) => t.user_id !== selected);
    return current_token ? [current_token, ...filtered] : filtered;
  };

  const add_and_change = (jwt: string) => {
    const user_id = extractUserIdFromJwt(jwt);
    if (!user_id) return;
    const filtered = load().tokens.filter((t) => t.user_id !== user_id);
    filtered.push({ user_id, jwt });
    filtered.sort((a, b) => a.user_id.localeCompare(b.user_id));
    selected = user_id;
    save({
      current: user_id,
      tokens: filtered,
    });
  };

  const remove = (user_id: string) => {
    const { current, tokens } = load();
    const filtered = tokens.filter((t) => t.user_id !== user_id);
    if (selected === user_id) selected = filtered[0]?.user_id;
    // The user chosen last, unless that is the one signing out.
    let next = current;
    if (current === user_id) {
      next = filtered.some((t) => t.user_id === selected)
        ? selected
        : filtered[0]?.user_id;
    }
    save({
      current: next,
      tokens: filtered,
    });
  };

  const remove_all = () => {
    selected = undefined;
    save({
      current: undefined,
      tokens: [],
    });
  };

  const change = (to_id: string) => {
    const { tokens } = load();
    selected = to_id;
    save({
      current: to_id,
      tokens,
    });
  };

  return {
    jwt,
    accounts,
    add_and_change,
    remove,
    remove_all,
    change,
    subscribe,
  };
}

/**
 * The login tokens kept in `localStorage`, under `mogh-auth-tokens-v1`.
 * See `createLoginTokens`.
 *
 * `undefined` where `localStorage` is unavailable: in node, or in a
 * browser blocking site data for the origin.
 */
export const LOGIN_TOKENS = createLoginTokens();

function resolveStorage(key: string) {
  try {
    // An undeclared global has to be checked with `typeof`, using it
    // directly throws a ReferenceError. When the browser blocks site
    // data, even reading `localStorage` (and so `typeof`) throws a
    // SecurityError, and some browsers only throw on use.
    if (typeof localStorage === "undefined" || !localStorage) return;
    localStorage.getItem(key);
    return localStorage;
  } catch (error) {
    console.warn(
      "localStorage is unavailable, login tokens are not kept.",
      error,
    );
    return;
  }
}

function parseLoginTokens(stored: string | null): LoginTokens {
  try {
    const parsed = stored ? JSON.parse(stored) : undefined;
    // Anything else than what this module stored is dropped,
    // rather than failing every page load until it is cleared.
    if (parsed && Array.isArray(parsed.tokens)) {
      return {
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
  return { current: undefined, tokens: [] };
}
