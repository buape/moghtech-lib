export function sanitizeQuery() {
  sanitizeQueryInner(new URLSearchParams(location.search));
}

export function sanitizeQueryInner(search: URLSearchParams) {
  search.delete("redeem_ready");
  search.delete("totp");
  search.delete("passkey");
  const query = search.toString();
  location.replace(
    `${location.origin}${location.pathname}${query.length ? "?" + query : ""}`,
  );
}

/**
 * A navigation target reduced to a path on this origin, or `fallback`.
 *
 * Only a relative path starting with a single `/` is accepted.
 * Anything which could leave the app gives the fallback: other
 * origins, `javascript:` and other schemes, protocol relative
 * `//host` and `/\host`, and forms which only become one of those
 * once the url is parsed (`/\t/host`). A path which resolves to
 * `//...` (`/.//host`, `/%2e//host`) has its leading slashes
 * collapsed, so it stays a path.
 *
 * For targets anyone can put in a link, like the login page's `backto`.
 */
export function sameOriginPath(
  target: string | null | undefined,
  fallback = "/",
): string {
  if (!target || !target.startsWith("/") || /^\/[\/\\]/.test(target)) {
    return fallback;
  }
  let url: URL;
  try {
    url = new URL(target, location.origin);
  } catch {
    return fallback;
  }
  if (url.origin !== location.origin) {
    return fallback;
  }
  const path = url.pathname.replace(/^\/+/, "/");
  return path + url.search + url.hash;
}

/**
 * Where to go after logging in: the `backto` query param of the
 * current url, if it is a path on this origin (see
 * [sameOriginPath]), otherwise `fallback`.
 *
 * Every use of `backto` goes through this. The login page's
 * navigation after logging in, its back button, and the redirect of
 * an external login ([externalLogin]).
 */
export function backtoPath(fallback = "/"): string {
  return sameOriginPath(
    new URLSearchParams(location.search).get("backto"),
    fallback,
  );
}
