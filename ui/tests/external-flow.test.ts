import { test } from "node:test";
import assert from "node:assert/strict";
import {
  flowReturnError,
  flowReturnParam,
  markExternalFlow,
  takeExternalFlow,
  withoutFlowReturnParams,
} from "../src/auth/external-flow.ts";

type ExternalFlow = typeof import("../src/auth/external-flow.ts");

let loads = 0;
/** The module as a new page load of the app sees it. */
function pageLoad(): Promise<ExternalFlow> {
  loads += 1;
  return import(`../src/auth/external-flow.ts?load=${loads}`);
}

function withStorage(storage: unknown) {
  (globalThis as { sessionStorage?: unknown }).sessionStorage = storage;
}

function memoryStorage() {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, value),
    removeItem: (key: string) => void items.delete(key),
  };
}

test("a failed login's reason is only vouched for once", () => {
  withStorage(memoryStorage());
  // Nothing started here, eg. a link carrying `login_error`
  assert.equal(takeExternalFlow(), false);
  markExternalFlow();
  assert.equal(takeExternalFlow(), true);
  assert.equal(takeExternalFlow(), false);
});

test("an old mark doesn't vouch for a later link", () => {
  const storage = memoryStorage();
  withStorage(storage);
  markExternalFlow();
  const [key] = storage.items.keys();
  storage.items.set(key, String(Date.now() - 60 * 60_000));
  assert.equal(takeExternalFlow(), false);
  // Not a timestamp at all
  storage.items.set(key, "soon");
  assert.equal(takeExternalFlow(), false);
});

test("blocked storage vouches for nothing, and doesn't throw", () => {
  const blocked = () => {
    throw new Error("SecurityError");
  };
  withStorage({ getItem: blocked, setItem: blocked, removeItem: blocked });
  markExternalFlow();
  assert.equal(takeExternalFlow(), false);
});

test("the return from the provider ends the flow, whatever it brings", async () => {
  withStorage(memoryStorage());
  const page = await pageLoad();
  assert.equal(page.takeExternalFlowReturn(), false);
  page.markExternalFlow();
  // Renders before the tab has left
  assert.equal(page.takeExternalFlowReturn(), false);

  // Back with a token to redeem, a second factor to ask for, or a
  // finished link (without any query): no error to vouch for, the
  // return takes the mark all the same.
  const back = await pageLoad();
  assert.equal(back.takeExternalFlowReturn(), true);
  assert.equal(back.takeExternalFlowReturn(), false);

  // A later link carrying `login_error`, in the same tab
  assert.equal((await pageLoad()).takeExternalFlowReturn(), false);
});

test("the back button at the provider drops the flow", async () => {
  const storage = memoryStorage();
  withStorage(storage);
  const global = globalThis as { addEventListener?: unknown };
  const onPageShow: ((event: { persisted: boolean }) => void)[] = [];
  global.addEventListener = (
    type: string,
    listener: (event: { persisted: boolean }) => void,
  ) => {
    if (type === "pageshow") onPageShow.push(listener);
  };
  /** Loads a page, and gives its `pageshow` listener. */
  const listeningPage = async () => {
    const before = onPageShow.length;
    const page = await pageLoad();
    assert.equal(onPageShow.length, before + 1);
    return { page, pageShow: onPageShow[before] };
  };
  try {
    // A page of the app, which sends the user to `/login` to log in
    // again (`location.assign`, it stays in the back / forward cache)
    const earlier = await listeningPage();
    earlier.pageShow({ persisted: false });

    // `/login`, which leaves for the provider with `location.replace`:
    // back can't show it again.
    const login = await listeningPage();
    login.page.markExternalFlow();
    assert.equal(onPageShow.length, 2);
    // Its own first `pageshow` can come after the mark (eg. auto
    // redirect before the load event), and leaves it.
    login.pageShow({ persisted: false });
    assert.equal(storage.items.size, 1);

    // Back at the provider: the earlier page, as it was.
    earlier.pageShow({ persisted: true });
    assert.equal(storage.items.size, 0);
    // A later link carrying `login_error`, in the same tab
    assert.equal((await pageLoad()).takeExternalFlowReturn(), false);
  } finally {
    delete global.addEventListener;
  }
});

const SPOOFED = "Your account is locked. Call support at +1-555-0100";

/** The server's redirect after an external login (`format_redirect`). */
function serverReturn(path: string, extra: string) {
  const url = new URL(path, "http://app.example");
  url.search = url.search ? `${url.search}&${extra}` : extra;
  return url.searchParams;
}

test("the server's params are read from their last value", () => {
  // Planted before the server's own
  const search = serverReturn(
    "/?redeem_ready=0&totp=false&passkey=x",
    "redeem_ready=true",
  );
  assert.equal(flowReturnParam(search, "redeem_ready"), "true");
  assert.equal(flowReturnParam(search, "totp"), "false");
  assert.equal(
    flowReturnParam(serverReturn("/?passkey=x", "passkey=real"), "passkey"),
    "real",
  );
  assert.equal(flowReturnParam(new URLSearchParams(), "totp"), null);
});

test("a login error next to a login which went through isn't the server's", () => {
  for (const extra of ["redeem_ready=true", "totp=true", "passkey=e30"]) {
    const search = serverReturn(
      `/?login_error=${encodeURIComponent(SPOOFED)}`,
      extra,
    );
    // Even on the return from the tab's own flow
    assert.deepEqual(flowReturnError(search, true), {
      link: false,
      text: SPOOFED,
      source: "stray",
    });
  }
  const link = serverReturn("/profile?link_error=x", "redeem_ready=true");
  assert.equal(flowReturnError(link, true)?.source, "stray");
});

test("only the one reason of the tab's own flow is the server's", () => {
  // The server's failure: the configured page, with the reason added.
  const failed = serverReturn(
    "/login?theme=dark",
    `login_error=${encodeURIComponent("User registration is disabled")}`,
  );
  assert.deepEqual(flowReturnError(failed, true), {
    link: false,
    text: "User registration is disabled",
    source: "server",
  });
  // Not after a flow this tab started
  assert.equal(flowReturnError(failed, false)?.source, "unverified");
  // A second reason: one of them was in the url already
  const twice = serverReturn(
    `/login?login_error=${encodeURIComponent(SPOOFED)}`,
    "login_error=Rejected",
  );
  assert.deepEqual(flowReturnError(twice, true), {
    link: false,
    text: SPOOFED,
    source: "unverified",
  });
  const both = serverReturn("/profile?login_error=x", "link_error=Rejected");
  assert.equal(flowReturnError(both, true)?.source, "unverified");
  assert.deepEqual(
    flowReturnError(new URLSearchParams("link_error=Rejected"), true),
    { link: true, text: "Rejected", source: "server" },
  );
  // Nothing to show
  assert.equal(flowReturnError(new URLSearchParams(""), true), undefined);
  assert.equal(
    flowReturnError(new URLSearchParams("login_error="), true),
    undefined,
  );
});

test("a login error planted in the return path doesn't come back", () => {
  // `/login?backto=<this>`: the provider returns to it, the server adds
  // its param after the query already there.
  const backto = `/?login_error=${encodeURIComponent(SPOOFED)}&redeem_ready=0`;
  const returned = serverReturn(
    withoutFlowReturnParams(backto),
    "redeem_ready=true",
  );
  assert.equal(flowReturnError(returned, true), undefined);
  assert.equal(returned.getAll("redeem_ready").join(), "true");
});

test("withoutFlowReturnParams keeps everything else as it is", () => {
  assert.equal(withoutFlowReturnParams("/"), "/");
  assert.equal(withoutFlowReturnParams("/a?b=%20+c#d"), "/a?b=%20+c#d");
  assert.equal(
    withoutFlowReturnParams("/a?totp=true&b=%20+c&&passkey#d?totp=1"),
    "/a?b=%20+c#d?totp=1",
  );
  assert.equal(withoutFlowReturnParams("/a?login_error=x#h"), "/a#h");
  assert.equal(withoutFlowReturnParams("/a?redeem_ready"), "/a");
  // Same names once decoded
  assert.equal(withoutFlowReturnParams("/a?link%5Ferror=x&b"), "/a?b");
  // Similar names aren't the same
  assert.equal(
    withoutFlowReturnParams("/a?totp_code=1&my_login_error=x"),
    "/a?totp_code=1&my_login_error=x",
  );
});
