import { test } from "node:test";
import assert from "node:assert/strict";
import {
  markExternalFlow,
  takeExternalFlow,
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
