import { test } from "node:test";
import assert from "node:assert/strict";
import {
  guardJwt,
  SEND_REJECTED_ONCE,
  sendableJwt,
} from "../src/auth/rejected-jwt.ts";

// React Query behaves like in a browser (it retries 3 times by
// default), not like on a server (no retries).
(globalThis as { window?: unknown }).window = {};
const { QueryClient, QueryObserver, focusManager } =
  await import("@tanstack/query-core");

type Options = ConstructorParameters<typeof QueryObserver>[1];

/**
 * Runs a query until it settles, then focuses the window again.
 * Returns how often the request was sent.
 */
async function sendCount(
  request: () => Promise<unknown>,
  options: Partial<Options>,
) {
  const client = new QueryClient();
  client.mount();
  let sent = 0;
  const observer = new QueryObserver(client, {
    queryKey: ["GetUserId"],
    queryFn: () => {
      sent++;
      return request();
    },
    retryDelay: 0,
    ...options,
  });
  const settled = new Promise<void>((resolve) =>
    observer.subscribe((result) => {
      if (result.status !== "pending" && result.fetchStatus === "idle") {
        resolve();
      }
    }),
  );
  await settled;
  // The user comes back to the tab
  focusManager.setFocused(false);
  focusManager.setFocused(true);
  // Long enough for a refetch and its retries (no delay between them)
  await new Promise((resolve) => setTimeout(resolve, 100));
  focusManager.setFocused(undefined);
  observer.destroy();
  client.unmount();
  // Drops the queries with their timers, which keep node running
  client.clear();
  return sent;
}

const refused = (status: number) => () => Promise.reject({ status });

test("without the options, a refused token is sent again and again", async () => {
  // What the query did before, with the defaults of the host app:
  // 3 retries, and the same again when the window is focused.
  assert.equal(await sendCount(refused(401), {}), 8);
});

test("a token the server refused is only sent once", async () => {
  const jwt = "expired-jwt";
  assert.equal(sendableJwt(jwt), true);
  const sent = await sendCount(
    () => guardJwt(jwt, [401, 403], refused(401)),
    SEND_REJECTED_ONCE,
  );
  assert.equal(sent, 1);
  // Not enabled again for it, only for another token
  assert.equal(sendableJwt(jwt), false);
  assert.equal(sendableJwt("fresh-jwt"), true);
  assert.equal(sendableJwt(undefined), false);
});

test("only the listed statuses mark a token as refused", async () => {
  const jwt = "not-an-admin-jwt";
  await assert.rejects(guardJwt(jwt, [401], refused(403)));
  assert.equal(sendableJwt(jwt), true);
  await assert.rejects(guardJwt(jwt, [401], refused(401)));
  assert.equal(sendableJwt(jwt), false);
});

test("a request which never reached the server is retried", async () => {
  let attempts = 0;
  const flaky = async () => {
    attempts++;
    if (attempts < 3) throw { status: 1 };
    return { user_id: "user" };
  };
  const sent = await sendCount(
    () => guardJwt("jwt", [401, 403], flaky),
    SEND_REJECTED_ONCE,
  );
  assert.equal(sent, 3);
  assert.equal(sendableJwt("jwt"), true);

  // At most 3 times
  const unreachable = await sendCount(refused(1), SEND_REJECTED_ONCE);
  assert.equal(unreachable, 4);
});
