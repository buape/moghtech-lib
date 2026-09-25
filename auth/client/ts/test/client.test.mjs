import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { setLocalStorage } from "./helpers.mjs";

// Like node without `--localstorage-file`, minus the warning.
setLocalStorage({ value: undefined });

const {
  MoghAuthClient,
  REAUTHENTICATION_REQUIRED,
  isReauthenticationRequired,
  safeBackto,
} = await import("../dist/lib.js");

const realFetch = globalThis.fetch;
/** The requests sent by the client. */
let sent = [];

function mockFetch(respond) {
  sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url, init });
    return respond();
  };
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

const client = MoghAuthClient("https://auth.example");

async function rejection(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  assert.fail("expected the request to fail");
}

describe("request errors", () => {
  it("keeps the status and body of a non json error", async () => {
    mockFetch(
      () =>
        new Response("<html>\n<h1>502 Bad Gateway</h1>\n</html>", {
          status: 502,
          statusText: "Bad Gateway",
        }),
    );
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 502);
    assert.deepEqual(e.result, {
      error: "Request failed with status 502 Bad Gateway",
      trace: ["<html> <h1>502 Bad Gateway</h1> </html>"],
    });
  });

  it("handles an empty error body", async () => {
    mockFetch(() => new Response(null, { status: 404 }));
    const e = await rejection(client.manage("GetUserId", {}));
    assert.equal(e.status, 404);
    assert.deepEqual(e.result, {
      error: "Request failed with status 404",
      trace: [],
    });
  });

  it("passes the json error of the server through", async () => {
    const result = { error: "Invalid credentials", trace: ["cause"] };
    mockFetch(() => Response.json(result, { status: 401 }));
    const e = await rejection(client.login("LoginLocalUser", {}));
    assert.deepEqual(e, { status: 401, result });
  });

  it("describes a network failure", async () => {
    sent = [];
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed", {
        cause: new Error("connect ECONNREFUSED 127.0.0.1:443"),
      });
    };
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 1);
    assert.deepEqual(e.result, {
      error: "Request failed with error",
      trace: [
        "TypeError: fetch failed",
        "Error: connect ECONNREFUSED 127.0.0.1:443",
      ],
    });
  });

  it("reports an invalid 200 body apart from network failures", async () => {
    // Eg. the auth url points at the ui, which serves index.html.
    mockFetch(() => new Response("<!doctype html>", { status: 200 }));
    const e = await rejection(client.login("GetLoginOptions", {}));
    assert.equal(e.status, 200);
    assert.equal(e.result.error, "Invalid response body");
    assert.match(e.result.trace[0], /^SyntaxError: /);
    assert.equal(e.result.trace[1], "<!doctype html>");
  });

  it("reports a json error of another shape like a non json one", async () => {
    // Eg. a gateway / WAF in front of the auth api.
    for (const foreign of [
      { error: { code: 403, message: "Forbidden" } },
      { error: true, message: "Forbidden" },
      { message: "Forbidden" },
      ["Forbidden"],
      "Forbidden",
      403,
      null,
    ]) {
      mockFetch(() =>
        Response.json(foreign, { status: 403, statusText: "Forbidden" }),
      );
      const e = await rejection(client.manage("UpdatePassword", {}));
      assert.deepEqual(
        e,
        {
          status: 403,
          result: {
            error: "Request failed with status 403 Forbidden",
            trace: [JSON.stringify(foreign)],
          },
        },
        JSON.stringify(foreign),
      );
      assert.equal(isReauthenticationRequired(e), false);
    }
  });

  it("keeps only the string lines of the trace", async () => {
    for (const [trace, expected] of [
      [undefined, []],
      ["cause", []],
      [{ 0: "cause" }, []],
      [["cause", 1, null, { a: 1 }, "root"], ["cause", "root"]],
    ]) {
      mockFetch(() =>
        Response.json(
          { error: "Forbidden", trace, code: 7 },
          { status: 403 },
        ),
      );
      const e = await rejection(client.manage("UpdatePassword", {}));
      assert.deepEqual(e, {
        status: 403,
        result: { error: "Forbidden", trace: expected, code: 7 },
      });
    }
  });

  it("tells a reauthentication error apart", async () => {
    const error = `${REAUTHENTICATION_REQUIRED}: this needs a recent login`;
    mockFetch(() => Response.json({ error, trace: [] }, { status: 403 }));
    const e = await rejection(client.manage("UpdatePassword", {}));
    assert.equal(isReauthenticationRequired(e), true);
    // Only as a 403.
    assert.equal(
      isReauthenticationRequired({ status: 401, result: { error } }),
      false,
    );
  });

  it("resolves the json body", async () => {
    mockFetch(() => Response.json({ user_id: "x" }));
    assert.deepEqual(await client.manage("GetUserId", {}), {
      user_id: "x",
    });
  });
});

describe("tokenExchange errors", () => {
  it("keeps the status of a non json error", async () => {
    mockFetch(
      () =>
        new Response("upstream timeout", {
          status: 504,
          statusText: "Gateway Timeout",
        }),
    );
    const e = await rejection(client.tokenExchange("token"));
    assert.equal(e.status, 504);
    assert.deepEqual(e.result, {
      error: "server_error",
      error_description:
        "Request failed with status 504 Gateway Timeout | upstream timeout",
    });
  });

  it("passes the oauth error through", async () => {
    const result = { error: "invalid_grant", error_description: "expired" };
    mockFetch(() => Response.json(result, { status: 400 }));
    const e = await rejection(client.tokenExchange("token"));
    assert.deepEqual(e, { status: 400, result });
  });

  it("reports a json error of another shape as server_error", async () => {
    for (const foreign of [
      { error: { code: 429 }, error_description: "slow down" },
      { message: "Too Many Requests" },
      ["temporarily_unavailable"],
      "temporarily_unavailable",
    ]) {
      mockFetch(() =>
        Response.json(foreign, {
          status: 429,
          statusText: "Too Many Requests",
        }),
      );
      const e = await rejection(client.tokenExchange("token"));
      assert.deepEqual(
        e,
        {
          status: 429,
          result: {
            error: "server_error",
            error_description: `Request failed with status 429 Too Many Requests | ${JSON.stringify(foreign)}`,
          },
        },
        JSON.stringify(foreign),
      );
    }
  });

  it("drops an error_description which isn't a string", async () => {
    mockFetch(() =>
      Response.json(
        { error: "temporarily_unavailable", error_description: { a: 1 } },
        { status: 503 },
      ),
    );
    const e = await rejection(client.tokenExchange("token"));
    assert.deepEqual(e, {
      status: 503,
      result: { error: "temporarily_unavailable" },
    });
  });

  it("keeps only the string lines of a trace", async () => {
    for (const [trace, expected] of [
      ["s", []],
      [null, []],
      [{ a: 1 }, []],
      [["cause", 1, null, { a: 1 }, "root"], ["cause", "root"]],
    ]) {
      mockFetch(() =>
        Response.json(
          { error: "temporarily_unavailable", trace, code: 7 },
          { status: 503 },
        ),
      );
      const e = await rejection(client.tokenExchange("token"));
      assert.deepEqual(
        e,
        {
          status: 503,
          result: {
            error: "temporarily_unavailable",
            trace: expected,
            code: 7,
          },
        },
        JSON.stringify(trace),
      );
    }
  });

  it("describes a network failure", async () => {
    globalThis.fetch = async () => {
      throw new TypeError("fetch failed");
    };
    const e = await rejection(client.tokenExchange("token"));
    assert.equal(e.status, 1);
    assert.equal(
      e.result.error_description,
      "Request failed with error | TypeError: fetch failed",
    );
  });
});

describe("isReauthenticationRequired", () => {
  const error = `${REAUTHENTICATION_REQUIRED}: this needs a recent login`;

  it("is true for the reauthentication error", () => {
    assert.equal(
      isReauthenticationRequired({ status: 403, result: { error } }),
      true,
    );
  });

  it("is false for anything else, without throwing", () => {
    const throwing = {
      status: 403,
      get result() {
        throw new Error("getter");
      },
    };
    for (const e of [
      undefined,
      null,
      "",
      error,
      403,
      [],
      {},
      { status: 403 },
      { status: 403, result: null },
      { status: 403, result: error },
      { status: 403, result: { error: { code: 403 } } },
      { status: 403, result: { error: 403 } },
      { status: 403, result: { error: true } },
      { status: 403, result: { error: [error] } },
      { status: 403, result: { error: "Forbidden" } },
      { status: "403", result: { error } },
      { status: 401, result: { error } },
      throwing,
      new Proxy(
        {},
        {
          get() {
            throw new Error("proxy");
          },
        },
      ),
    ]) {
      assert.equal(isReauthenticationRequired(e), false);
    }
  });
});

describe("passkey requests", () => {
  // A credential without `toJSON`, its fields on the prototype
  // like the browser's `PublicKeyCredential`.
  class LegacyCredential {
    get id() {
      return "AQID";
    }
    get rawId() {
      return new Uint8Array([1, 2, 3]).buffer;
    }
    get type() {
      return "public-key";
    }
    get response() {
      return {
        clientDataJSON: new Uint8Array([4]).buffer,
        authenticatorData: new Uint8Array([5]).buffer,
        signature: new Uint8Array([6]).buffer,
        userHandle: null,
      };
    }
    getClientExtensionResults() {
      return {};
    }
  }

  it("sends the credential in its json form", async () => {
    mockFetch(() => Response.json({ type: "UserId", data: "x" }));
    await client.login("CompletePasskeyLogin", {
      credential: new LegacyCredential(),
    });
    assert.equal(sent.length, 1);
    assert.deepEqual(JSON.parse(sent[0].init.body), {
      credential: {
        id: "AQID",
        rawId: "AQID",
        type: "public-key",
        authenticatorAttachment: null,
        clientExtensionResults: {},
        response: {
          clientDataJSON: "BA",
          authenticatorData: "BQ",
          signature: "Bg",
          userHandle: null,
        },
      },
    });
  });

  it("leaves other requests alone", async () => {
    mockFetch(() => Response.json({}));
    await client.manage("UpdateUsername", { username: "credential" });
    assert.deepEqual(JSON.parse(sent[0].init.body), {
      username: "credential",
    });
  });
});

describe("safeBackto", () => {
  const origin = "https://app.example";
  for (const [backto, expected] of [
    ["/stacks/1?tab=logs#top", "/stacks/1?tab=logs#top"],
    ["/", "/"],
    [null, "/"],
    ["", "/"],
    ["@evil.example", "/"],
    [".evil.example", "/"],
    [":8443/x", "/"],
    ["https://evil.example/x", "/"],
    ["//evil.example/x", "/"],
    ["/\\evil.example/x", "/"],
    ["/\t/evil.example/x", "/"],
    ["javascript:alert(1)", "/"],
    ["/a/../b", "/b"],
    // Paths which only resolve to `//host` once dot segments are removed.
    ["/.//evil.example", "/evil.example"],
    ["/..//evil.example/x", "/evil.example/x"],
    ["/%2e//evil.example", "/evil.example"],
    ["/a/..//evil.example", "/evil.example"],
    ["/./\\evil.example", "/evil.example"],
    ["/./\\/evil.example?a=1#b", "/evil.example?a=1#b"],
  ]) {
    it(`${JSON.stringify(backto)} -> ${expected}`, () => {
      const path = safeBackto(backto, origin);
      assert.equal(path, expected);
      // Wherever it is navigated to, it stays on the origin.
      assert.equal(new URL(path, origin).origin, origin);
    });
  }
});
