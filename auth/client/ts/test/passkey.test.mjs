import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { credentialToJSON } = await import("../dist/passkey.js");

const bytes = (...values) => new Uint8Array(values).buffer;

describe("credentialToJSON", () => {
  it("encodes an assertion without toJSON", () => {
    const credential = {
      id: "AQID",
      rawId: bytes(1, 2, 3),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: bytes(0xfb, 0xff),
        authenticatorData: bytes(5),
        // A view into a larger buffer.
        signature: new Uint8Array([9, 6, 9]).subarray(1, 2),
        userHandle: bytes(7),
      },
      getClientExtensionResults: () => ({
        hmacGetSecret: { output1: bytes(8) },
      }),
    };
    // `JSON.stringify` alone loses the binary fields.
    assert.deepEqual(JSON.parse(JSON.stringify(credential)).rawId, {});
    assert.deepEqual(credentialToJSON(credential), {
      id: "AQID",
      rawId: "AQID",
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: { hmacGetSecret: { output1: "CA" } },
      response: {
        clientDataJSON: "-_8",
        authenticatorData: "BQ",
        signature: "Bg",
        userHandle: "Bw",
      },
    });
  });

  it("encodes an attestation without toJSON", () => {
    const credential = {
      rawId: bytes(1, 2, 3),
      type: "public-key",
      response: {
        clientDataJSON: bytes(4),
        attestationObject: bytes(5),
        getTransports() {
          return ["internal", "hybrid"];
        },
      },
    };
    assert.deepEqual(credentialToJSON(credential), {
      id: "AQID",
      rawId: "AQID",
      type: "public-key",
      authenticatorAttachment: null,
      clientExtensionResults: {},
      response: {
        clientDataJSON: "BA",
        attestationObject: "BQ",
        transports: ["internal", "hybrid"],
      },
    });
  });

  it("uses toJSON where the browser has it", () => {
    const json = { id: "a", rawId: "a", type: "public-key", response: {} };
    assert.equal(credentialToJSON({ toJSON: () => json }), json);
  });

  it("returns a credential in json form as is", () => {
    const json = { id: "a", rawId: "a", type: "public-key", response: {} };
    assert.equal(credentialToJSON(json), json);
  });

  it("rejects a missing credential", () => {
    assert.throws(() => credentialToJSON(null), /No passkey credential/);
  });
});
