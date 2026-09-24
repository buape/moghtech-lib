import type * as Types from "./types.js";

/**
 ## USAGE:
 ```
 navigator.credentials
  .get(prepareRequestChallengeResponse(requestChallengeResponse))
  .then((credential) =>
    completePasskeyLogin({ credential: credentialToJSON(credential) })
  )
 ```
 */
export function prepareRequestChallengeResponse(
  challenge: Types.RequestChallengeResponse,
) {
  return {
    ...challenge,
    publicKey: {
      ...challenge.publicKey,
      challenge: base64urlToArrayBuffer(challenge.publicKey.challenge),
      allowCredentials: challenge.publicKey.allowCredentials?.map(
        (cred: any) => ({
          ...cred,
          id: base64urlToArrayBuffer(cred.id),
        }),
      ),
    },
  };
}

/**
 ## USAGE:
 ```
 navigator.credentials
  .create(prepareCreationChallengeResponse(creationChallengeResponse))
  .then((credential) =>
    confirmPasskeyEnrollment({ credential: credentialToJSON(credential) })
  )
 ```
 */
export function prepareCreationChallengeResponse(
  challenge: Types.CreationChallengeResponse,
) {
  return {
    ...challenge,
    publicKey: {
      ...challenge.publicKey,
      challenge: base64urlToArrayBuffer(challenge.publicKey.challenge),
      user: {
        ...challenge.publicKey.user,
        id: base64urlToArrayBuffer(challenge.publicKey.user.id),
      },
      excludeCredentials: challenge.publicKey.excludeCredentials?.map(
        (cred: any) => ({ ...cred, id: base64urlToArrayBuffer(cred.id) }),
      ),
    },
  };
}

/**
 * A passkey credential in the JSON form the server expects
 * (`PublicKeyCredential.toJSON`): binary fields are base64url strings.
 */
export type PublicKeyCredentialJson = {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string | null;
  clientExtensionResults?: Record<string, unknown>;
  response: Record<string, unknown>;
};

/** The parts of a `PublicKeyCredential` read by `credentialToJSON`. */
type CredentialLike = {
  id?: string;
  rawId?: unknown;
  type?: string;
  authenticatorAttachment?: string | null;
  response?: {
    clientDataJSON?: unknown;
    // Assertion (login)
    authenticatorData?: unknown;
    signature?: unknown;
    userHandle?: unknown;
    // Attestation (enrollment)
    attestationObject?: unknown;
    transports?: unknown;
    getTransports?: () => unknown;
  };
  getClientExtensionResults?: () => unknown;
  toJSON?: () => unknown;
};

/**
 * The credential returned by `navigator.credentials.get` / `.create`,
 * in the JSON form to send in `CompletePasskeyLogin` /
 * `ConfirmPasskeyEnrollment`. `MoghAuthClient` applies it to those
 * requests already, use it when sending the credential another way.
 *
 * Uses the browser's `PublicKeyCredential.toJSON` where it exists.
 * Older browsers, and some password manager extensions, return
 * credentials without it, which `JSON.stringify` turns into `{}`: their
 * binary fields are base64url encoded here instead. A credential which
 * is already in JSON form is returned as is.
 */
export function credentialToJSON(
  credential: object | null | undefined,
): PublicKeyCredentialJson {
  if (!credential) {
    throw new Error("No passkey credential was returned.");
  }
  const c = credential as CredentialLike;
  if (typeof c.toJSON === "function") {
    return c.toJSON() as PublicKeyCredentialJson;
  }
  if (typeof c.rawId === "string") {
    return credential as PublicKeyCredentialJson;
  }
  const rawId = binaryToBase64url(c.rawId);
  const response = c.response ?? {};
  const json: Record<string, unknown> = {
    clientDataJSON: binaryToBase64url(response.clientDataJSON),
  };
  if (response.attestationObject !== undefined) {
    json.attestationObject = binaryToBase64url(response.attestationObject);
    const transports =
      typeof response.getTransports === "function"
        ? response.getTransports()
        : response.transports;
    if (Array.isArray(transports)) json.transports = transports;
  } else {
    json.authenticatorData = binaryToBase64url(response.authenticatorData);
    json.signature = binaryToBase64url(response.signature);
    json.userHandle =
      response.userHandle == null
        ? null
        : binaryToBase64url(response.userHandle);
  }
  return {
    id: c.id ?? rawId,
    rawId,
    type: c.type ?? "public-key",
    authenticatorAttachment: c.authenticatorAttachment ?? null,
    clientExtensionResults: toJsonValue(
      c.getClientExtensionResults?.() ?? {},
    ) as Record<string, unknown>,
    response: json,
  };
}

/** Base64url encode an ArrayBuffer / typed array. Strings pass through. */
function binaryToBase64url(value: unknown): string {
  if (typeof value === "string") return value;
  if (isArrayBuffer(value)) return arrayBufferToBase64url(value);
  if (ArrayBuffer.isView(value)) {
    return arrayBufferToBase64url(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
    );
  }
  throw new Error("Invalid passkey credential: missing binary field.");
}

/** Also true for an ArrayBuffer of another realm (eg. an extension). */
function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return Object.prototype.toString.call(value) === "[object ArrayBuffer]";
}

/** Base64url encode the binary values nested in `value`. */
function toJsonValue(value: unknown): unknown {
  if (isArrayBuffer(value) || ArrayBuffer.isView(value)) {
    return binaryToBase64url(value);
  }
  if (Array.isArray(value)) return value.map(toJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, toJsonValue(v)]),
    );
  }
  return value;
}

export function base64urlToArrayBuffer(base64url: any) {
  // Convert from URL-safe base64 to normal base64
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad =
    base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  const bstr = atob(base64 + pad);
  const bytes = new Uint8Array(bstr.length);
  for (let i = 0; i < bstr.length; i++) {
    bytes[i] = bstr.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToBase64url(buffer: any) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(str: string) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  return atob(base64);
}
