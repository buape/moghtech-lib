// Tokens the server refused, shared by the auth queries.
// Not exported from the package.

// Every request which fails auth counts against the server's per IP
// auth rate limit, which logging in shares. A token the server
// rejected isn't sent again.
let rejectedJwt: string | undefined;

/** Whether there is a token, and the server hasn't rejected it yet. */
export function sendableJwt(jwt: string | undefined): jwt is string {
  return !!jwt && jwt !== rejectedJwt;
}

/**
 * Runs a request made with `jwt`, remembering the token as
 * rejected when the server refuses it with one of `rejectedOn`.
 */
export async function guardJwt<T>(
  jwt: string | undefined,
  rejectedOn: number[],
  request: () => Promise<T>,
): Promise<T> {
  try {
    return await request();
  } catch (e) {
    const status = (e as { status?: number } | undefined)?.status;
    if (status !== undefined && rejectedOn.includes(status)) {
      rejectedJwt = jwt;
    }
    throw e;
  }
}

/**
 * Query options which keep a query from sending a token the server
 * refused again, whatever the host's query client defaults: only a
 * request which never reached the server (the client's status 1) is
 * retried, and an error isn't refetched when the window is focused.
 */
export const SEND_REJECTED_ONCE = {
  retry: (failures: number, e: unknown) =>
    (e as { status?: number } | undefined)?.status === 1 && failures < 3,
  refetchOnWindowFocus: false,
} as const;
