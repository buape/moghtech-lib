import { EXAMPLE_BASE_URL } from "@/main";
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationOptions,
  type UseQueryOptions,
} from "@tanstack/react-query";
import {
  ExampleClient,
  MoghAuth,
  Types,
  type ExecuteResponses,
  type ReadResponses,
  type WriteResponses,
} from "example_client";
import { notifications } from "@mantine/notifications";

/**
 * The login tokens kept in the browser (`localStorage`).
 * The auth client leaves them unset where that is unavailable.
 */
export function loginTokens() {
  const tokens = MoghAuth.LOGIN_TOKENS;
  if (!tokens) {
    throw new Error(
      "MoghAuth.LOGIN_TOKENS is unset: localStorage is unavailable.",
    );
  }
  return tokens;
}

/** A fresh client per call, so it always uses the current token. */
export function example_client() {
  return ExampleClient(EXAMPLE_BASE_URL, {
    type: "jwt",
    params: { jwt: loginTokens().jwt() },
  });
}

// A token the server already rejected isn't sent again:
// every rejected request counts against the auth rate limit.
let rejectedJwt: string | undefined;

export function useUser() {
  const jwt = loginTokens().jwt();
  return useQuery({
    queryKey: ["GetUser"],
    queryFn: async () => {
      try {
        return await example_client().getUser();
      } catch (e) {
        const status = (e as { status?: number }).status;
        if (status === 401 || status === 403) rejectedJwt = jwt;
        throw e;
      }
    },
    refetchInterval: 30_000,
    enabled: !!jwt && jwt !== rejectedJwt,
  });
}

export function useUserInvalidate() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["GetUser"] });
  };
}

//

export function useRead<
  T extends Types.ReadRequest["type"],
  R extends Extract<Types.ReadRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseQueryOptions<
      ReadResponses[R["type"]],
      unknown,
      ReadResponses[R["type"]],
      (T | P)[]
    >,
    "queryFn" | "queryKey"
  >,
>(type: T, params: P, config?: C) {
  const hasJwt = !!loginTokens().jwt();
  return useQuery({
    queryKey: [type, params],
    queryFn: () => example_client().read<T, R>(type, params),
    ...config,
    // After the spread, so a caller's `enabled` can't remove the token gate.
    enabled: hasJwt && (config?.enabled ?? true),
  });
}

/** `invalidate(["ListNotes"], ["GetNote", { id }])` */
export function useInvalidate() {
  const qc = useQueryClient();
  return <
    Type extends Types.ReadRequest["type"],
    Params extends Extract<Types.ReadRequest, { type: Type }>["params"],
  >(
    ...keys: Array<[Type] | [Type, Params]>
  ) => keys.forEach((key) => qc.invalidateQueries({ queryKey: key }));
}

//

type ApiError = { result?: { error?: string; trace?: string[] } };

function notifyError(kind: string, type: string, e: ApiError) {
  console.log(`${kind} error:`, e);
  const msg = e.result?.error || "Unknown error. See console.";
  // Skip the causes the message already shows, eg. a failed
  // attempt's error under the rate limit's attempts remaining note.
  const detail = e.result?.trace
    ?.filter((cause) => !msg.includes(cause))
    .map((msg) => msg[0].toUpperCase() + msg.slice(1))
    .join(" | ");
  let msg_log = msg[0].toUpperCase() + msg.slice(1) + " | ";
  if (detail) {
    msg_log += detail + " | ";
  }
  notifications.show({
    title: `${kind} request ${type} failed`,
    message: `${msg_log}See console for details`,
    color: "red",
  });
}

export function useWrite<
  T extends Types.WriteRequest["type"],
  R extends Extract<Types.WriteRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<WriteResponses[R["type"]], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => example_client().write<T, R>(type, params),
    // After the spread, so a caller's `onError` extends the notification.
    onError: (e: ApiError, ...args) => {
      notifyError("Write", type, e);
      config?.onError && config.onError(e, ...args);
    },
  });
}

export function useExecute<
  T extends Types.ExecuteRequest["type"],
  R extends Extract<Types.ExecuteRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<ExecuteResponses[R["type"]], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => example_client().execute<T, R>(type, params),
    onError: (e: ApiError, ...args) => {
      notifyError("Execute", type, e);
      config?.onError && config.onError(e, ...args);
    },
  });
}
