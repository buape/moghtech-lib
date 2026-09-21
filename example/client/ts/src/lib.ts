import { MoghAuthClient } from "mogh_auth_client";
import {
  ExecuteResponses,
  ReadResponses,
  WriteResponses,
} from "./responses.js";
import {
  ExecuteRequest,
  ReadRequest,
  User,
  WriteRequest,
} from "./types.js";

export * as MoghAuth from "mogh_auth_client";
export * as Types from "./types.js";
export type {
  ExecuteResponses,
  ReadResponses,
  WriteResponses,
} from "./responses.js";

export type InitOptions =
  | { type: "jwt"; params: { jwt: string } }
  | { type: "api-key"; params: { key: string; secret: string } };

/** What failed requests reject with. `status: 1` means the server wasn't reached. */
export type RequestError = {
  status: number;
  result: { error?: string; trace?: string[] };
  error?: unknown;
};

export function ExampleClient(url: string, options: InitOptions) {
  const state = {
    jwt: options.type === "jwt" ? options.params.jwt : undefined,
    key: options.type === "api-key" ? options.params.key : undefined,
    secret: options.type === "api-key" ? options.params.secret : undefined,
  };

  const auth = MoghAuthClient(url + "/auth", state.jwt);

  const request = <Params, Res>(
    path: "/user" | "/read" | "/write" | "/execute",
    type: string,
    params: Params,
    method = "POST",
  ): Promise<Res> =>
    new Promise(async (res, rej) => {
      try {
        const response = await fetch(`${url}${path}${type ? "/" + type : ""}`, {
          method,
          body: method === "GET" ? undefined : JSON.stringify(params),
          headers: {
            ...(state.jwt
              ? { authorization: state.jwt }
              : state.key && state.secret
                ? { "x-api-key": state.key, "x-api-secret": state.secret }
                : {}),
            "content-type": "application/json",
          },
          credentials: "include",
        });
        if (response.status === 200) {
          const body: Res = await response.json();
          res(body);
        } else {
          try {
            const result = await response.json();
            rej({ status: response.status, result });
          } catch (error) {
            rej({
              status: response.status,
              result: {
                error: "Failed to get response body",
                trace: [String(error)],
              },
              error,
            });
          }
        }
      } catch (error) {
        rej({
          status: 1,
          result: {
            error: "Request failed with error",
            trace: [String(error)],
          },
          error,
        });
      }
    });

  /** Get the calling user. Also works for users who aren't enabled. */
  const getUser = async () =>
    await request<undefined, User>("/user", "", undefined, "GET");

  const read = async <
    T extends ReadRequest["type"],
    Req extends Extract<ReadRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], ReadResponses[Req["type"]]>(
      "/read",
      type,
      params,
    );

  const write = async <
    T extends WriteRequest["type"],
    Req extends Extract<WriteRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], WriteResponses[Req["type"]]>(
      "/write",
      type,
      params,
    );

  const execute = async <
    T extends ExecuteRequest["type"],
    Req extends Extract<ExecuteRequest, { type: T }>,
  >(
    type: T,
    params: Req["params"],
  ) =>
    await request<Req["params"], ExecuteResponses[Req["type"]]>(
      "/execute",
      type,
      params,
    );

  return {
    /** Call the `/auth` api (login and credential management). */
    auth,
    getUser,
    /** Call the `/read` api. */
    read,
    /** Call the `/write` api. */
    write,
    /** Call the `/execute` api. */
    execute,
  };
}
