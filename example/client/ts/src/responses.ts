import * as Types from "./types.js";

export type ReadResponses = {
  GetVersion: Types.GetVersionResponse;
  GetCoreInfo: Types.GetCoreInfoResponse;
  GetRequestInfo: Types.GetRequestInfoResponse;
  GetStats: Types.GetStatsResponse;

  // ==== USER ====
  GetUser: Types.GetUserResponse;
  ListUsers: Types.ListUsersResponse;
  ListApiKeys: Types.ListApiKeysResponse;

  // ==== NOTE ====
  ListNotes: Types.ListNotesResponse;
  GetNote: Types.GetNoteResponse;
};

export type WriteResponses = {
  // ==== NOTE ====
  CreateNote: Types.CreateNoteResponse;
  UpdateNote: Types.UpdateNoteResponse;
  DeleteNote: Types.DeleteNoteResponse;

  // ==== USER ====
  UpdateCidrWhitelist: Types.UpdateCidrWhitelistResponse;
  UpdateUserAccess: Types.UpdateUserAccessResponse;
  DeleteUser: Types.DeleteUserResponse;
};

export type ExecuteResponses = {
  GenerateKeyPair: Types.GenerateKeyPairResponse;
  SealText: Types.SealTextResponse;
  OpenText: Types.OpenTextResponse;
  ValidateString: Types.ValidateStringResponse;
};
