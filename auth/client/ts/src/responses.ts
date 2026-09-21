import * as Types from "./types.js";

export type LoginResponses = {
  GetLoginOptions: Types.GetLoginOptionsResponse;
  SignUpLocalUser: Types.SignUpLocalUserResponse;
  LoginLocalUser: Types.LoginLocalUserResponse;
  ExchangeForJwt: Types.ExchangeForJwtResponse;
  ExchangeExternalForJwt: Types.ExchangeExternalForJwtResponse;
  CompleteTotpLogin: Types.CompleteTotpLoginResponse;
  CompletePasskeyLogin: Types.CompletePasskeyLoginResponse;
  CompleteTotpRecoveryLogin: Types.CompleteTotpRecoveryLoginResponse;
};

export type ManageResponses = {
  GetUserId: Types.GetUserIdResponse;
  // Local
  UpdateUsername: Types.UpdateUsernameResponse;
  UpdatePassword: Types.UpdatePasswordResponse;
  // External
  BeginExternalLoginLink: Types.BeginExternalLoginLinkResponse;
  UnlinkLocalLogin: Types.UnlinkLocalLoginResponse;
  UnlinkExternalLogin: Types.UnlinkExternalLoginResponse;
  // External login providers (admin)
  ListExternalLoginProviders: Types.ListExternalLoginProvidersResponse;
  CreateExternalLoginProvider: Types.CreateExternalLoginProviderResponse;
  UpdateExternalLoginProvider: Types.UpdateExternalLoginProviderResponse;
  DeleteExternalLoginProvider: Types.DeleteExternalLoginProviderResponse;
  // Trusted issuers for workload identity (admin)
  ListTrustedIssuers: Types.ListTrustedIssuersResponse;
  CreateTrustedIssuer: Types.CreateTrustedIssuerResponse;
  UpdateTrustedIssuer: Types.UpdateTrustedIssuerResponse;
  DeleteTrustedIssuer: Types.DeleteTrustedIssuerResponse;
  // Passkey
  BeginPasskeyEnrollment: Types.BeginPasskeyEnrollmentResponse;
  ConfirmPasskeyEnrollment: Types.ConfirmPasskeyEnrollmentResponse;
  UnenrollPasskey: Types.UnenrollPasskeyResponse;
  // Totp
  BeginTotpEnrollment: Types.BeginTotpEnrollmentResponse;
  ConfirmTotpEnrollment: Types.ConfirmTotpEnrollmentResponse;
  UnenrollTotp: Types.UnenrollTotpResponse;
  // Skip
  UpdateExternalSkip2fa: Types.UpdateExternalSkip2faResponse;
  // API KEY
  CreateApiKey: Types.CreateApiKeyResponse;
  DeleteApiKey: Types.DeleteApiKeyResponse;
  CreateApiKeyV2: Types.CreateApiKeyV2Response;
  DeleteApiKeyV2: Types.DeleteApiKeyV2Response;
};
