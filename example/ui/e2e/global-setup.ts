import { request } from "@playwright/test";
import { APP_URL } from "../playwright.config";

export const ADMIN = "admin";
export const ADMIN_PASSWORD = "admin-password-e2e";

/** The first user to sign up is the admin, make it a known one. */
export default async function globalSetup() {
  const api = await request.newContext({ baseURL: APP_URL });
  const res = await api.post("/auth/login/SignUpLocalUser", {
    data: { username: ADMIN, password: ADMIN_PASSWORD },
  });
  if (!res.ok()) {
    throw new Error(`Failed to create the admin: ${await res.text()}`);
  }
  await api.dispose();
}
