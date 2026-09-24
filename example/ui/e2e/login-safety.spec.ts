import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import {
  enrollTotp,
  expectLoggedInAs,
  freshCode,
  logOut,
  notification,
  PASSWORD,
  signUp,
  uniqueName,
} from "./helpers";
import { ADMIN, ADMIN_PASSWORD } from "./global-setup";
import { APP_URL, IDP_URL } from "../playwright.config";

/**
 * What the login flows do with input anyone can put in a link:
 * `backto`, `login_error`, `passkey` and `redeem_ready`.
 */

async function logInAt(page: Page, url: string, username: string) {
  await page.goto(url);
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page
    .getByRole("textbox", { name: "Password", exact: true })
    .fill(PASSWORD);
  await page.getByRole("button", { name: "Log In" }).click();
}

test("login only returns to pages of the app", async ({ page }) => {
  const username = uniqueName("backto-safe");
  await signUp(page, username);
  await logOut(page);

  // Scripts, other sites and what only becomes one once parsed.
  for (const backto of [
    "javascript:window.__pwned=1",
    "//evil.example/login",
    "/\\evil.example/login",
    "/\t/evil.example/login",
    "https://evil.example/login",
    `${APP_URL}@evil.example/login`,
  ]) {
    await logInAt(
      page,
      `/login?backto=${encodeURIComponent(backto)}`,
      username,
    );
    await expect(page, backto).toHaveURL(`${APP_URL}/`);
    await expectLoggedInAs(page, username);
    expect(
      await page.evaluate(
        () => (window as unknown as { __pwned?: number }).__pwned,
      ),
      backto,
    ).toBeUndefined();
  }

  // A path which resolves to `//host` stays a path.
  await logInAt(
    page,
    `/login?backto=${encodeURIComponent("/.//evil.example")}`,
    username,
  );
  await expect(page).toHaveURL(`${APP_URL}/evil.example`);

  // Pages of the app keep their query.
  await logInAt(
    page,
    `/login?backto=${encodeURIComponent("/tools?tab=a#b")}`,
    username,
  );
  await expect(page).toHaveURL(`${APP_URL}/tools?tab=a#b`);
});

test("the back button of the login page stays in the app", async ({ page }) => {
  await signUp(page, uniqueName("back"));
  await page.goto(
    `/login?backto=${encodeURIComponent("https://evil.example/login")}`,
  );
  await expect(page.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/",
  );
  await page.goto(`/login?backto=${encodeURIComponent("/tools")}`);
  await expect(page.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/tools",
  );
});

async function addIdpUser(page: Page, username: string) {
  const res = await page.request.post(`${IDP_URL}/control/users`, {
    data: { sub: `${username}-sub`, preferred_username: username },
  });
  expect(res.ok()).toBeTruthy();
}

async function pickIdpUser(page: Page, username: string) {
  await expect(page.getByText("Mock Identity Provider")).toBeVisible();
  await page.getByTestId(`idp-user-${username}-sub`).click();
}

test("second factor of an external login while still signed in", async ({
  page,
}) => {
  const username = uniqueName("oidc2fa-again");
  await addIdpUser(page, username);
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  const { totp } = await enrollTotp(page);

  // Logging in again (eg. to reauthenticate) without logging out.
  // The second factor is shown outside the app's router, and the
  // old token still says somebody is signed in.
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expect(page).toHaveURL(/totp=true/);
  await page
    .getByRole("textbox", { name: "2FA Code" })
    .fill(freshCode(totp, "next"));
  await page.getByRole("button", { name: "Log In" }).click();
  await expectLoggedInAs(page, username);
  await expect(page).not.toHaveURL(/totp=true/);
});

test("a passkey challenge which can't be read doesn't crash the app", async ({
  page,
}) => {
  for (const passkey of ["x", "e30", "bnVsbA"]) {
    await page.goto(`/?passkey=${passkey}`);
    await expect(
      notification(page, "Invalid passkey challenge").first(),
    ).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
    await expect(page).not.toHaveURL(/passkey=/);
  }
});

test("a failed redeem falls back to the login page", async ({ page }) => {
  // No external login happened, the session has nothing to redeem.
  await page.goto("/?redeem_ready=true");
  await expect(notification(page, /ExchangeForJwt failed/)).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
  await expect(page).not.toHaveURL(/redeem_ready/);
});

test("a login error in a link isn't shown as the app's message", async ({
  page,
}) => {
  const spoofed = "Your account is locked. Call support at +1-555-0100";
  await page.goto(`/login?login_error=${encodeURIComponent(spoofed)}`);
  await expect(
    notification(page, "The external login didn't complete."),
  ).toBeVisible();
  await expect(page.locator("body")).not.toContainText("+1-555-0100");
  await expect(page).toHaveURL(/\/login$/);
});

test("a finished external login or link doesn't vouch for a later login error", async ({
  page,
}) => {
  const spoofed = "Your account is locked. Call support at +1-555-0100";
  async function expectNotVouched() {
    await page.goto(`/login?login_error=${encodeURIComponent(spoofed)}`);
    await expect(
      notification(page, "The external login didn't complete."),
    ).toBeVisible();
    await expect(page.locator("body")).not.toContainText("+1-555-0100");
  }

  // A link which succeeded comes back without any query.
  const idpUser = uniqueName("vouch-link-idp");
  await addIdpUser(page, idpUser);
  await signUp(page, uniqueName("vouch-link"));
  await page.goto("/profile");
  await page.getByRole("button", { name: "Link OIDC" }).click();
  await pickIdpUser(page, idpUser);
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    `${idpUser}-sub`,
  );
  await expectNotVouched();

  // A login which comes back for the second factor.
  const username = uniqueName("vouch-2fa");
  await addIdpUser(page, username);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  await enrollTotp(page);
  await logOut(page);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expect(page).toHaveURL(/totp=true/);
  await expectNotVouched();
});

/** A fresh admin token, manage requests need a recent login. */
async function adminJwt(request: APIRequestContext): Promise<string> {
  const login = await request.post("/auth/login/LoginLocalUser", {
    data: { username: ADMIN, password: ADMIN_PASSWORD },
  });
  expect(login.ok(), await login.text()).toBeTruthy();
  return (await login.json()).data.jwt;
}

test("auto redirect to a provider stops when the login fails", async ({
  page,
  request,
}) => {
  const created = await request.post(
    "/auth/manage/CreateExternalLoginProvider",
    {
      headers: { authorization: await adminJwt(request) },
      data: {
        name: uniqueName("Auto SSO"),
        registration_disabled: false,
        config: {
          kind: "Oidc",
          params: {
            enabled: true,
            provider: IDP_URL,
            client_id: "example-client-id",
            client_secret: "example-client-secret",
            auto_redirect: true,
          },
        },
      },
    },
  );
  expect(created.ok(), await created.text()).toBeTruthy();
  const providerId: string = (await created.json()).provider.id;

  try {
    let providerVisits = 0;
    page.on("request", (req) => {
      if (/\/auth\/external\/[^/]+\/login/.test(req.url())) providerVisits++;
    });
    // Straight to the provider, where the user says no.
    await page.goto("/login");
    await expect(page.getByText("Mock Identity Provider")).toBeVisible();
    await page.getByTestId("idp-deny").click();

    // Back on the login page with the reason, which stays.
    await expect(notification(page, /access_denied/)).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
    await page.waitForTimeout(2_000);
    await expect(page).toHaveURL(new RegExp(`^${APP_URL}/login`));
    await expect(page.getByText("Mock Identity Provider")).toHaveCount(0);
    expect(providerVisits).toBe(1);
  } finally {
    // Every other test expects the login page.
    const deleted = await request.post(
      "/auth/manage/DeleteExternalLoginProvider",
      {
        headers: { authorization: await adminJwt(request) },
        data: { id: providerId },
      },
    );
    expect(deleted.ok(), await deleted.text()).toBeTruthy();
  }
});
