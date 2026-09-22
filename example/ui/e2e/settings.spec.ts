import { expect, test } from "@playwright/test";
import {
  expectLoggedInAs,
  logIn,
  logOut,
  signUp,
  uniqueName,
} from "./helpers";
import { ADMIN, ADMIN_PASSWORD } from "./global-setup";
import { IDP_URL } from "../playwright.config";

test("settings are for admins", async ({ page }) => {
  await signUp(page, uniqueName("plain"));
  await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0);
  await page.goto("/settings");
  await expect(
    page.getByText("Only admins can change the settings."),
  ).toBeVisible();
});

test("admin enables and disables users", async ({ page, browser }) => {
  // Another browser (own storage) for the user being managed.
  const username = uniqueName("managed");
  const userContext = await browser.newContext();
  const userPage = await userContext.newPage();
  await signUp(userPage, username);

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");
  const row = page.getByTestId(`user-row-${username}`);
  await expect(row).toBeVisible();
  // The switch reflects the server state, which changes after the write.
  const enabled = row.getByRole("switch", { name: `${username} enabled` });
  await expect(enabled).toBeChecked();
  await enabled.click({ force: true });
  await expect(enabled).not.toBeChecked();

  await userPage.reload();
  await expect(userPage.getByText("User not enabled")).toBeVisible();

  await enabled.click({ force: true });
  await expect(enabled).toBeChecked();
  await userPage.reload();
  await expectLoggedInAs(userPage, username);
  await userContext.close();
});

test("admin adds a login provider, which users can use to log in", async ({
  page,
}) => {
  const providerName = uniqueName("SSO");
  const idpUser = uniqueName("sso-user");
  await page.request.post(`${IDP_URL}/control/users`, {
    data: { sub: `${idpUser}-sub`, preferred_username: idpUser },
  });

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");

  // The provider from the server config is listed, read only.
  await expect(page.getByRole("row", { name: /OIDC/ }).first()).toBeVisible();

  await page.getByRole("button", { name: "New Login Provider" }).click();
  await page
    .getByRole("dialog")
    .getByRole("textbox", { name: "Name" })
    .fill(providerName);
  await page.getByRole("dialog").getByRole("button", { name: "Create" }).click();

  // Continues with the full configuration of the new provider.
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Provider created.")).toBeVisible();
  await expect(dialog.getByText(/\/auth\/external\/.+\/callback/)).toBeVisible();
  await dialog.getByRole("textbox", { name: "Provider URL" }).fill(IDP_URL);
  await dialog.getByRole("textbox", { name: "Client ID" }).fill("example-client-id");
  await dialog
    .getByRole("textbox", { name: "Client Secret" })
    .fill("example-client-secret");
  await dialog.getByRole("switch").first().check({ force: true });
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog).toHaveCount(0);

  // The secret is never sent back to the browser.
  await page.getByText(providerName, { exact: true }).click();
  await expect(
    page.getByRole("dialog").getByRole("textbox", { name: "Client Secret" }),
  ).toHaveValue("");
  await expect(page.locator("body")).not.toContainText("example-client-secret");
  await page.keyboard.press("Escape");

  await logOut(page);
  await page.getByRole("button", { name: new RegExp(providerName) }).click();
  await page.getByTestId(`idp-user-${idpUser}-sub`).click();
  await expectLoggedInAs(page, idpUser);
});

test("admin adds a workload identity issuer, a job exchanges its token", async ({
  page,
  request,
}) => {
  const issuerName = uniqueName("CI");
  const audience = `https://example-app.test/${issuerName}`;

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");
  await page.getByRole("button", { name: "New Trusted Issuer" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill(issuerName);
  await dialog.getByRole("textbox", { name: "Issuer", exact: true }).fill(IDP_URL);
  const audiences = dialog.getByPlaceholder(/audience/i).first();
  await audiences.fill(audience);
  await audiences.press("Enter");

  await dialog.getByRole("button", { name: /Add Rule/i }).click();
  await dialog.getByRole("textbox", { name: "Rule Name" }).fill("Deploy");
  await dialog.getByPlaceholder(/claim/i).first().fill("repository_id");
  await dialog.getByPlaceholder(/pattern|value/i).first().fill("12345");
  await dialog.getByRole("button", { name: /Save|Create/ }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("row", { name: new RegExp(issuerName) })).toBeVisible();

  // The job gets a token from its platform (the mock idp) ...
  const minted = await request.post(`${IDP_URL}/control/mint`, {
    data: {
      sub: "repo:my-org/my-repo",
      aud: [audience],
      claims: { repository_id: "12345" },
    },
  });
  const { token } = await minted.json();
  // ... and exchanges it for an app token.
  const exchanged = await request.post("/auth/token", {
    form: {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: token,
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    },
  });
  expect(exchanged.status(), await exchanged.text()).toBe(200);
  const { access_token } = await exchanged.json();
  const info = await request.post("/read/GetRequestInfo", {
    headers: { authorization: `Bearer ${access_token}` },
    data: {},
  });
  expect(info.status()).toBe(200);

  // Its user shows up for the admin, marked as a workload.
  await page.reload();
  await expect(
    page.getByTestId("user-row-workload-deploy").first(),
  ).toContainText("Workload");
});
