import { expect, test } from "@playwright/test";
import {
  expectLoggedInAs,
  logIn,
  logOut,
  notification,
  signUp,
  uniqueName,
} from "./helpers";

test("unauthenticated visitors are sent to the login page", async ({
  page,
}) => {
  await page.goto("/notes");
  await expect(page).toHaveURL(/\/login\?backto=%2Fnotes/);
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
  // The static oidc provider is offered next to local login.
  await expect(page.getByRole("button", { name: /OIDC/ })).toBeVisible();
});

test("sign up, log out, log in", async ({ page }) => {
  const username = uniqueName("local");
  await signUp(page, username);
  await expect(page.getByTestId("welcome")).toContainText(username);
  // The server sees the browser's ip (mogh_request_ip).
  await expect(page.getByText("127.0.0.1")).toBeVisible();

  await logOut(page);
  await logIn(page, username);
  await expectLoggedInAs(page, username);

  // The token is kept, a reload stays logged in.
  await page.reload();
  await expectLoggedInAs(page, username);
});

test("login returns to the page which required it", async ({ page }) => {
  const username = uniqueName("backto");
  await signUp(page, username);
  await logOut(page);
  await page.goto("/tools");
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page.getByRole("textbox", { name: "Password", exact: true }).fill("correct-horse-battery");
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(page).toHaveURL(/\/tools$/);
  await expectLoggedInAs(page, username);
});

test("failed logins and invalid signups show the reason", async ({ page }) => {
  const username = uniqueName("fail");
  await signUp(page, username);
  await logOut(page);

  await logIn(page, username, "not-the-password");
  await expect(
    notification(page, /Invalid login credentials/),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();

  // A taken username is a conflict, not a server error.
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page.getByRole("textbox", { name: "Password", exact: true }).fill("correct-horse-battery");
  await page.getByRole("button", { name: "Sign Up" }).click();
  await expect(notification(page, /Username is already taken/)).toBeVisible();

  await page.getByRole("textbox", { name: "Username" }).fill(uniqueName("short"));
  await page.getByRole("textbox", { name: "Password", exact: true }).fill("short");
  await page.getByRole("button", { name: "Sign Up" }).click();
  await expect(notification(page, /at least 8 characters/)).toBeVisible();
});

test("update username and password", async ({ page }) => {
  const username = uniqueName("creds");
  const renamed = uniqueName("renamed");
  await signUp(page, username);
  await page.goto("/profile");

  await page.getByRole("textbox", { name: "Username" }).fill(renamed);
  await page.getByRole("button", { name: "Update Username" }).click();
  await expect(notification(page, "Username updated.")).toBeVisible();
  await expectLoggedInAs(page, renamed);

  await page.getByRole("textbox", { name: "New Password" }).fill("a-whole-new-password");
  await page.getByRole("button", { name: "Update Password" }).click();
  await expect(notification(page, "Password updated.")).toBeVisible();

  await logOut(page);
  await logIn(page, renamed, "a-whole-new-password");
  await expectLoggedInAs(page, renamed);
});
