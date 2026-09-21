import { expect, test } from "@playwright/test";
import {
  expectLoggedInAs,
  notification,
  PASSWORD,
  signUp,
  uniqueName,
} from "./helpers";

test("changing credentials needs a recent login", async ({ page }) => {
  test.setTimeout(90_000);
  const username = uniqueName("reauth");
  await signUp(page, username);

  // The server is configured with a 15 second window for these tests.
  await page.waitForTimeout(17_000);

  await page.goto("/profile");
  await page
    .getByRole("textbox", { name: "New Password" })
    .fill("a-whole-new-password");
  await page.getByRole("button", { name: "Update Password" }).click();
  await expect(notification(page, /Log in again to continue/)).toBeVisible();

  // Sent to the login page, and back to the profile after logging in.
  await expect(page).toHaveURL(/\/login\?backto=%2Fprofile/, {
    timeout: 15_000,
  });
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page
    .getByRole("textbox", { name: "Password", exact: true })
    .fill(PASSWORD);
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(page).toHaveURL(/\/profile$/);
  await expectLoggedInAs(page, username);

  // The old password was never changed, now it can be.
  await page
    .getByRole("textbox", { name: "New Password" })
    .fill("a-whole-new-password");
  await page.getByRole("button", { name: "Update Password" }).click();
  await expect(notification(page, "Password updated.")).toBeVisible();

  // Everything else kept working the whole time.
  await page.goto("/notes");
  await expect(page.getByText("No notes yet.")).toBeVisible();
});
