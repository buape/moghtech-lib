import { LoginPage } from "mogh_ui";
import { useUser, useUserInvalidate } from "@/lib/hooks";

export default function Login(props: {
  passkeyIsPending?: boolean;
  totpIsPending?: boolean;
}) {
  const userInvalidate = useUserInvalidate();
  const user = useUser().data;
  return (
    <LoginPage
      {...props}
      // Known from the app's own query, so the login
      // page doesn't have to ask the auth api itself.
      alreadyLoggedIn={!!user}
      appName="EXAMPLE"
      iconLink="/mogh-512x512.png"
      iconLinkAlt="moghtech"
      exampleConfigLink="https://github.com/moghtech/lib/blob/main/example/README.md"
      onLogin={userInvalidate}
    />
  );
}
