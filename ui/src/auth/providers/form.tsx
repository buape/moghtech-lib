import {
  Alert,
  Button,
  Divider,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { Info, Save, ShieldAlert } from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import { CopyText, EnableSwitch, useManageAuth } from "../..";
import { LoginProviderIcon, LoginProviderKind } from "../login/providers";

type ListItem = MoghAuth.Types.ExternalLoginProviderListItem;
type ProviderConfig = MoghAuth.Types.ExternalLoginProviderConfig;

/** Flat form values covering every kind of provider. */
interface ProviderFormValues {
  name: string;
  registration_disabled: boolean;
  enabled: boolean;
  client_id: string;
  client_secret: string;
  /** Remove the stored secret. Not part of the provider config. */
  clear_client_secret: boolean;
  // Token exchange
  token_exchange_enabled: boolean;
  token_exchange_audiences: string[];
  /** 0 for no limit */
  token_exchange_max_age_secs: number;
  // OIDC
  provider: string;
  redirect_host: string;
  use_full_email: boolean;
  auto_redirect: boolean;
  additional_audiences: string[];
  additional_scopes: string[];
  groups_claim: string;
  allowed_groups: string[];
  admin_groups: string[];
}

function formValues(item: ListItem): ProviderFormValues {
  const { kind, params } = item.provider.config;
  const oidc = kind === "Oidc" ? params : undefined;
  return {
    name: item.provider.name,
    registration_disabled: item.provider.registration_disabled ?? false,
    enabled: params.enabled ?? false,
    client_id: params.client_id ?? "",
    // The secret is never sent to the client.
    // Left empty, the existing secret is kept.
    client_secret: "",
    clear_client_secret: false,
    token_exchange_enabled: item.provider.token_exchange?.enabled ?? false,
    token_exchange_audiences: item.provider.token_exchange?.audiences ?? [],
    token_exchange_max_age_secs:
      item.provider.token_exchange?.max_token_age_secs ?? 0,
    provider: oidc?.provider ?? "",
    redirect_host: oidc?.redirect_host ?? "",
    use_full_email: oidc?.use_full_email ?? false,
    auto_redirect: oidc?.auto_redirect ?? false,
    additional_audiences: oidc?.additional_audiences ?? [],
    additional_scopes: oidc?.additional_scopes ?? [],
    groups_claim: oidc?.groups_claim ?? "",
    allowed_groups: oidc?.allowed_groups ?? [],
    admin_groups: oidc?.admin_groups ?? [],
  };
}

function providerConfig(
  kind: LoginProviderKind,
  values: ProviderFormValues,
): ProviderConfig {
  const named = {
    enabled: values.enabled,
    client_id: values.client_id.trim(),
    client_secret: values.clear_client_secret ? "" : values.client_secret,
  };
  if (kind !== "Oidc") {
    return { kind, params: named } as ProviderConfig;
  }
  return {
    kind: "Oidc",
    params: {
      ...named,
      provider: values.provider.trim(),
      redirect_host: values.redirect_host.trim(),
      use_full_email: values.use_full_email,
      auto_redirect: values.auto_redirect,
      additional_audiences: values.additional_audiences,
      additional_scopes: values.additional_scopes,
      groups_claim: values.groups_claim.trim(),
      allowed_groups: values.allowed_groups,
      admin_groups: values.admin_groups,
    },
  };
}

function validHttpUrl(value: string) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

export function LoginProviderModal({
  item,
  justCreated,
  onClose,
  onSaved,
}: {
  /** The provider to view / edit, or undefined if closed. */
  item: ListItem | undefined;
  /** The provider was just created and still has to be configured. */
  justCreated?: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  return (
    <Modal
      opened={!!item}
      onClose={onClose}
      size="lg"
      title={
        item && (
          <Group gap="xs">
            <LoginProviderIcon kind={item.provider.config.kind} size="1.2rem" />
            <Text fz="h3">{item.provider.name}</Text>
          </Group>
        )
      }
    >
      {item && (
        <LoginProviderForm
          // Reset the form for another provider
          key={item.provider.id}
          item={item}
          justCreated={justCreated}
          onClose={onClose}
          onSaved={onSaved}
        />
      )}
    </Modal>
  );
}

/** The form inside [LoginProviderModal], to embed it elsewhere. */
export function LoginProviderForm({
  item,
  justCreated,
  onClose,
  onSaved,
}: {
  item: ListItem;
  justCreated?: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const kind = item.provider.config.kind;
  const readOnly = item.read_only;
  const existing = item.provider.config.params;
  const hasSecret = !!existing.client_secret;
  const existingProviderUrl =
    item.provider.config.kind === "Oidc"
      ? (item.provider.config.params.provider ?? "")
      : "";

  const form = useForm<ProviderFormValues>({
    mode: "controlled",
    initialValues: formValues(item),
    validate: {
      name: (name) => (name.trim().length ? null : "Name cannot be empty"),
      provider: (provider) =>
        kind === "Oidc" && provider.trim().length && !validHttpUrl(provider)
          ? "Must be an http(s) URL"
          : null,
      redirect_host: (host) =>
        kind === "Oidc" && host.trim().length && !validHttpUrl(host)
          ? "Must be an http(s) URL"
          : null,
      client_secret: (secret, values) => {
        if (values.clear_client_secret) return null;
        // The server won't send the stored secret to another address
        if (
          kind === "Oidc" &&
          hasSecret &&
          !secret.length &&
          values.provider.trim() !== existingProviderUrl
        ) {
          return "Enter the client secret again when changing the provider URL";
        }
        // Only OIDC works without a secret (public clients using PKCE)
        if (kind !== "Oidc" && values.enabled && !hasSecret && !secret.length) {
          return "A client secret is required to enable this provider";
        }
        return null;
      },
      token_exchange_max_age_secs: (age) =>
        typeof age === "number" && Number.isInteger(age) && age >= 0
          ? null
          : "Must be a whole number of seconds, 0 for no limit",
      clear_client_secret: (clear, values) =>
        clear && kind !== "Oidc" && values.enabled
          ? "Disable the provider to remove its secret, it can't work without one"
          : null,
    },
  });

  const { mutate: update, isPending } = useManageAuth(
    "UpdateExternalLoginProvider",
    {
      onSuccess: () => {
        notifications.show({ message: "Saved login provider." });
        onSaved();
        onClose();
      },
    },
  );

  const values = form.getValues();
  const groupsUsed =
    !!values.groups_claim.trim() ||
    values.allowed_groups.length > 0 ||
    values.admin_groups.length > 0;

  return (
    <form
      onSubmit={form.onSubmit((values) =>
        update({
          id: item.provider.id,
          name: values.name.trim(),
          registration_disabled: values.registration_disabled,
          // Github has no signed tokens to exchange
          token_exchange: {
            enabled: kind !== "Github" && values.token_exchange_enabled,
            audiences: values.token_exchange_audiences,
            max_token_age_secs: values.token_exchange_max_age_secs,
          },
          config: providerConfig(kind, values),
          clear_client_secret: values.clear_client_secret,
        }),
      )}
    >
      <Stack>
        {readOnly && (
          <Alert icon={<Info size="1rem" />} color="gray">
            This provider comes from the app configuration (file /
            environment), and can only be changed there.
          </Alert>
        )}

        {justCreated && (
          <Alert icon={<Info size="1rem" />} color="green">
            Provider created. Register the redirect URI below at the provider,
            then enter the client id and secret it gives you and enable the
            provider.
          </Alert>
        )}

        <Stack gap="0.2rem">
          <Text size="sm" fw={500}>
            Redirect URI
          </Text>
          <CopyText
            content={item.redirect_uri}
            label="redirect URI"
            w="100%"
            groupProps={{ w: "100%" }}
          />
          <Text size="xs" c="dimmed">
            Must be registered as an allowed redirect / callback URI at the
            provider.
          </Text>
        </Stack>

        <Group justify="space-between" align="end">
          <TextInput
            {...form.getInputProps("name")}
            label="Name"
            description="Shown on the login button"
            disabled={readOnly}
            style={{ flexGrow: 1 }}
          />
          <EnableSwitch
            checked={values.enabled}
            onCheckedChange={(enabled) =>
              form.setFieldValue("enabled", enabled)
            }
            disabled={readOnly}
            mb={6}
          />
        </Group>

        {kind === "Oidc" && (
          <TextInput
            {...form.getInputProps("provider")}
            label="Provider URL"
            description="The issuer address, as reachable from the app server. It must serve /.well-known/openid-configuration"
            placeholder="https://accounts.example.com/application/o/app"
            disabled={readOnly}
          />
        )}

        <TextInput
          {...form.getInputProps("client_id")}
          label="Client ID"
          autoComplete="off"
          disabled={readOnly}
        />

        <PasswordInput
          {...form.getInputProps("client_secret")}
          label="Client Secret"
          description={
            kind === "Oidc"
              ? "May be empty if the provider supports PKCE for public clients"
              : undefined
          }
          placeholder={
            values.clear_client_secret
              ? "Will be removed"
              : hasSecret
                ? "Unchanged"
                : "Enter client secret"
          }
          autoComplete="new-password"
          disabled={readOnly || values.clear_client_secret}
        />

        {/* Left empty the secret is kept, removing it has to be explicit */}
        {hasSecret && !readOnly && (
          <Switch
            {...form.getInputProps("clear_client_secret", {
              type: "checkbox",
            })}
            onChange={(e) => {
              form.setFieldValue("clear_client_secret", e.target.checked);
              if (e.target.checked) form.setFieldValue("client_secret", "");
            }}
            label="Remove the stored client secret"
            description={
              kind === "Oidc"
                ? "For a provider switched to a public client using PKCE"
                : "The provider has to be disabled, it can't work without a secret"
            }
            color="red"
          />
        )}

        <Switch
          {...form.getInputProps("registration_disabled", {
            type: "checkbox",
          })}
          label="Disable new user registration"
          description="Only users who already have an account can log in with this provider"
          disabled={readOnly}
        />

        {kind === "Oidc" && (
          <>
            <Divider label="Groups" labelPosition="left" />

            <TextInput
              {...form.getInputProps("groups_claim")}
              label="Groups Claim"
              description="The claim holding the user's groups. Nested claims use a dotted path, eg. realm_access.roles. Defaults to 'groups' when groups are used below."
              placeholder="groups"
              disabled={readOnly}
            />

            <TagsInput
              {...form.getInputProps("allowed_groups")}
              label="Allowed Groups"
              description="Only members of one of these groups (or an admin group) can log in. Empty allows everyone."
              placeholder="Add group"
              disabled={readOnly}
            />

            <TagsInput
              {...form.getInputProps("admin_groups")}
              label="Admin Groups"
              description="Members of these groups are made admins when they log in"
              placeholder="Add group"
              disabled={readOnly}
            />

            {values.admin_groups.length > 0 && !readOnly && (
              <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
                Anyone who controls membership of these groups at the provider
                can make themselves an admin here.
              </Alert>
            )}

            <TagsInput
              {...form.getInputProps("additional_scopes")}
              label="Additional Scopes"
              description={
                "Requested on top of openid, profile and email. The 'groups' scope is requested automatically when the provider advertises it." +
                (groupsUsed
                  ? " Add the scope your provider needs for the groups claim if it is named differently."
                  : "")
              }
              placeholder="Add scope"
              disabled={readOnly}
            />

            <Divider label="Advanced" labelPosition="left" />

            <TextInput
              {...form.getInputProps("redirect_host")}
              label="Redirect Host"
              description="The provider address users are redirected to in their browser, if it differs from the Provider URL. Host only, without a path."
              placeholder="https://accounts.example.com"
              disabled={readOnly}
            />

            <TagsInput
              {...form.getInputProps("additional_audiences")}
              label="Additional Audiences"
              description="Audiences the provider sets on its tokens other than the client id"
              placeholder="Add audience"
              disabled={readOnly}
            />

            <Switch
              {...form.getInputProps("use_full_email", { type: "checkbox" })}
              label="Use full email as username"
              description="Otherwise new users are named after the part before the @"
              disabled={readOnly}
            />

            <Switch
              {...form.getInputProps("auto_redirect", { type: "checkbox" })}
              label="Auto redirect"
              description="Send users straight to this provider instead of showing the login page. Add ?disableAutoLogin to the login URL to get the page back."
              disabled={readOnly}
            />
          </>
        )}

        {kind !== "Github" && (
          <>
            <Divider label="Token Exchange" labelPosition="left" />

            <Switch
              {...form.getInputProps("token_exchange_enabled", {
                type: "checkbox",
              })}
              label="Allow token exchange"
              description="Lets a client which already holds a token of a user from this provider (eg. a CLI or script) swap it for an app token at the token endpoint, without a browser login. Only for users who already exist."
              disabled={readOnly}
            />

            {values.token_exchange_enabled && (
              <>
                <TagsInput
                  {...form.getInputProps("token_exchange_audiences")}
                  label="Accepted Audiences"
                  description="Client ids of other apps at this provider whose tokens are accepted, in addition to the Client ID above"
                  placeholder="Add client id"
                  // The server accepts at most 16
                  maxTags={16}
                  disabled={readOnly}
                />

                <NumberInput
                  {...form.getInputProps("token_exchange_max_age_secs")}
                  label="Maximum Token Age"
                  description="Only accept tokens issued at most this many seconds ago. 0 accepts them until they expire, which can be hours. Clients should exchange a token right after receiving it, so a few minutes (eg. 300) is enough."
                  suffix=" seconds"
                  min={0}
                  allowDecimal={false}
                  allowNegative={false}
                  disabled={readOnly}
                />

                {!readOnly && (
                  <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
                    Anyone holding a valid token of a user can log in as them
                    without interaction
                    {values.token_exchange_audiences.length > 0
                      ? ", including tokens issued to every app listed above."
                      : "."}{" "}
                    Users who need a second factor for external logins can't
                    use it.
                  </Alert>
                )}
              </>
            )}
          </>
        )}

        <Group justify="end" mt="sm">
          <Button variant="default" onClick={onClose}>
            {readOnly ? "Close" : "Cancel"}
          </Button>
          {!readOnly && (
            <Button
              type="submit"
              loading={isPending}
              leftSection={<Save size="1rem" />}
            >
              Save
            </Button>
          )}
        </Group>
      </Stack>
    </form>
  );
}
