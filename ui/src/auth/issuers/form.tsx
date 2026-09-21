import {
  ActionIcon,
  Alert,
  Button,
  Divider,
  Group,
  Modal,
  NumberInput,
  SegmentedControl,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import {
  CircleMinus,
  Info,
  Plus,
  Save,
  ShieldAlert,
  Trash,
} from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import { EnableSwitch, useManageAuth } from "../..";

type ListItem = MoghAuth.Types.TrustedIssuerListItem;
type TrustedIssuer = MoghAuth.Types.TrustedIssuer;
type KeysSource = MoghAuth.Types.TrustedIssuerKeys["source"];

interface RuleFormValues {
  /** Empty for rules which don't exist yet. */
  id: string;
  name: string;
  enabled: boolean;
  claims: { claim: string; pattern: string }[];
  groups: string[];
  admin: boolean;
  token_ttl_secs: number;
}

interface IssuerFormValues {
  name: string;
  enabled: boolean;
  issuer: string;
  keys_source: KeysSource;
  /** The url / key set json, depending on the source. */
  keys_url: string;
  keys_static: string;
  audiences: string[];
  max_token_age_secs: number;
  rules: RuleFormValues[];
}

const KEYS_SOURCES: { value: KeysSource; label: string }[] = [
  { value: "Discovery", label: "Discovery" },
  { value: "JwksUri", label: "Keys URL" },
  { value: "Static", label: "Static keys" },
];

const newRule = (): RuleFormValues => ({
  id: "",
  name: "",
  enabled: true,
  claims: [{ claim: "", pattern: "" }],
  groups: [],
  admin: false,
  // Workloads should get short lived tokens
  token_ttl_secs: 900,
});

function formValues(issuer: TrustedIssuer | undefined): IssuerFormValues {
  const keys = issuer?.keys;
  return {
    name: issuer?.name ?? "",
    enabled: issuer?.enabled ?? true,
    issuer: issuer?.issuer ?? "",
    keys_source: keys?.source ?? "Discovery",
    keys_url: keys?.source === "JwksUri" ? keys.params : "",
    keys_static: keys?.source === "Static" ? keys.params : "",
    // An audience specific to this app, the platform
    // default is shared with every other service.
    audiences: issuer?.audiences ?? [location.origin],
    max_token_age_secs: issuer?.max_token_age_secs ?? 300,
    rules: (issuer?.rules ?? []).map((rule) => ({
      id: rule.id ?? "",
      name: rule.name,
      enabled: rule.enabled ?? false,
      claims: (rule.claims ?? []).map((c) => ({ ...c })),
      groups: rule.groups ?? [],
      admin: rule.admin ?? false,
      token_ttl_secs: rule.token_ttl_secs ?? 0,
    })),
  };
}

function trustedIssuer(id: string, values: IssuerFormValues): TrustedIssuer {
  const keys: MoghAuth.Types.TrustedIssuerKeys =
    values.keys_source === "JwksUri"
      ? { source: "JwksUri", params: values.keys_url.trim() }
      : values.keys_source === "Static"
        ? { source: "Static", params: values.keys_static }
        : { source: "Discovery", params: {} };
  return {
    id,
    name: values.name.trim(),
    enabled: values.enabled,
    issuer: values.issuer.trim(),
    keys,
    audiences: values.audiences,
    max_token_age_secs: values.max_token_age_secs,
    rules: values.rules.map((rule) => ({
      ...rule,
      name: rule.name.trim(),
      claims: rule.claims.map(({ claim, pattern }) => ({
        claim: claim.trim(),
        pattern,
      })),
    })),
  };
}

function validHttpUrl(value: string) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

const wholeSeconds = (value: unknown) =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? null
    : "Must be a whole number of seconds";

export function TrustedIssuerModal({
  opened,
  item,
  groupOptions,
  onClose,
  onSaved,
}: {
  opened: boolean;
  /** The issuer to view / edit, or undefined to create one. */
  item: ListItem | undefined;
  /** The groups of the app, suggested for the groups of a rule. */
  groupOptions?: string[];
  onClose: () => void;
  onSaved: () => void;
}) {
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      size="xl"
      title={<Text fz="h3">{item?.issuer.name ?? "New Trusted Issuer"}</Text>}
    >
      {opened && (
        <TrustedIssuerForm
          // Reset the form for another issuer
          key={item?.issuer.id ?? "new"}
          item={item}
          groupOptions={groupOptions}
          onClose={onClose}
          onSaved={onSaved}
        />
      )}
    </Modal>
  );
}

/** The form inside [TrustedIssuerModal], to embed it elsewhere. */
export function TrustedIssuerForm({
  item,
  groupOptions,
  onClose,
  onSaved,
}: {
  item: ListItem | undefined;
  groupOptions?: string[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const readOnly = item?.read_only ?? false;

  const form = useForm<IssuerFormValues>({
    mode: "controlled",
    initialValues: formValues(item?.issuer),
    validate: {
      name: (name) => (name.trim().length ? null : "Name cannot be empty"),
      issuer: (issuer) =>
        validHttpUrl(issuer.trim()) ? null : "Must be an http(s) URL",
      keys_url: (url, values) =>
        values.keys_source !== "JwksUri" || validHttpUrl(url.trim())
          ? null
          : "Must be an http(s) URL",
      keys_static: (keys, values) => {
        if (values.keys_source !== "Static") return null;
        try {
          return Array.isArray(JSON.parse(keys).keys)
            ? null
            : 'Must be a key set: { "keys": [...] }';
        } catch {
          return "Must be valid JSON";
        }
      },
      // What ties a token to this app
      audiences: (audiences) =>
        audiences.length ? null : "At least one audience is required",
      max_token_age_secs: wholeSeconds,
      rules: {
        name: (name) => (name.trim().length ? null : "Name cannot be empty"),
        token_ttl_secs: wholeSeconds,
        claims: {
          claim: (claim) => (claim.trim().length ? null : "Required"),
          // The server refuses patterns which match anything
          pattern: (pattern) =>
            !pattern.length
              ? "Required"
              : /^\*+$/.test(pattern)
                ? "Matches any value, which restricts nothing"
                : null,
        },
      },
    },
  });

  const onSuccess = () => {
    notifications.show({ message: "Saved trusted issuer." });
    onSaved();
    onClose();
  };
  const { mutate: create, isPending: createPending } = useManageAuth(
    "CreateTrustedIssuer",
    { onSuccess },
  );
  const { mutate: update, isPending: updatePending } = useManageAuth(
    "UpdateTrustedIssuer",
    { onSuccess },
  );

  const values = form.getValues();

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        // A rule without claims would accept every token of the issuer
        const empty = values.rules.find((rule) => !rule.claims.length);
        if (empty) {
          notifications.show({
            message: `Rule '${empty.name}' needs at least one claim to match.`,
            color: "red",
          });
          return;
        }
        const issuer = trustedIssuer(item?.issuer.id ?? "", values);
        item ? update({ issuer }) : create({ issuer });
      })}
    >
      <Stack>
        {readOnly && (
          <Alert icon={<Info size="1rem" />} color="gray">
            This issuer comes from the app configuration (file / environment),
            and can only be changed there.
          </Alert>
        )}

        <Group justify="space-between" align="end">
          <TextInput
            {...form.getInputProps("name")}
            label="Name"
            placeholder="eg. Github Actions"
            disabled={readOnly}
            style={{ flexGrow: 1 }}
            data-autofocus
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

        <TextInput
          {...form.getInputProps("issuer")}
          label="Issuer"
          description="The issuer (iss) of the tokens, eg. https://token.actions.githubusercontent.com, or the issuer url of a Kubernetes cluster"
          placeholder="https://token.actions.githubusercontent.com"
          disabled={readOnly}
        />

        <Stack gap="0.3rem">
          <Text size="sm" fw={500}>
            Signing Keys
          </Text>
          <SegmentedControl
            value={values.keys_source}
            onChange={(source) =>
              form.setFieldValue("keys_source", source as KeysSource)
            }
            data={KEYS_SOURCES}
            disabled={readOnly}
            fullWidth
          />
          {values.keys_source === "Discovery" && (
            <Text size="xs" c="dimmed">
              Loaded from the issuer's /.well-known/openid-configuration. Works
              for Github Actions, Gitlab, and clusters which expose their
              discovery publicly.
            </Text>
          )}
          {values.keys_source === "JwksUri" && (
            <TextInput
              {...form.getInputProps("keys_url")}
              description="The url of the key set (JWKS), as reachable from the app server"
              placeholder="https://issuer.example.com/keys"
              disabled={readOnly}
            />
          )}
          {values.keys_source === "Static" && (
            <Textarea
              {...form.getInputProps("keys_static")}
              description="The key set (JWKS json), for issuers the app server can't reach, like most clusters: kubectl get --raw /openid/v1/jwks. Has to be updated when the issuer rotates its keys."
              placeholder='{ "keys": [...] }'
              autosize
              minRows={3}
              maxRows={8}
              styles={{ input: { fontFamily: "monospace" } }}
              disabled={readOnly}
            />
          )}
        </Stack>

        <TagsInput
          {...form.getInputProps("audiences")}
          label="Audiences"
          description="The audience (aud) the workload requests its token for. Use one specific to this app, like its url. The default audience of a platform is shared with every other service trusting it, and any of them could replay the tokens they receive."
          placeholder="Add audience"
          maxTags={16}
          disabled={readOnly}
        />

        <NumberInput
          {...form.getInputProps("max_token_age_secs")}
          label="Maximum Token Age"
          description="Only accept tokens issued at most this many seconds ago. 0 accepts them until they expire."
          suffix=" seconds"
          min={0}
          allowDecimal={false}
          allowNegative={false}
          disabled={readOnly}
        />

        <Divider label="Rules" labelPosition="left" />

        <Text size="sm" c="dimmed">
          A token is accepted by the first enabled rule it meets all the claims
          of. Each rule has its own user, with the groups given here.
        </Text>

        {values.rules.map((rule, r) => (
          <Stack
            key={r}
            className="bordered-light"
            bdrs="md"
            p="md"
            gap="sm"
          >
            <Group justify="space-between" align="end">
              <TextInput
                {...form.getInputProps(`rules.${r}.name`)}
                label="Rule Name"
                description="Names the user of the rule"
                placeholder="eg. Deploy"
                disabled={readOnly}
                style={{ flexGrow: 1 }}
              />
              <EnableSwitch
                checked={rule.enabled}
                onCheckedChange={(enabled) =>
                  form.setFieldValue(`rules.${r}.enabled`, enabled)
                }
                disabled={readOnly}
                mb={6}
              />
              {!readOnly && (
                <ActionIcon
                  color="red"
                  variant="light"
                  size="lg"
                  mb={2}
                  title="Remove rule"
                  onClick={() => form.removeListItem("rules", r)}
                >
                  <Trash size="1rem" />
                </ActionIcon>
              )}
            </Group>

            <Stack gap="0.3rem">
              <Text size="sm" fw={500}>
                Claims
              </Text>
              <Text size="xs" c="dimmed">
                All of them have to match. * matches any run of characters.
                Prefer claims which can't be changed or reused over names (eg.
                Github's repository_id over repository), and keep wildcards
                narrow. Nested claims use a dotted path, eg.
                kubernetes.io.namespace.
              </Text>
              {rule.claims.map((_, c) => (
                <Group key={c} gap="xs" wrap="nowrap" align="start">
                  <TextInput
                    {...form.getInputProps(`rules.${r}.claims.${c}.claim`)}
                    placeholder="Claim, eg. sub"
                    disabled={readOnly}
                    style={{ flex: 1 }}
                  />
                  <TextInput
                    {...form.getInputProps(`rules.${r}.claims.${c}.pattern`)}
                    placeholder="Value, eg. repo:my-org/my-repo:ref:refs/heads/main"
                    disabled={readOnly}
                    style={{ flex: 2 }}
                  />
                  {!readOnly && (
                    <ActionIcon
                      color="red"
                      variant="subtle"
                      mt={4}
                      title="Remove claim"
                      onClick={() =>
                        form.removeListItem(`rules.${r}.claims`, c)
                      }
                    >
                      <CircleMinus size="1rem" />
                    </ActionIcon>
                  )}
                </Group>
              ))}
              {!readOnly && (
                <Button
                  variant="subtle"
                  size="compact-sm"
                  w="fit-content"
                  leftSection={<Plus size="0.9rem" />}
                  onClick={() =>
                    form.insertListItem(`rules.${r}.claims`, {
                      claim: "",
                      pattern: "",
                    })
                  }
                >
                  Add claim
                </Button>
              )}
            </Stack>

            <TagsInput
              {...form.getInputProps(`rules.${r}.groups`)}
              label="Groups"
              description="The groups of the rule's user, which decide what the workload can do"
              placeholder="Add group"
              data={groupOptions}
              disabled={readOnly}
            />

            <NumberInput
              {...form.getInputProps(`rules.${r}.token_ttl_secs`)}
              label="App Token Lifetime"
              description="How long the token given to the workload is valid. 0 and anything longer use the app default."
              suffix=" seconds"
              min={0}
              allowDecimal={false}
              allowNegative={false}
              disabled={readOnly}
            />

            <Switch
              {...form.getInputProps(`rules.${r}.admin`, {
                type: "checkbox",
              })}
              label="Admin"
              description="The rule's user is an admin"
              color="red"
              disabled={readOnly}
            />

            {rule.admin && !readOnly && (
              <Alert icon={<ShieldAlert size="1rem" />} color="yellow">
                Every workload matching this rule acts as an admin. Make sure
                its claims only match what you intend.
              </Alert>
            )}
          </Stack>
        ))}

        {!readOnly && (
          <Button
            variant="default"
            w="fit-content"
            leftSection={<Plus size="1rem" />}
            onClick={() => form.insertListItem("rules", newRule())}
          >
            Add rule
          </Button>
        )}

        <Group justify="end" mt="sm">
          <Button variant="default" onClick={onClose}>
            {readOnly ? "Close" : "Cancel"}
          </Button>
          {!readOnly && (
            <Button
              type="submit"
              loading={createPending || updatePending}
              leftSection={<Save size="1rem" />}
            >
              {item ? "Save" : "Create"}
            </Button>
          )}
        </Group>
      </Stack>
    </form>
  );
}
