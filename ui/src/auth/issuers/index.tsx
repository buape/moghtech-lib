import { useState } from "react";
import { Badge, Button, Group, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, ServerCog, Trash, View } from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import {
  ConfirmModal,
  DataTable,
  Section,
  SectionProps,
  useManageAuth,
  useTrustedIssuers,
} from "../..";
import { TrustedIssuerModal } from "./form";

export * from "./form";

type ListItem = MoghAuth.Types.TrustedIssuerListItem;

/**
 * Manage the token issuers trusted for workload identity: CI jobs,
 * Kubernetes service accounts and other machines exchange the token
 * their platform issues them for an app token, without an api key.
 * For use in app settings pages.
 *
 * The API behind it is limited to admin users, see `AuthUserImpl::is_admin`.
 * Issuers from the app configuration are listed read only.
 */
export function TrustedIssuersTable({
  groupOptions,
  ...sectionProps
}: {
  /** The groups of the app, suggested for the groups of a rule. */
  groupOptions?: string[];
} & SectionProps) {
  const queryClient = useQueryClient();
  const { data: issuers, isPending, error } = useTrustedIssuers();

  const [opened, setOpened] = useState<{ id: string | undefined }>();
  const openedItem = issuers?.find((item) => item.issuer.id === opened?.id);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["ListTrustedIssuers"] });

  const { mutateAsync: deleteIssuer, isPending: deletePending } =
    useManageAuth("DeleteTrustedIssuer", {
      onSuccess: () => {
        notifications.show({ message: "Deleted trusted issuer." });
        invalidate();
      },
    });

  return (
    <Section
      title="Workload Identity"
      titleFz="h3"
      icon={<ServerCog size="1.2rem" />}
      description="Token issuers (CI platforms, Kubernetes clusters) whose workloads can get an app token without an api key."
      withBorder
      isPending={isPending}
      error={
        error
          ? (((error as any)?.result?.error as string | undefined) ??
            "Failed to load trusted issuers")
          : false
      }
      actions={
        <Button
          leftSection={<Plus size="1rem" />}
          onClick={() => setOpened({ id: undefined })}
          w={{ base: "100%", xs: "fit-content" }}
        >
          New Trusted Issuer
        </Button>
      }
      {...sectionProps}
    >
      <DataTable
        noBorder
        tableKey="manage-trusted-issuers-v1"
        data={issuers ?? []}
        noResults={<Text c="dimmed">No trusted issuers configured.</Text>}
        onRowClick={(item) => setOpened({ id: item.issuer.id })}
        columns={[
          {
            header: "Name",
            accessorFn: (item: ListItem) => item.issuer.name,
            cell: ({ row: { original: item } }) => (
              <Text fw="bold">{item.issuer.name}</Text>
            ),
          },
          {
            header: "Issuer",
            accessorFn: (item: ListItem) => item.issuer.issuer,
            cell: ({ row: { original: item } }) => (
              <Text
                size="sm"
                maw="30vw"
                title={item.issuer.issuer}
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  textWrap: "nowrap",
                }}
              >
                {item.issuer.issuer}
              </Text>
            ),
          },
          {
            header: "Status",
            accessorFn: (item: ListItem) =>
              item.issuer.enabled ? "Enabled" : "Disabled",
            cell: ({ row: { original: item } }) => (
              <Badge color={item.issuer.enabled ? "green.8" : "red"}>
                {item.issuer.enabled ? "Enabled" : "Disabled"}
              </Badge>
            ),
          },
          {
            header: "Rules",
            accessorFn: (item: ListItem) =>
              String(item.issuer.rules?.length ?? 0),
            cell: ({ row: { original: item } }) => {
              const rules = item.issuer.rules ?? [];
              const enabled = rules.filter((rule) => rule.enabled).length;
              return (
                <Group gap="xs" wrap="nowrap">
                  <Text size="sm">
                    {enabled === rules.length
                      ? rules.length
                      : `${enabled} of ${rules.length} enabled`}
                  </Text>
                  {rules.some((rule) => rule.enabled && rule.admin) && (
                    <Badge color="yellow" title="A rule grants admin">
                      Admin
                    </Badge>
                  )}
                </Group>
              );
            },
          },
          {
            header: "Source",
            accessorFn: (item: ListItem) =>
              item.read_only ? "Config" : "Managed",
            cell: ({ row: { original: item } }) =>
              item.read_only ? (
                <Badge
                  color="gray"
                  title="From the app configuration, read only"
                >
                  Config
                </Badge>
              ) : (
                <Badge color="blue">Managed</Badge>
              ),
          },
          {
            header: "Actions",
            cell: ({ row: { original: item } }) => (
              <Group gap="xs" wrap="nowrap">
                <Button
                  variant="default"
                  leftSection={
                    item.read_only ? (
                      <View size="1rem" />
                    ) : (
                      <Pencil size="1rem" />
                    )
                  }
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpened({ id: item.issuer.id });
                  }}
                >
                  {item.read_only ? "View" : "Edit"}
                </Button>
                {!item.read_only && (
                  <ConfirmModal
                    icon={<Trash size="1rem" />}
                    confirmText={item.issuer.name}
                    title="Delete Trusted Issuer"
                    loading={deletePending}
                    onConfirm={() => deleteIssuer({ id: item.issuer.id })}
                    targetProps={{ w: "fit-content" }}
                    confirmProps={{ variant: "filled", color: "red" }}
                    topAdditonal={
                      <Text>
                        Workloads of <b>{item.issuer.name}</b> can no longer
                        get app tokens, and the users of its rules are removed.
                        To pause it instead, disable the issuer.
                      </Text>
                    }
                  >
                    Delete
                  </ConfirmModal>
                )}
              </Group>
            ),
          },
        ]}
      />

      <TrustedIssuerModal
        opened={!!opened}
        item={openedItem}
        groupOptions={groupOptions}
        onClose={() => setOpened(undefined)}
        onSaved={invalidate}
      />
    </Section>
  );
}
