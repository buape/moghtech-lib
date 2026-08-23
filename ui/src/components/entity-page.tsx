import { Group, Stack, StackProps } from "@mantine/core";
import { ReactNode } from "react";
import { BackButton } from "./back-button";

export interface EntityPageProps extends StackProps {
  backTo?: string;
  breadcrumbs?: ReactNode;
  actions?: ReactNode;
}

export function EntityPage({
  backTo,
  breadcrumbs,
  actions,
  children,
  ...props
}: EntityPageProps) {
  return (
    <Stack mb="50vh" {...props}>
      <Group justify="space-between">
        {breadcrumbs ? (
          <Group>
            <BackButton to={backTo} />
            {breadcrumbs}
          </Group>
        ) : (
          <BackButton to={backTo} />
        )}
        {actions && <Group wrap="nowrap">{actions}</Group>}
      </Group>
      {children}
    </Stack>
  );
}
