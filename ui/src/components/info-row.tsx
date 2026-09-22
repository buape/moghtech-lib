import { Group, GroupProps, Text } from "@mantine/core";
import { ReactNode } from "react";

export interface InfoRowProps extends GroupProps {
  label: string;
  children: ReactNode;
}

/** One label / value row of an entity page's details section. */
export function InfoRow({ label, children, ...props }: InfoRowProps) {
  return (
    <Group gap="md" wrap="nowrap" align="baseline" {...props}>
      <Text c="dimmed" size="sm" w="10rem" style={{ flexShrink: 0 }}>
        {label}
      </Text>
      {typeof children === "string" ? <Text>{children}</Text> : children}
    </Group>
  );
}
