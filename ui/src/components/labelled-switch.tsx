import {
  Group,
  GroupProps,
  Switch,
  SwitchProps,
  Text,
  TextProps,
} from "@mantine/core";
import { ReactNode } from "react";

export interface LabelledSwitchProps extends SwitchProps {
  checked: boolean | undefined;
  onCheckedChange: (checked: boolean) => void;
  label?: ReactNode;
  groupProps?: GroupProps;
  labelProps?: TextProps;
}

export function LabelledSwitch({
  checked,
  onCheckedChange,
  label,
  groupProps,
  labelProps,
  disabled,
  ...switchProps
}: LabelledSwitchProps) {
  return (
    <Group
      gap="xs"
      onClick={(e) => {
        e.preventDefault();
        // The whole group is the click target (the switch ignores
        // pointer events), so it has to honor `disabled` itself.
        if (disabled) return;
        onCheckedChange(!checked);
      }}
      className="bordered-light"
      px="xs"
      py={4}
      bdrs="sm"
      style={{ cursor: disabled ? "not-allowed" : "pointer" }}
      aria-disabled={disabled || undefined}
      justify="space-between"
      w={{ base: "100%", xs: "fit-content" }}
      {...groupProps}
    >
      <Text c={checked ? undefined : "dimmed"} {...labelProps}>
        {label}
      </Text>
      <Switch
        checked={checked}
        disabled={disabled}
        style={{ pointerEvents: "none" }}
        {...switchProps}
      />
    </Group>
  );
}
