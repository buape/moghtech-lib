import { Fragment, useState } from "react";
import { ConfigFieldArgs, ConfigGroupArgs } from ".";
import { ConfigInput, ConfigItem, ConfigSelector, ConfigSwitch } from "./item";
import { Group, NumberInput, Stack } from "@mantine/core";
import { CircleQuestionMark } from "lucide-react";

export function ConfigGroup<T>({
  config,
  update,
  setUpdate,
  disabled,
  fields,
}: {
  config: T;
  update: Partial<T>;
  setUpdate: (update: Partial<T>) => void;
  disabled: boolean;
  fields: ConfigGroupArgs<T>["fields"];
}) {
  return (
    <Stack gap="xl">
      {Object.entries(fields).map(([key, field]) => {
        const value =
          (update as { [key: string]: unknown })[key] ??
          (config as { [key: string]: unknown })[key];
        if (typeof field === "function") {
          return <Fragment key={key}>{field(value, setUpdate)}</Fragment>;
        } else if (typeof field === "object" || field === true) {
          const args =
            typeof field === "object" ? (field as ConfigFieldArgs) : undefined;

          if (args?.hidden) {
            return null;
          }

          switch (
            value !== undefined && value !== null ? typeof value : args?.type
          ) {
            case "string":
              if (args?.options) {
                return (
                  <ConfigSelector
                    key={key}
                    label={args?.label ?? key}
                    value={value as string}
                    options={args.options}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                    description={args?.description}
                  />
                );
              } else {
                return (
                  <ConfigInput
                    key={key}
                    label={args?.label ?? key}
                    value={value as string}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                    description={args?.description}
                  />
                );
              }

            case "number":
              return (
                <ConfigItem
                  key={key}
                  label={args?.label ?? key}
                  description={args?.description}
                >
                  <ConfigNumberInput
                    value={typeof value === "number" ? value : undefined}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                  />
                </ConfigItem>
              );

            case "boolean":
              return (
                <ConfigSwitch
                  key={key}
                  label={args?.label ?? key}
                  value={value as boolean}
                  onCheckedChange={(value) =>
                    setUpdate({ [key]: value } as Partial<T>)
                  }
                  disabled={args?.disabled || disabled}
                  description={args?.description}
                />
              );

            default:
              return (
                <Group>
                  Config '{args?.label ?? key}':{" "}
                  <CircleQuestionMark size="1rem" />
                </Group>
              );
          }
        } else {
          return <Fragment key={key} />;
        }
      })}
    </Stack>
  );
}

/**
 * Only complete numbers reach `onValueChange`: partial input ('' or
 * '-') stays in the input instead of becoming 0. On blur, the input
 * shows the stored value again, so it never disagrees with what Save
 * sends.
 */
function ConfigNumberInput({
  value,
  onValueChange,
  disabled,
  placeholder,
}: {
  value: number | undefined;
  onValueChange: (value: number) => void;
  disabled: boolean | undefined;
  placeholder: string | undefined;
}) {
  // The text while it isn't the stored number. NumberInput passes
  // strings for partial input, and for text it keeps as typed
  // ('1.', '0.10', 14+ digits).
  const [draft, setDraft] = useState<string>();
  return (
    <NumberInput
      w={{ base: "85%", lg: 400 }}
      value={draft ?? value ?? ""}
      onChange={(input) => {
        setDraft(typeof input === "string" ? input : undefined);
        const number =
          typeof input === "number"
            ? input
            : input.trim() === ""
              ? NaN
              : Number(input);
        if (Number.isFinite(number)) onValueChange(number);
      }}
      onBlur={() => setDraft(undefined)}
      disabled={disabled}
      placeholder={placeholder}
    />
  );
}
