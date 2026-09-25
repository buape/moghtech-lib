import { useRef, useState } from "react";
import { useDisclosure } from "@mantine/hooks";
import { Box, Button, Group, Modal, Stack, Text } from "@mantine/core";
import { Save } from "lucide-react";
import { ShowHideButton } from "../show-hide-button";
import { MonacoDiffEditor, MonacoLanguage } from "../monaco";
import { deepCompare } from "../../utils";
import { fmtSnakeCaseToUpperSpaceCase } from "../../formatting";
import { useCtrlKeyListener, useKeyListener } from "../../hooks";
import {
  confirmDialogOpen,
  saveButtonFocus,
  useCountOpenConfirm,
} from "./confirm-open";

export interface ConfirmUpdateProps<T> {
  original: T;
  update: Partial<T>;
  onConfirm: () => Promise<unknown>;
  loading?: boolean;
  disabled: boolean;
  language?: MonacoLanguage;
  fileContentsLanguage?: MonacoLanguage;
  fullWidth?: boolean;
  /** Ctrl / Cmd + Enter opens the dialog. Default: true */
  openKeyListener?: boolean;
  /** See `ConfirmUpdateModalProps.confirmKeyListener`. Default: true */
  confirmKeyListener?: boolean;
  enableFancyToml?: boolean;
  /** Fields whose values are never shown, see `ConfigProps.secretKeys`. */
  secretKeys?: (keyof T)[];
}

/**
 * A Save button opening a dialog which lists the changes (`update`
 * against `original`), saved with the dialog's own Save button.
 *
 * Keys: Ctrl / Cmd + Enter (outside of text inputs) opens the dialog,
 * Enter in the open dialog confirms. When several are mounted, only the
 * first one takes a press, and none opens while a confirm dialog (of
 * any ConfirmUpdate / Config) is open.
 */
export function ConfirmUpdate<T>({
  original,
  update,
  onConfirm,
  loading,
  disabled,
  language,
  fileContentsLanguage,
  fullWidth,
  openKeyListener = true,
  confirmKeyListener = true,
  enableFancyToml,
  secretKeys,
}: ConfirmUpdateProps<T>) {
  const [opened, { open, close }] = useDisclosure();

  useCtrlKeyListener("Enter", (e) => {
    // Declined presses keep their default. `defaultPrevented`: another
    // ConfirmUpdate on the page already took this one.
    if (
      opened ||
      confirmDialogOpen() ||
      !openKeyListener ||
      disabled ||
      e.defaultPrevented
    ) {
      return false;
    }
    open();
  });

  return (
    <>
      <ConfirmUpdateModal
        opened={opened}
        onClose={close}
        original={original}
        update={update}
        onConfirm={onConfirm}
        loading={loading}
        disabled={disabled}
        language={language}
        fileContentsLanguage={fileContentsLanguage}
        confirmKeyListener={confirmKeyListener}
        enableFancyToml={enableFancyToml}
        secretKeys={secretKeys}
      />

      <Button
        leftSection={<Save size="1rem" />}
        onClick={(e) => {
          e.stopPropagation();
          open();
        }}
        disabled={disabled}
        w={fullWidth ? undefined : 100}
        fullWidth={fullWidth}
      >
        Save
      </Button>
    </>
  );
}

export interface ConfirmUpdateModalProps<T> {
  opened: boolean;
  onClose: () => void;
  original: T;
  update: Partial<T>;
  /**
   * The dialog closes once this resolves. When it rejects, the dialog
   * stays open to retry (showing the error is up to `onConfirm`).
   */
  onConfirm: () => Promise<unknown>;
  loading?: boolean;
  disabled?: boolean;
  language?: MonacoLanguage;
  fileContentsLanguage?: MonacoLanguage;
  /**
   * Enter in the open dialog confirms, which opens with its Save button
   * focused. When false, Enter only does what the focused element does,
   * and the dialog opens with its close button focused. Default: true
   */
  confirmKeyListener?: boolean;
  enableFancyToml?: boolean;
  /** Fields whose values are never shown, see `ConfigProps.secretKeys`. */
  secretKeys?: (keyof T)[];
}

/**
 * The confirm dialog of `ConfirmUpdate`, with its open state controlled
 * by the caller. For one dialog behind several Save buttons (see
 * `Config`). Runs one save at a time: presses while a save is in flight
 * are ignored.
 */
export function ConfirmUpdateModal<T>({
  opened,
  onClose,
  original,
  update,
  onConfirm,
  loading,
  disabled,
  language,
  fileContentsLanguage,
  confirmKeyListener = true,
  enableFancyToml,
  secretKeys,
}: ConfirmUpdateModalProps<T>) {
  const [saving, setSaving] = useState(false);
  // State lags a render behind, the ref stops a second press in the
  // same tick (eg. key repeat) from sending the update again.
  const inFlight = useRef(false);
  useCountOpenConfirm(opened);

  const handleConfirm = async () => {
    if (disabled || inFlight.current) return;
    inFlight.current = true;
    setSaving(true);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      console.error("Update not saved:", e);
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };

  useKeyListener("Enter", (e) => {
    // Enter on a focused button / link inside the dialog (close, show /
    // hide, the Save button itself) does what that element does.
    if (
      !opened ||
      !confirmKeyListener ||
      e.defaultPrevented ||
      isInteractiveTarget(e.target)
    ) {
      return false;
    }
    handleConfirm();
  });

  return (
    <Modal
      title={<Text size="xl">Confirm Update</Text>}
      opened={opened}
      onClose={onClose}
      size="auto"
      styles={{ content: { overflowY: "hidden" } }}
    >
      <Stack
        gap="xl"
        w={1400}
        maw={{
          base: "calc(100vw - 100px)",
          xs: "calc(100vw - 150px)",
          sm: "calc(100vw - 200px)",
          md: "calc(100vw - 250px)",
        }}
        my="lg"
        style={{ overflowY: "hidden" }}
      >
        <Stack
          mah="min(calc(100vh - 300px), 800px)"
          style={{ overflowY: "auto" }}
        >
          {Object.entries(update)
            .filter(([key, val]) => !deepCompare((original as any)[key], val))
            .map(([key, val], i) => (
              <ConfirmUpdateItem
                key={i}
                _key={key as any}
                val={val as any}
                previous={original}
                language={language}
                fileContentsLanguage={fileContentsLanguage}
                enableFancyToml={enableFancyToml}
                secret={secretKeys?.includes(key as keyof T)}
              />
            ))}
        </Stack>
        <Group justify="flex-end">
          <Button
            // Focused when the dialog opens while Enter confirms, then
            // Enter saves natively.
            {...saveButtonFocus(confirmKeyListener)}
            leftSection={<Save size="1rem" />}
            onClick={(e) => {
              e.stopPropagation();
              handleConfirm();
            }}
            w={{ base: "100%", xs: 200 }}
            loading={loading || saving}
            disabled={disabled}
          >
            Save
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/** Elements with their own Enter behavior (buttons, links, tabs, ...). */
function isInteractiveTarget(target: EventTarget | null) {
  return (
    target instanceof Element &&
    !!target.closest(
      "button, a[href], summary, [role=button], [role=link], [role=tab], [role=menuitem], [role=option]",
    )
  );
}

function ConfirmUpdateItem<T>({
  _key,
  val: _val,
  previous,
  language,
  fileContentsLanguage,
  fileContentsKeys = ["file_contents"],
  keyValueFields,
  enableFancyToml,
  secret,
}: {
  _key: keyof T;
  val: T[keyof T];
  previous: T;
  language?: MonacoLanguage;
  fileContentsLanguage?: MonacoLanguage;
  fileContentsKeys?: string[];
  keyValueFields?: string[];
  enableFancyToml?: boolean;
  secret?: boolean;
}) {
  const [show, setShow] = useState(true);
  if (secret) {
    return (
      <Stack gap="xs" p="xl" className="bordered-light" bdrs="md">
        <Text c="Neutral">{fmtSnakeCaseToUpperSpaceCase(_key as string)}</Text>
        <Box component="pre" mih={0}>
          <Text component="span" c="Critical">
            {previous[_key] ? "••••••••" : "None"}
          </Text>{" "}
          <Text component="span" c="dimmed">
            {"->"}
          </Text>{" "}
          <Text component="span" c="Good">
            {_val ? "••••••••" : "None"}
          </Text>
        </Box>
      </Stack>
    );
  }
  const val =
    typeof _val === "string"
      ? _val
      : Array.isArray(_val)
        ? _val.length > 0 &&
          ["string", "number", "boolean"].includes(typeof _val[0])
          ? JSON.stringify(_val)
          : JSON.stringify(_val, null, 2)
        : JSON.stringify(_val, null, 2);
  const prev_val =
    typeof previous[_key] === "string"
      ? previous[_key]
      : Array.isArray(previous[_key])
        ? previous[_key].length > 0 &&
          ["string", "number", "boolean"].includes(typeof previous[_key][0])
          ? JSON.stringify(previous[_key])
          : JSON.stringify(previous[_key], null, 2)
        : JSON.stringify(previous[_key], null, 2);
  const showDiff =
    val?.includes("\n") ||
    prev_val?.includes("\n") ||
    Math.max(val?.length ?? 0, prev_val?.length ?? 0) > 30;

  return (
    <Stack
      hidden={val === prev_val}
      gap="xs"
      p="xl"
      className="bordered-light"
      bdrs="md"
    >
      <Group justify="space-between">
        <Text c="Neutral">{fmtSnakeCaseToUpperSpaceCase(_key as string)}</Text>
        <ShowHideButton show={show} setShow={setShow} />
      </Group>
      {show && (
        <>
          {showDiff ? (
            <MonacoDiffEditor
              original={prev_val}
              modified={val}
              language={
                language ??
                (keyValueFields?.includes(_key as string)
                  ? "key_value"
                  : fileContentsKeys?.includes(_key as string)
                    ? fileContentsLanguage
                    : "json")
              }
              enableFancyToml={enableFancyToml}
              readOnly
            />
          ) : (
            <Box component="pre" mih={0}>
              <Text component="span" c="Critical">
                {prev_val || "None"}
              </Text>{" "}
              <Text component="span" c="dimmed">
                {"->"}
              </Text>{" "}
              <Text component="span" c="Good">
                {val || "None"}
              </Text>
            </Box>
          )}
        </>
      )}
    </Stack>
  );
}
