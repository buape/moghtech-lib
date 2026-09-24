import { useCombobox } from "@mantine/core";
import { useWindowEvent } from "@mantine/hooks";
import { useEffect, useState } from "react";

/**
 * Called on a matching key press. Return exactly `false` when the press
 * was not handled (eg. the shortcut is currently inactive): the event is
 * then left alone, so the browser default (eg. Enter activating a
 * focused button or link) still happens. Any other return value handles
 * the press, and its default is prevented.
 *
 * `e.defaultPrevented` tells whether an earlier listener already
 * handled this press.
 */
export type KeyListenerHandler = (e: KeyboardEvent) => unknown;

export function useKeyListener(
  listenKey: string,
  onPress: KeyListenerHandler,
  extra?: "shift" | "ctrl",
) {
  useWindowEvent("keydown", (e) => {
    // This will ignore Shift + listenKey if it is sent from input / textarea / monaco
    const target = e.target as HTMLElement | null;
    if (
      target?.matches("input") ||
      target?.matches("textarea") ||
      target?.matches("select") ||
      target?.role === "textbox"
    ) {
      return;
    }

    if (
      e.key === listenKey &&
      (extra === "shift"
        ? e.shiftKey
        : extra === "ctrl"
          ? e.ctrlKey || e.metaKey
          : true)
    ) {
      // The handler decides first: a declined press keeps its default.
      if (onPress(e) === false) return;
      e.preventDefault();
    }
  });
}

export function useShiftKeyListener(
  listenKey: string,
  onPress: KeyListenerHandler,
) {
  useKeyListener(listenKey, onPress, "shift");
}

/** Listens for ctrl (or CMD on mac) + the listenKey */
export function useCtrlKeyListener(
  listenKey: string,
  onPress: KeyListenerHandler,
) {
  useKeyListener(listenKey, onPress, "ctrl");
}

export type Dimensions = { width: number; height: number };
export function useWindowDimensions() {
  const [dimensions, setDimensions] = useState<Dimensions>({
    width: 0,
    height: 0,
  });
  useEffect(() => {
    const callback = () => {
      setDimensions({
        width: window.screen.availWidth,
        height: window.screen.availHeight,
      });
    };
    callback();
    window.addEventListener("resize", callback);
    return () => {
      window.removeEventListener("resize", callback);
    };
  }, []);
  return dimensions;
}

export function useSearchCombobox(props?: {
  onOpen?: () => void;
  onClose?: () => void;
  onSearch?: (search: string) => void;
  disableSelectFirst?: boolean;
}) {
  const [search, setSearch] = useState("");
  const combobox = useCombobox({
    onDropdownOpen: () => {
      combobox.focusSearchInput();
      props?.onOpen?.();
    },
    onDropdownClose: () => {
      combobox.resetSelectedOption();
      combobox.focusTarget();
      setSearch("");
      props?.onClose?.();
    },
  });
  useEffect(() => {
    if (!props?.disableSelectFirst) {
      combobox.selectFirstOption();
    }
    props?.onSearch?.(search);
  }, [search]);
  return {
    search,
    setSearch,
    combobox,
  };
}

/**
 * A custom React hook that debounces a value, delaying its update until after
 * a specified period of inactivity. This is useful for performance optimization
 * in scenarios like search inputs, form validation, or API calls.
 */
export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}
