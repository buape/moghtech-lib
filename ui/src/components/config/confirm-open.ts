import { useEffect } from "react";

// Internal (not re-exported): shared by ConfirmUpdateModal and the
// Ctrl / Cmd + Enter listeners which open one.

/** How many confirm update dialogs are open on the page. */
let openDialogs = 0;

/** Counts the dialog as open while `opened` (and mounted). */
export function useCountOpenConfirm(opened: boolean) {
  useEffect(() => {
    if (!opened) return;
    openDialogs++;
    return () => {
      openDialogs--;
    };
  }, [opened]);
}

/**
 * Whether a confirm update dialog is open. Ctrl / Cmd + Enter then
 * leaves the other Configs / ConfirmUpdates on the page alone, instead
 * of stacking their dialogs over the open one.
 */
export function confirmDialogOpen() {
  return openDialogs > 0;
}
