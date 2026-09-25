import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { saveButtonFocus } from "../src/components/config/confirm-open.ts";

/** The Save button as React renders it. */
function saveButton(confirmKeyListener: boolean) {
  return renderToStaticMarkup(
    createElement("button", saveButtonFocus(confirmKeyListener), "Save"),
  );
}

test("the confirm dialog opens on Save only while Enter confirms", () => {
  // Mantine's focus trap focuses `[data-autofocus]` when the dialog
  // opens, and Enter on the focused button saves.
  assert.equal(saveButton(true), '<button data-autofocus="true">Save</button>');
  // `confirmKeyListener={false}`: Enter mustn't save, so no focus on
  // Save. Not even `data-autofocus="false"`, which the trap would find.
  assert.equal(saveButton(false), "<button>Save</button>");
  assert.equal(
    renderToStaticMarkup(
      createElement("button", { "data-autofocus": false }, "Save"),
    ),
    '<button data-autofocus="false">Save</button>',
  );
});
