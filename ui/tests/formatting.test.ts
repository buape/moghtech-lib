import { test } from "node:test";
import assert from "node:assert/strict";
import {
  fmtSnakeCaseToUpperSpaceCase,
  fmtUpperCamelcase,
} from "../src/formatting.ts";

test("fmtSnakeCaseToUpperSpaceCase skips empty parts", () => {
  // These used to throw during render.
  assert.equal(fmtSnakeCaseToUpperSpaceCase("_"), "");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("exited_"), "Exited");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("_id"), "Id");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("a__b"), "A B");
  assert.equal(fmtSnakeCaseToUpperSpaceCase(""), "");
  assert.equal(
    fmtSnakeCaseToUpperSpaceCase("list_all_items"),
    "List All Items",
  );
});

test("fmtUpperCamelcase keeps what it can't split", () => {
  assert.equal(fmtUpperCamelcase("RunBuild"), "Run Build");
  assert.equal(fmtUpperCamelcase("Aes256Gcm"), "Aes 256 Gcm");
  assert.equal(fmtUpperCamelcase("Server_Unreachable"), "Server Unreachable");
  assert.equal(fmtUpperCamelcase("running"), "running");
  // These used to lose parts: "KILLED", "ERROR", "1", "Up 5".
  assert.equal(fmtUpperCamelcase("OOMKilled"), "OOMKilled");
  assert.equal(fmtUpperCamelcase("HTTPError"), "HTTPError");
  assert.equal(fmtUpperCamelcase("exited_1"), "exited_1");
  assert.equal(fmtUpperCamelcase("Up 5 minutes"), "Up 5 minutes");
});
