// The input is synthetic. Export only fixed labels, booleans, counts and proof fields.
import { readFileSync, appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const [extension, inputPath, cwd, evidencePath] = process.argv.slice(2);
const cases = JSON.parse(readFileSync(inputPath, "utf8"));
const handlers = new Map();
const fetches = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const response = await originalFetch(input, init);
  try {
    const url = new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url);
    const body = await response.clone().json();
    const payload = JSON.parse(init.body);
    const reference = payload.guard_source_ref;
    const proof = {
      method: init.method,
      pathname: url.pathname,
      status: response.status,
      source_ref_present: reference !== undefined,
      encrypted_payload_ref_present: payload.guard_payload_ref?.encryption === "aes-256-gcm",
      encrypted_payload_sha256: payload.guard_payload_ref?.sha256 ?? null,
      source_ref_sha256: reference?.output_sha256 ?? null,
      source_ref_chars: reference?.output_chars ?? null,
      excerpt_truncated: payload.tool_response_summary?.excerpt_truncated === true,
    };
    for (const key of ["decision", "reason_code", "policy_action", "model_output_action", "reviewed_output_sha256"])
      if (typeof body[key] === "string") proof[key] = body[key];
    fetches.push(proof);
  } catch (error) {
    fetches.push({capture_failed: true, failure_kind: "fetch_observation_error",
      failure_sha256: createHash("sha256").update(String(error)).digest("hex")});
  }
  return response;
};
const api = {on(name, handler) { handlers.set(name, handler); }, sendMessage() {}};
(await import(pathToFileURL(extension).href)).default(api);
const context = {cwd, ui: {notify() {}}};
const digest = value => createHash("sha256").update(value).digest("hex");
for (const item of cases) {
  const row = {id: item.id, offered: true, returned: false};
  appendFileSync(evidencePath, JSON.stringify(row) + "\n", {mode: 0o600});
  const event = {toolCallId: item.toolCallId, toolName: item.toolName, input: item.input,
    content: structuredClone(item.content), details: {}, isError: false};
  const original = JSON.stringify(event);
  const start = fetches.length;
  try {
    const handler = handlers.get(item.event);
    if (typeof handler !== "function") throw new Error("missing registered callback");
    const result = await handler(event, context);
    row.returned = true;
    row.input_unchanged = original === JSON.stringify(event);
    row.preserved = result === undefined;
    row.blocked = item.event === "tool_call" ? result?.block === true : result?.isError === true;
    if (item.event === "tool_result" && row.blocked) {
      const message = {role: "toolResult", toolCallId: item.toolCallId, content: item.content};
      const updated = await handlers.get("message_end")({message});
      row.model_blocked = updated?.message?.isError === true &&
        JSON.stringify(updated.message.content) !== JSON.stringify(item.content);
    }
  } catch (error) {
    row.failure = {kind: "callback_error", message_sha256: digest(String(error))};
  }
  row.fetches = fetches.slice(start);
  appendFileSync(evidencePath, JSON.stringify(row) + "\n", {mode: 0o600});
  if (!row.returned) process.exitCode = 1;
}
