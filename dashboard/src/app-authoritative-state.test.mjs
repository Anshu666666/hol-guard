import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
// Full production App/layout/API/component tree; HTTP and browser ports are
// controlled. This is a UI contract, not native, OAuth or live Core execution.
for (const action of ["allow", "block"])
    for (const oldResponse of ["success", "error"]) {
        test(`actual App ${action} preserves workspace/count after older poll ${oldResponse}`, { timeout: 15_000 }, async () => {
            const dom = new JSDOM('<div id="root"></div>', { url: "http://127.0.0.1:4455/inbox#guard-token=synthetic-control-token" });
            for (const key of ["window", "document", "navigator", "HTMLElement", "HTMLInputElement", "Node", "Event", "MouseEvent", "KeyboardEvent", "localStorage", "sessionStorage"])
                Object.defineProperty(globalThis, key, { value: dom.window[key], configurable: true });
            globalThis.IS_REACT_ACT_ENVIRONMENT = true;
            dom.window.matchMedia = () => ({ matches: false, addEventListener() { }, removeEventListener() { } });
            dom.window.HTMLElement.prototype.scrollIntoView = () => { };
            const intervals = new Map();
            let nextInterval = 1;
            dom.window.setInterval = ((fn) => { const id = nextInterval++; intervals.set(id, fn); return id; });
            dom.window.clearInterval = (id) => { intervals.delete(id); };
            const { App } = await import("./app.tsx");
            const { buildDemoRuntimeSnapshot } = await import("./guard-api.ts");
            const { getDemoRequests } = await import("./guard-demo.ts");
            const request = { ...getDemoRequests()[0], artifact_type: "command", request_id: "synthetic-app-request", created_at: new Date().toISOString() };
            const initial = buildDemoRuntimeSnapshot();
            initial.pending_count = 1;
            initial.items = [request];
            initial.cloud_user_profile = { email: "a@example.invalid", display_name: "Team A", avatar_url: "" };
            initial.cloud_pairing_state.workspace_id = "workspace-a";
            initial.cloud_pairing_state.cloud_user_profile = initial.cloud_user_profile;
            const fresh = structuredClone(initial);
            fresh.pending_count = 0;
            fresh.items = [];
            fresh.cloud_user_profile = { email: "b@example.invalid", display_name: "Team B", avatar_url: "" };
            fresh.cloud_pairing_state.workspace_id = "workspace-b";
            fresh.cloud_pairing_state.cloud_user_profile = fresh.cloud_user_profile;
            let after = false;
            let holdRuntime = false;
            let releaseOld;
            let posts = 0;
            let releaseAction;
            let actionBody;
            let copiedWorkspace;
            Object.defineProperty(dom.window.navigator, "clipboard", { value: { writeText: async (value) => { copiedWorkspace = value; } }, configurable: true });
            const calls = [];
            const unknownPaths = [];
            const originalFetch = globalThis.fetch;
            const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
            globalThis.fetch = (async (input, init) => {
                const url = new URL(String(input), dom.window.location.href);
                assert.equal(url.origin, dom.window.location.origin);
                const path = url.pathname;
                calls.push((init?.method ?? "GET") + " " + path);
                if (path === "/v1/runtime") {
                    if (holdRuntime) {
                        holdRuntime = false;
                        return await new Promise(resolve => { releaseOld = () => resolve(oldResponse === "success" ? json(initial) : json({ error: "synthetic_old_poll_failure" }, 500)); });
                    }
                    return json(after ? fresh : initial);
                }
                if (path === "/v1/requests")
                    return json({ items: after ? [] : [request], next_cursor: null, total_pending_count: after ? 0 : 1, total_count: after ? 0 : 1, status: "pending" });
                if (path === `/v1/requests/${request.request_id}/approve` || path === `/v1/requests/${request.request_id}/block`) {
                    assert.equal(init?.method, "POST");
                    posts++;
                    actionBody = JSON.parse(String(init?.body));
                    return await new Promise(resolve => { releaseAction = () => { after = true; resolve(json({ resolved: true, remaining_pending_count: 0, next_selectable_request_id: null, remaining_pending_summaries: [], resolved_duplicate_ids: [], resolution_summary: "Decision saved." })); }; });
                }
                if (path === "/v1/requests/" + request.request_id)
                    return json(request);
                if (path === "/v1/settings")
                    return json({ settings: { approval_gate: null } });
                if (path === "/v1/read-state")
                    return json({ ids: [] });
                if (path === "/v1/receipts/latest")
                    return json({ error: "not_found" }, 404);
                if (path === "/v1/receipts")
                    return json({ items: [] });
                if (path === "/v1/policies" || path === "/v1/policy")
                    return json({ items: [] });
                if (path === "/v1/inventory")
                    return json({ items: [] });
                unknownPaths.push(path);
                return json({}, 404);
            });
            const root = createRoot(document.getElementById("root"));
            try {
                await act(async () => { root.render(createElement(App)); });
                assert.ok(document.querySelector('[aria-label="Cloud user: Team A"]'));
                assert.ok(document.querySelector('[aria-label="Inbox, 1 Guard action waiting"]'));
                holdRuntime = true;
                await act(async () => { for (const fn of [...intervals.values()])
                    fn(); });
                assert.ok(releaseOld);
                const block = [...document.querySelectorAll("button")].find(b => b.textContent?.trim() === (action === "block" ? "Keep blocked" : "Allow just this once"));
                assert.ok(block, "actual product resolution action exists");
                await act(async () => { block.click(); });
                assert.equal(posts, 1);
                assert.equal(block.disabled, true, "actual product action is disabled while its request is outstanding");
                await act(async () => { block.click(); });
                assert.equal(posts, 1, "duplicate product click must not resubmit");
                assert.equal(actionBody?.action, action);
                assert.ok(releaseAction);
                await act(async () => { releaseAction(); });
                assert.equal(posts, 1);
                assert.ok(document.querySelector('[aria-label="Cloud user: Team B"]'));
                assert.ok(document.querySelector('[aria-label="Inbox, no Guard actions waiting"]'));
                await act(async () => { releaseOld(); });
                assert.ok(document.body.textContent?.includes("Team B"), "older poll must not restore Team A after authoritative approval");
                assert.ok(!document.body.textContent?.includes("Team A"));
                assert.ok(document.querySelector('[aria-label="Inbox, no Guard actions waiting"]'));
                const menu = document.querySelector('[aria-label="Cloud user: Team B"]');
                await act(async () => { menu.click(); });
                const workspace = [...document.querySelectorAll("button")].find(b => b.textContent?.includes("workspace"));
                assert.ok(workspace, "actual product menu exposes the current Core workspace");
                await act(async () => { workspace.click(); });
                assert.equal(copiedWorkspace, "workspace-b");
                assert.ok(calls.some(x => x === "GET /v1/policies" || x === "GET /v1/policy"));
                assert.equal(posts, 1);
                assert.deepEqual(unknownPaths, []);
            }
            finally {
                await act(async () => root.unmount());
                globalThis.fetch = originalFetch;
                dom.window.close();
            }
        });
    }
