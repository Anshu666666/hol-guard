"""Produce a source-only inventory; do not import or execute product code."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "source"
CURRENT = "e44008445630aad28ccc291ec234f55a14892e6d"
TREE = "addf0c1daf8ceb6313d6805ee4d05e216d6fdac8"
tree = json.loads((HERE.parent / "rsp001-census/candidate-tree.json").read_text())
entries = {x["path"]: x for x in tree["tree"] if x["type"] == "blob"}


def dump(name: str, value: object) -> None:
    (HERE / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def adapter(name: str) -> str:
    return f"src/codex_plugin_scanner/guard/adapters/{name}.py"


rows = [
    ("claude-code", ["claude-code", "claude"], ["claude_code", "claude_hook_config", "claude_hook_argv"],
     "~/.claude/settings.json; shell-free command/args; daemon bridge, separate SessionStart argv",
     ["PreToolUse", "PermissionRequest", "PostToolUse", "Notification", "Stop", "SessionStart"],
     "PreToolUse matched Bash/Read/Write/Edit/MultiEdit/WebFetch/WebSearch/mcp__.*; PostToolUse also AskUserQuestion; Notification permission_prompt; SessionStart startup/resume/clear/compact",
     "Native pre/post registration; SessionStart is a separate generated session handler. Current installer removes managed UserPromptSubmit and PermissionDenied; normalizer support is not installation."),
    ("codex", ["codex"], ["codex", "codex_adapter_commands", "codex_adapter_installation", "codex_adapter_hook_writes"],
     "Canonical global Codex TOML plus authenticated managed-hook manifest; daemon bridge argv; old hooks.json migrated/removed",
     ["PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse"],
     "_managed_hook_groups emits exactly four events; original foreign hooks inventoried and preserved",
     "Pre/post and prompt/permission are separate interfaces; registration does not prove approval continuation."),
    ("cursor", ["cursor"], ["cursor", "cursor_hooks", "cursor_hook_config", "cursor_cli"],
     "~/.cursor/hooks.json and .cursor/hooks/hol-guard-cursor-hook.py; event baked into command; editor/CLI/all surfaces",
     ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeWriteFile", "afterShellExecution", "afterMCPExecution"],
     "Four before events failClosed=true; two after events failClosed=false",
     "After hooks are observation-only, never proof of output withholding. CLI shim is a distinct launch surface; do not infer editor registration from CLI detection."),
    ("copilot", ["copilot"], ["copilot", "copilot_state_paths"],
     "Global and project .github/hooks/hol-guard-copilot.json; bounded Python bridge; bash/powershell commands",
     ["userPromptSubmitted", "preToolUse", "postToolUse", "permissionRequest", "permissionRequestV2"],
     "sessionStart/sessionEnd/errorOccurred are detectable external events, not in the five managed events",
     "Actual native stdout uses Copilot's top-level binary permissionDecision for pre/post; permission-request behavior shape is separate. Host post-result enforcement must not be inferred solely from a deny JSON."),
    ("cline", ["cline", "cline-cli", "cline-vscode"], ["cline", "cline_hooks", "cline_state_paths", "cline_plugin", "cline_bridge"],
     "Canonical native hook root (Documents/Cline/Hooks, legacy .cline/hooks, or saved supported custom root); private state pins worker+wrapper hashes; alternate plugin selected explicitly",
     ["PreToolUse", "PostToolUse", "UserPromptSubmit", "TaskStart", "TaskError", "SessionShutdown"],
     "POSIX isolated Python wrapper or Windows PowerShell wrapper; hooks/plugin transports mutually selected in adapter-state",
     "Native PreToolUse can cancel; native PostToolUse and lifecycle are nonblocking. Alternate plugin can replace model-visible post-tool output; native hook evidence must not claim plugin mediation."),
    ("kimi", ["kimi", "kimi-code", "kimi-cli"], ["kimi", "kimi_hooks"],
     "Kimi TOML managed block with bounded CLI bridge",
     ["PreToolUse", "UserPromptSubmit", "PostToolUse", "SessionStart", "Stop"],
     "All five literal event registrations in _build_managed_block",
     "Restrictive pre/prompt outcomes use exit 2; lifecycle does not. Post-result JSON and actual host withholding are distinct claims."),
    ("grok", ["grok", "grok-build", "grok-build-cli", "xai-grok"], ["grok", "grok_config", "grok_hooks"],
     "~/.grok/hooks/hol-guard-pretooluse.json plus observe-hook JSON and managed_config.toml compatibility hooks; bounded CLI bridge",
     ["PreToolUse", "UserPromptSubmit", "SubagentStart", "SessionStart"],
     "PreToolUse catch-all deliberately omits matcher; OBSERVE_HOOK_EVENTS contains the other three",
     "Observe events are not enforcement. Additional normalized PostToolUse/SessionEnd/SubagentStop/PermissionDenied support is not an installed managed post hook."),
    ("hermes", ["hermes"], ["hermes", "hermes_runtime_hooks"],
     "Managed pretool-hook.json and MCP overlay plus Hermes config.yaml hooks.pre_tool_call; bounded CLI bridge and launch shim",
     ["pre_tool_call"],
     "Runtime YAML hook registration and approval command checked separately from generated managed descriptor",
     "Pre-tool only in this native inventory; absent runtime hook is explicitly launch-review-only. No managed post-hook claim."),
    ("openclaw", ["openclaw"], ["openclaw", "openclaw_config", "openclaw_support"],
     "Managed OpenClaw overlay.json, pretool-hook.json, manifest and Guard launch shim",
     ["pre-tool descriptor"],
     "Descriptor + launch overlay are generated; actual gateway activation is a separate witness",
     "Do not equate generated manifest or detection with a successfully activated host callback; no managed post hook."),
    ("opencode", ["opencode"], ["opencode", "opencode_pretool"],
     "Managed and global ~/.config/opencode/plugins TypeScript pretool plugin; managed config/MCP proxy and shim",
     ["tool.execute.before"],
     "Plugin executes exact generated Guard argv through bounded CLI; runtime may be Bun or Node",
     "Native pre-tool plugin path; no managed PostToolUse output-mediation registration in this source."),
    ("pi", ["pi", "pi-agent", "pi-coding-agent"], ["pi", "pi_extension_source", "pi_extension_cli_runtime_source", "pi_extension_content_source"],
     "Managed extension TypeScript enabled in Pi settings plus launch shim",
     ["input", "tool_call", "tool_result", "message_end"],
     "input->UserPromptSubmit; tool_call->PreToolUse; tool_result->PostToolUse; message_end applies retained blocked-tool-result replacement",
     "Extension callbacks are not standalone native hook stdout/exit. Post-result replacement requires exact tool identity/source reference and actual extension witness."),
    ("omp", ["omp", "oh-my-pi"], ["pi", "pi_extension_source", "pi_extension_cli_runtime_source", "pi_extension_content_source"],
     "OMP settings and managed extension generated by shared Pi-family adapter",
     ["input", "tool_call", "tool_result", "message_end"],
     "Same callback family as Pi with distinct harness/settings ownership",
     "Shared generator does not make a Pi execution an OMP installed execution; carry separate harness identity."),
    ("zcode", ["zcode", "zai", "z-code", "zai-zcode"], ["zcode", "zcode_config", "zcode_hooks"],
     "ZCode config hooks.events; bounded CLI command with managed shell marker; launch shim",
     ["PreToolUse", "UserPromptSubmit"],
     "18 PreToolUse matchers plus catch-all UserPromptSubmit; normalizer has extra events not installed",
     "No managed PostToolUse. Existing registered runner explicitly refuses Windows shell-comment command semantics; that limitation is not silently waived."),
    ("paseo", ["paseo"], ["paseo", "paseo_install", "paseo_config"],
     "Delegated supported native-provider installation and proof receipt plus launch shim",
     ["provider-owned events"],
     "preflight_native then install_native for detected supported providers",
     "No direct Paseo hook identity in frozen native corpus. Current provider installation is real source behavior, but receipt labels runtime verification not performed; inherited provider events must retain provider identity."),
    ("gemini", ["gemini"], ["gemini", "base"],
     "Detect Gemini settings/extensions/hooks/skills/MCP; base launch/preflight behavior",
     [], "External hooks may be discovered but adapter does not install a native Guard hook",
     "Discovery/preflight only for this native-hook inventory; no managed enforcement claim."),
    ("antigravity", ["antigravity"], ["antigravity", "base"],
     "Discovery/preflight and base adapter launch behavior",
     [], "No Guard native hook installer in this adapter",
     "Preflight only; do not infer installed native enforcement."),
]

inventory = []
for harness, aliases, modules, launcher, events, detail, limits in rows:
    inventory.append(dict(harness=harness, aliases=aliases, source_paths=[adapter(x) for x in modules],
                          generated_launcher=launcher, managed_events=events,
                          registration_detail=detail, claim_limits=limits))

groups = [
    ("frozen-daemon-projections", "All generated frozen corpus projections, both native and delivered expectations, setup/size/source-ref checks and semantic mutation controls",
     ["tests/test_guard_native_qualification_corpus.py"],
     "Renderer + parser/body-limit contract; native producer vectors modeled; no installed process verdict or exit proof.", "existing_source_fixture"),
    ("native-watch-posture", "ACK mode and compatibility posture reads; native block retained while Watch output continues; off/unavailable; post-tool proof/empty/excerpt",
     ["tests/test_hook_worker_observe_pretool.py", "tests/test_hook_worker_native_post_tool_watch.py"],
     "Real worker orchestration with modeled native edges; no all-platform installed native claim.", "existing_source_fixture"),
    ("availability-integrity-permission-lifecycle", "Native unavailable/disabled/not-ready and unknown miss, integrity reference/retained-byte failures, PermissionDenied versus request aliases, lifecycle continuity",
     ["tests/test_native_runtime_delivery_contract.py", "tests/test_hook_availability_policy.py", "tests/test_daemon_session_continuity_edges.py"],
     "46 mandatory renderer cases are only one subset; existing additional source fixtures must be accounted for by node identity.", "existing_source_fixture"),
    ("bounded-cli-json-and-exit", "Timeout/empty/malformed child, oversize, Watch, Grok observation, restrictive action/authority consistency and exact return status",
     ["tests/test_bounded_cli_hook_bridge.py", "tests/test_bounded_cli_hook_daemon.py", "tests/test_bounded_cli_hook_watch_continue.py", "tests/test_bounded_cli_hook_native_consistency.py", "tests/test_bounded_cli_hook_copilot_delivery.py"],
     "Mix of real bridge/emitter calls and modeled child/HTTP results; per-test modeling must remain explicit.", "existing_source_fixture"),
    ("claude-generated-command-exit", "Generated argv plus real bridge output/exit, malformed/oversize/authenticated failure, completion distinct from decision; session handler distinct",
     ["tests/test_guard_claude_hook_argv.py", "tests/test_claude_hook_exit_paths.py", "tests/test_claude_hook_completion_contract.py", "tests/test_claude_daemon_hook_bridge.py"],
     "Some daemon/fallback helpers mocked; emitted stdout + returned status still asserted; current installer removes legacy prompt registration.", "existing_source_fixture"),
    ("codex-generated-command-exit", "Authenticated registered hook inventory, native supported denial/permission shapes, unavailable prompt, integrity, schema-exact post output and live bridge",
     ["tests/test_codex_hook_inventory.py", "tests/test_codex_daemon_hook_bridge.py"],
     "Many existing real-daemon tests; separate browser continuation currently fails in installed RSP136 corpus and is not satisfied by shape tests.", "existing_source_fixture"),
    ("cursor-generated-json-exit", "Real generated script Watch/protected/empty/read/shell/event override and observation-only after hooks",
     ["tests/test_cursor_watch_hook_script.py"],
     "Preserve empty {} post output, deny exit 2 versus availability/Watch exit 0; generic daemon JSON is insufficient.", "existing_source_fixture"),
    ("cline-generated-json-exit", "Generated isolated native hook: unavailable read versus mutation, multi-command fanout, oversize; alternate plugin syntax/block/replacement",
     ["tests/test_cline_hook_transports.py"],
     "Current tests cover native PreToolUse and one plugin pre/post pair, but do not enumerate the installed TaskStart/TaskError/SessionShutdown/UserPromptSubmit native-worker outputs and exits.", "partial_current_capture"),
    ("installed-readback-and-inputs", "Read exact registered argv/environment/digests, reject mutation, freeze normal alias delivery; four priority input categories x two events x two harnesses",
     ["tests/test_native_slo_registered_surfaces.py", "tests/test_native_slo_launcher_input.py"],
     "Source controls model process/native outcomes where indicated. Original 62 actual installed controls are a separate scoped result; 29-alias runner only selects normal pre/post cells.", "existing_source_fixture"),
    ("remaining-current-event-exits", "Kimi/Grok/ZCode registered prompt/lifecycle and Pi/OMP extension return semantics",
     ["tests/test_kimi_adapter.py", "tests/test_grok_adapter.py", "tests/test_guard_phase04_harness_contracts.py", "tests/test_guard_copilot_adapter.py", "tests/test_pi_extension_response_contract.py"],
     "Existing registration, emitter and some lifecycle assertions are distributed; no closed roster currently binds every registered event to a full JSON+exit/extension-return fixture.", "requires_closed_roster"),
]

coverage = [dict(id=i, covers=c, test_paths=p, scope_limit=l, status=s) for i,c,p,l,s in groups]

source_paths = {p for row in inventory for p in row["source_paths"]}
source_paths.update(p for row in coverage for p in row["test_paths"])
source_paths.update({
    adapter("contracts"), adapter("contract_models"), adapter("bounded_cli_hook_bridge"),
    adapter("bounded_cli_hook_daemon"), adapter("bounded_cli_hook_failure"),
    adapter("claude_daemon_hook_bridge"), adapter("codex_daemon_hook_bridge"),
    "src/codex_plugin_scanner/guard/cli/commands_support_interaction.py",
    "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
    "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py",
    "src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py",
    "src/codex_plugin_scanner/guard/daemon/hook_worker_responses.py",
    "src/codex_plugin_scanner/guard/daemon/hook_request_parsing.py",
    "src/codex_plugin_scanner/guard/native_hook_edge.py",
    "src/codex_plugin_scanner/guard/native_resident_client.py",
    "scripts/native_slo_workloads.py", "scripts/native_slo_workload_cases.py",
    "scripts/native_slo_registered_surfaces.py", "scripts/native_slo_registered_surfaces_run.py",
    "scripts/native_slo_launcher_corpus.py", "scripts/native_slo_launcher_input.py",
    "scripts/native_slo_priority_launchers.py",
    "tests/fixtures/guard-native-qualification/corpus.v1.json",
    "docs/guard/contracts/hook-data-plane-ownership.v2.json",
})
# This inventory intentionally binds actual available paths, never guesses an alias.
assert (SOURCE / "scripts/native_slo_registered_surfaces_run.py").is_file()

roster = []
test_nodes = []
for path in sorted(source_paths):
    raw = (SOURCE / path).read_bytes()
    blob = git_blob(raw)
    assert entries[path]["sha"] == blob, (path, blob, entries[path]["sha"])
    roster.append(dict(path=path, git_blob=blob, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    if path.startswith("tests/") and path.endswith(".py"):
        module = ast.parse(raw)
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                decorators = [ast.unparse(x) for x in node.decorator_list]
                test_nodes.append(dict(path=path, name=node.name, line=node.lineno,
                                       declared_parametrization=decorators,
                                       assertion_count=sum(isinstance(x, ast.Assert) for x in ast.walk(node)),
                                       static_only=True))

contracts = ast.parse((SOURCE / adapter("contracts")).read_text())
contract_aliases = {}
for node in ast.walk(contracts):
    if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "HarnessProtectionContract":
        kws = {x.arg:x.value for x in node.keywords}
        if "harness" in kws and "install_aliases" in kws:
            contract_aliases[ast.literal_eval(kws["harness"])] = list(ast.literal_eval(kws["install_aliases"]))
assert set(contract_aliases) == {r["harness"] for r in inventory}, contract_aliases
for row in inventory:
    assert row["aliases"] == contract_aliases[row["harness"]], row["harness"]

overlay = json.loads((HERE.parents[1] / "root-checkpoint/integrated-docs/task-status-overlay.json").read_text())
tasks = [x for x in overlay["tasks"] if x["id"] in {"RSP-013", "RSP-014", "RSP-015", "RSP-022", "RSP-133"}]
dump("original-task-extract.json", tasks)
dump("surface-inventory.json", dict(schema="hol-guard.rsp014-source-inventory.v1", source_commit=CURRENT,
                                     source_tree=TREE, execution_performed=False, surfaces=inventory))
dump("coverage-map.json", dict(schema="hol-guard.rsp015-source-fixture-map.v1", source_commit=CURRENT,
                               source_tree=TREE, product_imports=0, product_tests=0, performance_runs=0,
                               groups=coverage, static_test_function_count=len(test_nodes),
                               not_claimed="Static function census is not pytest collection or pass evidence."))
dump("source-roster.json", roster)
dump("static-test-index.json", test_nodes)
dump("source-check.json", dict(passed=True, source_commit=CURRENT, source_tree=TREE,
                               files_bound=len(roster), canonical_harnesses=len(inventory),
                               alias_contracts_equal=True, python_test_functions=len(test_nodes),
                               product_imports=0, product_tests=0, original_tasks_mutated=False))
print(json.dumps(dict(files_bound=len(roster), harnesses=len(inventory), static_functions=len(test_nodes))))
