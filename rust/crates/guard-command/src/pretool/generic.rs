#[path = "generic_extract.rs"]
mod extract;
#[path = "generic_result.rs"]
mod result;

use crate::{parse_command, CommandModelRequestV1};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;

use super::evaluate_pre_tool;
use extract::{extract_generic_signals, GenericSignals};
use result::{generic_action, generic_error_result, generic_result, review_reason};

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn tool_tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn tool_matches(tool: &str, terms: &[&str]) -> bool {
    let normalized = compact(tool);
    let tokens = tool_tokens(tool);
    terms.iter().any(|term| {
        let normalized_term = compact(term);
        if normalized == normalized_term {
            return true;
        }
        let term_tokens = tool_tokens(term);
        !term_tokens.is_empty()
            && tokens
                .windows(term_tokens.len())
                .any(|window| window == term_tokens.as_slice())
    })
}

fn is_mcp_tool(tool: &str) -> bool {
    let lowered = tool.to_ascii_lowercase();
    lowered.starts_with("mcp__")
        || lowered.starts_with("mcp_")
        || lowered == "mcp"
        || lowered == "mcptool"
        || lowered == "mcp_tool"
        || lowered.contains("filesystem__")
        || (tool.contains('/') && !tool.starts_with('/'))
}

fn is_package_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "npm",
            "npx",
            "pnpm",
            "yarn",
            "bun",
            "bunx",
            "pip",
            "pipx",
            "poetry",
            "cargo",
            "gem",
            "brew",
            "apt",
            "dnf",
            "yum",
            "apk",
            "go get",
            "install package",
            "package",
        ],
    )
}

fn is_network_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "web_fetch",
            "web_search",
            "fetch_web",
            "http",
            "request",
            "network",
            "open_url",
            "visit_url",
            "download",
        ],
    )
}

fn is_browser_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "browser",
            "navigate",
            "click",
            "type",
            "open_page",
            "web_browser",
        ],
    )
}

fn is_process_service_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "process",
            "service",
            "systemctl",
            "kill",
            "terminate",
            "start_process",
            "stop_process",
            "restart_process",
            "spawn_process",
        ],
    )
}

fn is_config_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &["config", "settings", "permission", "policy", "preferences"],
    )
}

fn is_prompt_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "spawn_subagent",
            "subagent",
            "prompt",
            "message",
            "ask_user",
        ],
    )
}

fn is_harness_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "harness",
            "session_start",
            "session_stop",
            "hook",
            "subagent",
            "agent_context",
        ],
    )
}

fn is_file_write_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "write",
            "edit",
            "patch",
            "replace",
            "delete",
            "mkdir",
            "create_file",
        ],
    )
}

fn is_file_read_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "read",
            "view",
            "open_file",
            "cat",
            "grep",
            "rg",
            "glob",
            "list_dir",
            "search",
        ],
    )
}

fn is_command_tool(tool: &str) -> bool {
    tool_matches(
        tool,
        &[
            "bash",
            "shell",
            "terminal",
            "run_command",
            "run_commands",
            "run_terminal_command",
            "execute_command",
            "execute_command_line",
        ],
    )
}

fn package_command(command: &str) -> bool {
    let Ok(model) = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-generic".to_owned(),
    }) else {
        return false;
    };
    model
        .segments
        .iter()
        .any(|segment| segment.executable.as_deref().is_some_and(is_package_tool))
}

fn safe_vitest_handoff_input(value: &str) -> bool {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.as_bytes().get(1) == Some(&b':')
    {
        return false;
    }
    let mut protected = false;
    for part in value.split('/') {
        let lowered = part.to_ascii_lowercase();
        if part.is_empty()
            || matches!(part, "." | "..")
            || lowered.starts_with(".env")
            || matches!(lowered.as_str(), ".git" | ".guard")
        {
            protected = true;
            break;
        }
    }
    if protected {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    [
        ".test.js",
        ".test.jsx",
        ".test.ts",
        ".test.tsx",
        ".spec.js",
        ".spec.jsx",
        ".spec.ts",
        ".spec.tsx",
    ]
    .iter()
    .any(|suffix| lowered.ends_with(suffix))
}

fn valid_vitest_handoff_tail(arguments: &[String], vitest_index: usize) -> bool {
    if arguments.get(vitest_index).map(String::as_str) != Some("vitest")
        || arguments.get(vitest_index + 1).map(String::as_str) != Some("run")
    {
        return false;
    }
    let mut index = vitest_index + 2;
    let mut file_count = 0usize;
    let mut no_coverage_seen = false;
    let mut reporter_seen = false;
    while index < arguments.len() {
        let token = arguments[index].as_str();
        if token == "--no-coverage" {
            if no_coverage_seen {
                return false;
            }
            no_coverage_seen = true;
        } else if token == "--reporter" || token.starts_with("--reporter=") {
            if reporter_seen {
                return false;
            }
            reporter_seen = true;
            let reporter = if token == "--reporter" {
                index += 1;
                match arguments.get(index) {
                    Some(value) => value.as_str(),
                    None => return false,
                }
            } else {
                token.split_once('=').map(|(_, value)| value).unwrap_or("")
            };
            if !matches!(reporter, "default" | "dot" | "verbose" | "basic") {
                return false;
            }
        } else if token.starts_with('-') || !safe_vitest_handoff_input(token) {
            return false;
        } else {
            file_count += 1;
        }
        index += 1;
    }
    file_count > 0
}

fn contained_node_handoff_manager_for_command(command: &str) -> Option<&'static str> {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-contained-node-handoff".to_owned(),
    })
    .ok()?;
    if model.confidence != "exact" || model.path_overridden || model.segments.len() != 1 {
        return None;
    }
    let segment = model.segments.first()?;
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return None;
    }
    let executable = segment.executable.as_deref()?;
    if executable.contains(['/', '\\']) {
        return None;
    }
    let (manager, vitest_index) = match executable {
        "npx" if segment.arguments.first().map(String::as_str) == Some("--no-install") => ("npx", 1usize),
        "bunx" if segment.arguments.first().map(String::as_str) == Some("--no-install") => ("bunx", 1usize),
        "bunx" => ("bunx", 0usize),
        _ => return None,
    };
    valid_vitest_handoff_tail(&segment.arguments, vitest_index).then_some(manager)
}

pub fn contained_node_handoff_manager(payload: &Value) -> Option<&'static str> {
    let signals = extract_generic_signals(payload).ok()?;
    contained_node_handoff_manager_for_command(signals.command.as_deref()?)
}

fn infer_action_type(
    event: &str,
    event_hint: Option<&str>,
    tool_name: Option<&str>,
    signals: &GenericSignals,
) -> (PreToolActionTypeV1, PreToolOperationV1) {
    let tool = tool_name.unwrap_or_default();
    let event_compact = compact(event_hint.unwrap_or(event));
    if event_compact.contains("userprompt") {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_mcp_tool(tool) {
        return (PreToolActionTypeV1::McpTool, PreToolOperationV1::Call);
    }
    if event_compact.contains("beforemcpexecution") {
        return (PreToolActionTypeV1::McpTool, PreToolOperationV1::Call);
    }
    if is_prompt_tool(tool) {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_harness_tool(tool) {
        let operation = if tool_matches(tool, &["stop", "end", "close"]) {
            PreToolOperationV1::Stop
        } else {
            PreToolOperationV1::Start
        };
        return (PreToolActionTypeV1::Harness, operation);
    }
    if is_browser_tool(tool) {
        return (PreToolActionTypeV1::Browser, PreToolOperationV1::Navigate);
    }
    if is_package_tool(tool) || signals.package_present {
        return (PreToolActionTypeV1::Package, PreToolOperationV1::Install);
    }
    if is_process_service_tool(tool) {
        let operation = if tool_matches(tool, &["kill", "stop", "terminate", "shutdown"]) {
            PreToolOperationV1::Stop
        } else {
            PreToolOperationV1::Start
        };
        return (PreToolActionTypeV1::ProcessService, operation);
    }
    if is_config_tool(tool) {
        return (PreToolActionTypeV1::Config, PreToolOperationV1::Set);
    }
    if is_file_write_tool(tool) {
        return (PreToolActionTypeV1::FileWrite, PreToolOperationV1::Write);
    }
    if is_file_read_tool(tool) {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if signals.prompt_present {
        return (PreToolActionTypeV1::Prompt, PreToolOperationV1::Submit);
    }
    if is_network_tool(tool) || !signals.url_values.is_empty() {
        return (PreToolActionTypeV1::Network, PreToolOperationV1::Request);
    }
    if signals.command.is_some() && (tool.is_empty() || is_command_tool(tool)) {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("beforeshellexecution") {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("beforereadfile") {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if event_compact.contains("beforewritefile") {
        return (PreToolActionTypeV1::FileWrite, PreToolOperationV1::Write);
    }
    if !signals.path_values.is_empty() {
        return (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read);
    }
    if signals.command.is_some() && tool.is_empty() {
        return (PreToolActionTypeV1::Command, PreToolOperationV1::Execute);
    }
    if event_compact.contains("session")
        || event_compact.contains("harness")
        || event_compact.contains("subagent")
    {
        return (PreToolActionTypeV1::Harness, PreToolOperationV1::Start);
    }
    (PreToolActionTypeV1::Unknown, PreToolOperationV1::Unknown)
}

/// Evaluate the complete raw PreToolUse payload in native code.
///
/// This remains separate from `evaluate_pre_tool`, the compatibility
/// command-model operation used by older clients.
pub fn evaluate_pre_tool_envelope(harness: &str, event: &str, payload: &Value) -> PreToolResultV1 {
    let signals = match extract_generic_signals(payload) {
        Ok(value) => value,
        Err(error) => return generic_error_result(harness, event, error),
    };
    evaluate_signals(harness, event, signals)
}

fn evaluate_signals(harness: &str, event: &str, signals: GenericSignals) -> PreToolResultV1 {
    let (mut action_type, mut operation) = infer_action_type(
        event,
        signals.event_hint.as_deref(),
        signals.tool_name.as_deref(),
        &signals,
    );
    if action_type == PreToolActionTypeV1::Command
        && signals.command.as_deref().is_some_and(package_command)
    {
        action_type = PreToolActionTypeV1::Package;
        operation = PreToolOperationV1::Install;
    }
    let action = generic_action(
        harness,
        event,
        action_type,
        operation,
        true,
        signals.sensitive_target,
    );
    if let Some(tool) = signals.tool_name.as_deref() {
        if tool_matches(
            tool,
            &["shutdown", "reboot", "wipe", "format", "kill", "terminate"],
        ) {
            return generic_result(
                action,
                "block",
                "native_process_service_dangerous",
                "HOL Guard blocked a destructive process or service action before execution.",
            );
        }
    }
    if signals.sensitive_target
        && !signals.url_values.is_empty()
        && (!signals.path_values.is_empty() || signals.command.is_some())
    {
        return generic_result(
            action,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a PreToolUse action that combines sensitive data with network transfer.",
        );
    }
    if signals.sensitive_target && action_type == PreToolActionTypeV1::Prompt {
        return generic_result(
            action,
            "block",
            "native_sensitive_prompt",
            "HOL Guard blocked a prompt that requests sensitive local data before execution.",
        );
    }
    if let Some(command) = signals.command.as_deref() {
        let command_request = CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "pre-tool-generic".to_owned(),
        };
        let command_decision = match evaluate_pre_tool(&command_request) {
            Ok(value) => value,
            Err(_) => {
                return generic_result(
                    action,
                    "block",
                    "native_pre_tool_malformed_payload",
                    "HOL Guard blocked a malformed PreToolUse command before execution.",
                )
            }
        };
        if command_decision.minimum_action == "block" {
            return generic_result(
                action,
                "block",
                &command_decision.reason_code,
                &command_decision.reason,
            );
        }
        if action_type == PreToolActionTypeV1::Command {
            return generic_result(
                action,
                &command_decision.minimum_action,
                &command_decision.reason_code,
                &command_decision.reason,
            );
        }
    }
    let (reason_code, reason) = review_reason(action_type);
    generic_result(action, "review", reason_code, reason)
}

#[cfg(test)]
mod contained_node_handoff_tests {
    use super::contained_node_handoff_manager_for_command;

    #[test]
    fn recognizes_only_single_exact_vitest_manager_commands() {
        for (command, expected) in [
            (
                "bunx vitest run tests/unit.test.ts --reporter=dot",
                Some("bunx"),
            ),
            (
                "bunx --no-install vitest run tests/unit.spec.ts --no-coverage",
                Some("bunx"),
            ),
            (
                "npx --no-install vitest run tests/unit.test.ts --reporter basic",
                Some("npx"),
            ),
        ] {
            assert_eq!(
                contained_node_handoff_manager_for_command(command),
                expected,
                "{command}"
            );
        }

        for command in [
            "npx vitest run tests/unit.test.ts",
            "npx --no vitest run tests/unit.test.ts",
            "npx --no-install vitest tests/unit.test.ts",
            "bunx vitest run",
            "bunx vitest run ../outside.test.ts",
            "bunx vitest run /tmp/outside.test.ts",
            "bunx vitest run .env.test.ts",
            "bunx vitest run tests/unit.test.ts --reporter=json",
            "bunx vitest run tests/unit.test.ts --coverage",
            "bunx eslint src/index.ts",
            "bunx vitest run tests/a.test.ts && cat .env",
            "bunx vitest run tests/a.test.ts | tee /tmp/out",
            "PATH=/tmp:$PATH bunx vitest run tests/a.test.ts",
            "/tmp/bunx vitest run tests/a.test.ts",
            "env bunx vitest run tests/a.test.ts",
        ] {
            assert_eq!(
                contained_node_handoff_manager_for_command(command),
                None,
                "{command}"
            );
        }
    }
}
