//! A POSIX shell (macOS and WSL Bash, Git Bash) substitutes `$x`, `${x}`,
//! `$(…)` and backquotes inside a double-quoted argument before the program
//! it starts reads it. Measured with Linux bash (fake `bash` and `cmd.exe`
//! that record their argv): `bash -c "'gi${x}t' reset --hard"` hands bash
//! `'git' reset --hard`, `cmd.exe /c "gi${X}t reset --hard"` hands cmd.exe
//! `git reset --hard`, and `cmd.exe /c "$X reset --hard"` hands it
//! ` reset --hard`, with `x` and `X` unset.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Claude,
    Codex,
}

fn payload(protocol: Protocol, command: &str, cwd: &std::path::Path) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-posix-outer-values",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_posix_outer_values",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-posix-outer-values",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_posix_outer_values",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path()).to_string();
    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_HEREDOC_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_AST_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{protocol:?}: the hook must exit with a verdict on {command:?}\nstderr: {stderr}"
    );
    if stdout.trim().is_empty() {
        return "allow".to_string();
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{protocol:?}: stdout is not one JSON value ({e}): {stdout}"));
    parsed["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("<missing>")
        .to_string()
}

fn decision_in(command: &str, dialect: ShellDialect) -> EvaluationDecision {
    let enabled: std::collections::HashSet<String> =
        ["core.git", "core.filesystem", "windows.filesystem"]
            .into_iter()
            .map(str::to_string)
            .collect();
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let index = REGISTRY.build_enabled_keyword_index(&ordered);
    let config = Config::default();
    let overrides = config.overrides.compile();
    let heredoc = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &keywords,
        &ordered,
        index.as_ref(),
        &overrides,
        &LayeredAllowlist::default(),
        &heredoc,
        None,
        dialect,
    )
    .decision
}

/// Checks each command in `dialects` and in both hook formats, and reports
/// every miss at once.
fn misses(commands: &[&str], dialects: &[ShellDialect], want: EvaluationDecision) -> Vec<String> {
    let hook_want = if want == EvaluationDecision::Deny {
        "deny"
    } else {
        "allow"
    };
    let mut misses = Vec::new();
    for command in commands {
        for &dialect in dialects {
            let got = decision_in(command, dialect);
            if got != want {
                misses.push(format!("{dialect:?}: {command:?} -> {got:?}"));
            }
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let got = hook_decision(protocol, command);
            if got != hook_want {
                misses.push(format!("{protocol:?}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// A value the parent shell substitutes is unknown text where the child
/// shell reads it, including inside the child's single quotes, so it can
/// complete a command name (`'gi${x}t'`), be one (`'$x'`), or be empty.
#[test]
fn outer_values_in_a_shell_payload_are_unknown_child_text() {
    let misses = misses(
        &[
            r#"bash -c "'gi${x}t' reset --hard""#,
            r#"bash -c "'$x' reset --hard""#,
            r#"bash -c "'gi$(true)t' reset --hard""#,
            r#"bash -c "'gi`true`t' reset --hard""#,
            r#"bash -c "\"gi${x}t\" reset --hard""#,
            r#"bash -c "'gi'$x't' reset --hard""#,
            r"bash -c gi${x}t' reset --hard'",
            r#"bash -c "git 're${x}set' --hard""#,
            r#"bash -c "r'm${x}' -rf /""#,
            r#"bash -c "echo ok; 'gi${x}t' reset --hard""#,
            r#"bash -c "\$'gi${x}t' reset --hard""#,
            r#"sh -c "'gi${x}t' reset --hard""#,
            r#"bash -lc "'gi${x}t' reset --hard""#,
            r#"sudo bash -c "'gi${x}t' reset --hard""#,
            r#"env bash -c "'gi${x}t' reset --hard""#,
            r#"ssh host "'gi${x}t' reset --hard""#,
            r#"ssh host "'gi${x}t'" reset --hard"#,
            r#"bash -c "echo $(git reset --hard)""#,
            r#"x="'; git reset --hard; '"; bash -c "echo '$x'""#,
            r#"x="'; git reset --hard; '"; ssh host "echo '$x'""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// PowerShell substitutes `$x`, `${x}` and `$(…)` in a double-quoted
/// argument too (pwsh 7.5, fake `bash` and `ssh`: `bash -c "'gi${x}t' reset
/// --hard"` hands bash `'git' reset --hard`), so the child reads the same
/// unknown text. A value the command binds is judged with its text.
#[test]
fn powershell_values_in_a_shell_payload_are_unknown_child_text() {
    let misses = misses(
        &[
            r#"bash -c "'gi${x}t' reset --hard""#,
            r#"bash -c "'$x' reset --hard""#,
            r#"bash -c "'gi$('')t' reset --hard""#,
            r#"sh -c "'gi$x' reset --hard""#,
            r#"ssh host "'gi${x}t' reset --hard""#,
            r#"$x = "'; git reset --hard; '"; bash -c "echo '$x'""#,
        ],
        &[ShellDialect::PowerShell, ShellDialect::Unknown],
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Text the parent shell does not expand reaches the child as written: its
/// single quotes, an escaped `$`, and an ANSI-C quote.
#[test]
fn text_the_parent_does_not_expand_stays_as_written() {
    let misses = misses(
        &[
            r#"bash -c "echo '$HOME'""#,
            r#"bash -c "echo $HOME""#,
            r#"bash -c "cd '$PWD' && git status""#,
            r#"bash -c 'echo "$HOME"'"#,
            r#"bash -c "git status $x""#,
            r#"bash -c "'gi\${x}t' reset --hard""#,
            r"bash -c $'echo \'${x}\''",
            r#"ssh host "ls '$HOME'""#,
            r"cmd.exe /c 'gi${X}t reset --hard'",
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The parent shell expands a here-string operand and an unquoted-delimiter
/// heredoc body before the shell on its stdin reads them, and the body's
/// quotes are data to the parent. Measured with Linux bash (fake `git`):
/// `/bin/bash <<< "'gi${x}t' reset --hard"`, and `/bin/bash <<EOF`, `<<-EOF`
/// with `'gi${x}t' reset --hard` as the body, run `git reset --hard`.
#[test]
fn outer_values_in_shell_stdin_are_unknown_child_text() {
    let body = "'gi${x}t' reset --hard";
    let heredocs = [
        "bash <<EOF",
        "sh <<EOF",
        "bash -s <<EOF",
        "/bin/bash <<EOF",
        "ssh host <<EOF",
        "ssh host bash <<EOF",
        "cat <<EOF | bash",
        "cat <<EOF | sh -s",
    ]
    .map(|head| format!("{head}\n{body}\nEOF"));
    let mut commands: Vec<String> = vec![
        r#"bash <<< "'gi${x}t' reset --hard""#.into(),
        r#"sh <<< "'gi${x}t' reset --hard""#.into(),
        r#"bash <<< "'g${x}' reset --hard""#.into(),
        r#"bash <<< "'gi$(true)t' reset --hard""#.into(),
        r#"ssh host <<< "'gi${x}t' reset --hard""#.into(),
        r#"ssh host bash <<< "'gi${x}t' reset --hard""#.into(),
        "bash <<-EOF\n\t'gi${x}t' reset --hard\n\tEOF".into(),
        "bash <<EOF\n'g${x}' reset --hard\nEOF".into(),
        "bash <<EOF\n'gi`true`t' reset --hard\nEOF".into(),
        "bash <<EOF\necho ok\n\"gi${x}t\" reset --hard\nEOF".into(),
    ];
    commands.extend(heredocs);
    let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
    let misses = misses(&commands, &POSIX, EvaluationDecision::Deny);
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The same holds whatever wrapper or runner stands before the shell that
/// reads the stdin. Measured with Linux bash (fake `git`): `/usr/bin/timeout
/// 5 /bin/bash <<EOF`, `/usr/bin/nice /bin/bash <<EOF`, `exec /bin/bash <<EOF`
/// and `/usr/bin/timeout 5 /bin/bash <<< "…"` run `git reset --hard`;
/// docker, kubectl and ssh pass on the stdin the parent already expanded.
/// An escaped `\$` in an unquoted body is a value of the next shell:
/// `bash <<EOF` + `bash -c "'gi\${x}t' reset --hard"` runs it too.
#[test]
fn outer_values_in_shell_stdin_behind_a_wrapper_are_unknown_child_text() {
    let body = "'gi${x}t' reset --hard";
    let heads = [
        "timeout 30 ssh host",
        "timeout 5 bash",
        "docker exec -i c sh",
        "docker exec -i c bash",
        "docker exec -i c bash -s",
        "docker compose exec -T svc sh",
        "kubectl exec -i p -- sh",
        "kubectl exec -i deploy/x -- bash -s",
        "kubectl --context c -n ns exec -i p -- sh",
        "nice bash",
        "nice -n 10 bash",
        "stdbuf -oL bash",
        "time bash",
        "exec bash",
        "sudo -u u bash",
        "su - u",
        "sudo -iu u",
    ];
    let mut commands: Vec<String> = heads
        .iter()
        .map(|head| format!("{head} <<EOF\n{body}\nEOF"))
        .collect();
    for head in [
        "timeout 30 ssh host",
        "timeout 5 bash",
        "docker exec -i c sh",
        "kubectl exec -i p -- sh",
    ] {
        commands.push(format!("{head} <<< \"{body}\""));
    }
    commands.push("timeout 5 bash <<-EOF\n\t'gi${x}t' reset --hard\n\tEOF".into());
    commands.push("nice bash <<EOF\n'r${x}m' -rf /\nEOF".into());
    commands.push("bash <<EOF\nbash -c \"'gi\\${x}t' reset --hard\"\nEOF".into());
    let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
    let misses = misses(&commands, &POSIX, EvaluationDecision::Deny);
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Behind a wrapper, a harmless value stays data, and a body an interpreter
/// or a data sink receives keeps its own reading.
#[test]
fn shell_stdin_behind_a_wrapper_keeps_harmless_values_and_data_sinks() {
    let misses = misses(
        &[
            "timeout 30 ssh host <<EOF\ncd $DIR && git pull\nEOF",
            "docker exec -i c sh <<EOF\nls $HOME\nEOF",
            "kubectl exec -i p -- sh <<EOF\ncat /etc/$f\nEOF",
            "timeout 5 bash <<EOF\necho \\$HOME \\`date\\`\nEOF",
            "python3 <<EOF\nprint('$HOME')\nEOF",
            "cat > /tmp/s.sh <<EOF\n'gi${x}t' status\nEOF",
            "tee /tmp/x <<EOF\n'gi${x}t' reset --hard\nEOF",
            r#"grep x <<< "'gi${x}t' reset --hard""#,
            "git commit -F - <<EOF\nfix: don't read '$x'\nEOF",
            "psql <<EOF\nselect '$x';\nEOF",
            "kubectl apply -f - <<EOF\nnamespace: $NS\nEOF",
            "mail -s hi bob <<EOF\nhello $USER\nEOF",
            r#"read -r a b <<< "$line""#,
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A quoted heredoc delimiter keeps the body as written, and a value the
/// parent substitutes as data stays data, as in a `-c` word.
#[test]
fn shell_stdin_the_parent_does_not_expand_stays_as_written() {
    let misses = misses(
        &[
            "bash <<'EOF'\n'gi${x}t' reset --hard\nEOF",
            "bash <<\"EOF\"\n'gi${x}t' reset --hard\nEOF",
            "bash <<\\EOF\n'gi${x}t' reset --hard\nEOF",
            "bash <<EOF\n'gi\\${x}t' reset --hard\nEOF",
            "bash <<EOF\necho '$HOME'\nEOF",
            "bash <<EOF\ncd $HOME && ls\nEOF",
            "ssh host bash <<EOF\ncd $DIR && git pull\nEOF",
            r#"bash <<< "echo '$HOME'""#,
            r#"bash <<< "git status $x""#,
            r"bash <<< 'echo ${x}'",
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A value the parent shell substitutes into a cmd payload is unknown cmd
/// text: a top-level `cmd /c` fails closed on it, as on `%X%`.
#[test]
fn outer_values_in_a_cmd_payload_are_unknown_cmd_text() {
    let misses = misses(
        &[
            r#"cmd.exe /c "gi${X}t reset --hard""#,
            r#"cmd.exe /c "$X reset --hard""#,
            r#"cmd.exe /c "r${X}d /s /q C:\x""#,
            r#"cmd /c "gi${X}t reset --hard""#,
            r#"cmd.exe /k "gi${X}t reset --hard""#,
            r#"cmd.exe /d /s /c "gi${X}t reset --hard""#,
            r"cmd.exe /c gi${X}t reset --hard",
            r#"cmd.exe /c "gi"${X}"t reset --hard""#,
            r#"cmd.exe /c "gi$(true)t reset --hard""#,
            r#"cmd.exe /c "gi`true`t reset --hard""#,
            r#"cmd.exe //c "gi${X}t reset --hard""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The same rule makes a harmless-looking value fail closed: cmd cannot
/// know it before the parent shell runs, exactly like `%USERNAME%`.
#[test]
fn harmless_outer_values_in_a_cmd_payload_fail_closed_like_cmd_variables() {
    let misses = misses(
        &[
            r#"cmd.exe /c "echo $HOME""#,
            r#"cmd.exe /c "dir $(pwd)""#,
            r#"cmd.exe /c "echo %USERNAME%""#,
        ],
        &[ShellDialect::Posix],
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}
