//! Proven variable values are field-split and quote-removed where they are
//! used, under both hook protocols.
//!
//! Parameter expansion happens before field splitting and quote removal, so
//! a literal value can change which command runs without any word of the
//! source spelling it. Bash 5.2 runs `git reset --hard` for each of
//! `X=" "; git${X}reset${X}--hard`, `X=$IFS; git${X}reset${X}--hard` and
//! `X=gi; "${X}t" reset --hard`. 0.16.0 allowed all three: the executable
//! model only reads a command word that is exactly one reference, and only
//! the rm classifier consulted the deny-only value splice.

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
            "session_id": "sess-var",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_var",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-var",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_var",
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
        "{protocol:?}: the hook must exit with a verdict ({:?}) on {command:?}\nstderr: {stderr}",
        out.status
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

fn assert_both(decision: &str, commands: &[&str]) {
    let mut failures = Vec::new();
    for command in commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let actual = hook_decision(protocol, command);
            if actual != decision {
                failures.push(format!(
                    "{protocol:?}: {command:?}: expected {decision}, got {actual}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn proven_whitespace_values_split_the_command_word() {
    assert_both(
        "deny",
        &[
            r#"X=" "; git${X}reset${X}--hard"#,
            r"X=' '; git${X}reset${X}--hard",
            r#"X=" "; git$X'reset'$X--hard"#,
            r"X=$'\x20'; git${X}reset${X}--hard",
            // A value copied from the default IFS.
            r"X=$IFS; git${X}reset${X}--hard",
            r#"X="$IFS"; git${X}reset${X}--hard"#,
            r"X=${IFS}; git${X}reset${X}--hard",
            // A custom IFS splits on its own characters.
            r"IFS=x; X=x; git${X}reset${X}--hard",
            // Sequencing, rebinding and nesting that keep the binding.
            r#"X=" " && git${X}reset${X}--hard"#,
            r#"X=" "; cd /tmp; git${X}reset${X}--hard"#,
            r#"X=a; X=" "; git${X}reset${X}--hard"#,
            r#"export X=" "; git${X}reset${X}--hard"#,
            r#"X=" " Y=1; git${X}reset${X}--hard"#,
            r#"X=" "; (git${X}reset${X}--hard)"#,
            r#"X=" "; if true; then git${X}reset${X}--hard; fi"#,
            r#"X=" "; echo ok | git${X}reset${X}--hard"#,
            r#"X=" "; bash -c "git${X}reset${X}--hard""#,
            r#"X=" "; rm${X}-rf${X}/"#,
            // Bash indirection and namerefs (t_49339710 review, Bash 5.2/5.3:
            // `declare -n r=IFS; printf "[%s]" a${r}b` prints `[a][b]`).
            r"v=IFS; git${!v}reset${!v}--hard",
            r"declare -n r=IFS; git${r}reset${r}--hard",
            r#"X=" "; v=X; git${!v}reset${!v}--hard"#,
            r#"X=" "; declare -n r=X; git${r}reset${r}--hard"#,
            // Scalar operators whose text comes from the value (Bash 5.2/5.3:
            // `printf '[%s]' a${X:0:1}b` prints `[a][b]` after `X=' '`).
            r"X=' '; git${X[0]}reset${X[0]}--hard",
            r"X=' '; git${X:0:1}reset${X:0:1}--hard",
            r"X=' '; git${X:-other}reset${X:-other}--hard",
            r"X=' x'; git${X%x}reset${X%x}--hard",
            // An assignment list runs left to right.
            r"X=' ' Y=$X; git${Y}reset${Y}--hard",
        ],
    );
}

#[test]
fn unset_ifs_restores_default_field_splitting() {
    assert_both(
        "deny",
        &[
            r#"unset IFS; X=" "; git${X}reset${X}--hard"#,
            r#"IFS=x; unset IFS; X=" "; git${X}reset${X}--hard"#,
            r#"IFS=x; X=" "; unset IFS; git${X}reset${X}--hard"#,
            r"unset IFS; X=$'\t'; git${X}reset${X}--hard",
        ],
    );
    assert_both(
        "allow",
        &[
            r#"IFS=; X=" "; git${X}reset${X}--hard"#,
            r"unset IFS; X=$IFS; git${X}reset${X}--hard",
        ],
    );
}

#[test]
fn unconditional_bindings_after_hazards_can_be_proven() {
    assert_both(
        "deny",
        &[
            r"printf 'hi\n'; X=' '; git${X}reset${X}--hard",
            r"export A=1; X=' '; git${X}reset${X}--hard",
            r"X=a; read -r X <<< b; X=' '; git${X}reset${X}--hard",
            r"{ X=a; }; X=' '; git${X}reset${X}--hard",
            r#"source .venv/bin/activate; X=gi; "${X}t" reset --hard"#,
            r"{ X=' '; }; git${X}reset${X}--hard",
            r"if true; then X=a; fi; X=' '; git${X}reset${X}--hard",
            r"X=' '; echo $(X=a); git${X}reset${X}--hard",
        ],
    );
}

#[test]
fn variable_executables_respect_actual_override_kinds() {
    assert_both(
        "deny",
        &[
            r"PATH=/usr/local/bin:$PATH; X=' '; git${X}reset${X}--hard",
            r#"PATH="$HOME/.cargo/bin:$PATH"; X=' '; git${X}reset${X}--hard"#,
            r#"PATH=/usr/local/bin:$PATH; Y=git; X=$Y; "$X" reset --hard"#,
            r#"alias git=echo; X=gi; "${X}t" reset --hard"#,
            r#"alias git=echo; Y=git; X=$Y; "$X" reset --hard"#,
            r#"git() { :; }; unset -f git; X=gi; "${X}t" reset --hard"#,
            r#"PATH=/usr/local/bin:$PATH; X=git; "$X" reset --hard"#,
            r#"alias git=echo; X=git; "$X" reset --hard"#,
            r#"git() { :; }; unset -f git; X=git; "$X" reset --hard"#,
            r"PATH=/usr/local/bin:$PATH; git reset --hard",
            r"alias git=echo; git reset --hard",
            r"git() { :; }; unset -f git; git reset --hard",
        ],
    );
}

#[test]
fn executable_overrides_and_non_git_values_keep_harmless_commands() {
    assert_both(
        "allow",
        &[
            r#"Y=git; X=$Y; hash -p /usr/bin/printf git; "$X" reset --hard"#,
            r#"git() { :; }; Y=git; X=$Y; "$X" reset --hard"#,
            r#"X=echo; sudo "$X" reset --hard"#,
            r#"X=not_git; "${X}t" reset --hard"#,
        ],
    );
}

#[test]
fn only_proven_bindings_and_the_ifs_in_force_split() {
    assert_both(
        "allow",
        &[
            // A blank that is not an IFS character stays inside the word
            // (`IFS=x; X=' '; printf '[%s]' a${X}b` prints `[a b]`).
            r"IFS=x; X=' '; git${X}reset${X}--hard",
            r"IFS=,; X=$'\n'; git${X}reset${X}--hard",
            // A nameref declaration that may not have run proves no alias
            // (`X=' '; r=a; false && declare -n r=X; printf '[%s]' a${r}b`
            // prints `[aab]`).
            r"X=' '; r=a; false && declare -n r=X; git${r}reset${r}--hard",
            r"X=' '; r=a; (declare -n r=X); git${r}reset${r}--hard",
            r"X=' '; declare -n r=X; declare +n r; git${r}reset${r}--hard",
        ],
    );
}

#[test]
fn quoted_composition_of_a_proven_value_forms_the_command_word() {
    assert_both(
        "deny",
        &[
            r#"X=gi; "${X}t" reset --hard"#,
            r#"X=gi; "$X"t reset --hard"#,
            r#"X=gi; Y=t; "$X$Y" reset --hard"#,
            r#"X=g; Y="${X}i"; "${Y}t" reset --hard"#,
            // An eval body runs with the shell's bindings and its own prefix
            // assignments (t_49339710 review: Bash 3.2/5.2/5.3 print `[git]`).
            r#"X=t eval '"gi${X}" reset --hard'"#,
            r#"X=t; eval '"gi${X}" reset --hard'"#,
            r#"IFS=t eval '"gi${IFS}" reset --hard'"#,
            // `printf -v` with a plain format binds the value.
            r#"printf -v X t; "gi${X}" reset --hard"#,
            r#"printf -v IFS t; "gi${IFS}" reset --hard"#,
        ],
    );
}

#[test]
fn eval_bodies_and_printf_bindings_keep_harmless_uses() {
    assert_both(
        "allow",
        &[
            r#"X=t eval 'echo "gi${X}" reset --hard'"#,
            r#"X=t; eval 'X=a; "gi${X}" reset --hard'"#,
            r#"printf -v X t; "gi${X}" status"#,
        ],
    );
}

#[test]
fn proven_argument_values_reach_their_rules() {
    assert_both(
        "deny",
        &[
            // An unquoted value that splits into several arguments, and a
            // value glued to a literal.
            r#"X="reset --hard"; git $X"#,
            r#"X=" --hard"; git reset$X"#,
        ],
    );
}

#[test]
fn quoting_empty_ifs_and_data_keep_values_whole() {
    assert_both(
        "allow",
        &[
            // Inside double quotes the value is one word: no git runs.
            r#"X=" "; "git${X}reset${X}--hard""#,
            // An empty IFS performs no field splitting.
            r#"IFS=; X=" "; git${X}reset${X}--hard"#,
            // Single quotes and escapes do not expand.
            r#"X=" "; echo 'git${X}reset${X}--hard'"#,
            r#"X=" "; echo git\${X}reset\${X}--hard"#,
            // The value is data for these commands.
            r#"X="git reset --hard"; echo "$X""#,
            r#"X=gi; echo "${X}t reset --hard""#,
            r#"X=" "; printf "%s\n" git${X}reset${X}--hard"#,
            r#"MSG="rm -rf /"; git commit -m "$MSG""#,
            // An assignment word is not split.
            r#"X=" "; Y=git${X}reset${X}--hard; echo "$Y""#,
            // Harmless commands assembled the same way.
            r#"X=" "; git${X}status"#,
            r#"X=gi; "${X}t" status"#,
            r"X=gi; ${X}t log --oneline",
            r#"B=main; git checkout "$B" && git pull"#,
            r"F=out.txt; cat $F | wc -l",
        ],
    );
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn alternate_values_appends_and_arrays_form_the_command_word() {
    // Bash 5.2/5.3 run `git reset --hard` for each (t_416fd788 review 2).
    assert_both(
        "deny",
        &[
            r#"X=a; "gi${X:+t}" reset --hard"#,
            r#"X=a; "gi${X+t}" reset --hard"#,
            r#""gi${IFS:+t}" reset --hard"#,
            r#"X=g; X+=i; "${X}t" reset --hard"#,
            r#"unset X; X+=g; "${X}it" reset --hard"#,
            r#"X=(g x); "${X}it" reset --hard"#,
            // Only the binding in force decides, even after an unknown one.
            r"X=$(date); X=' '; git${X}reset${X}--hard",
            // A body the outer shell expands is still judged.
            "X=' '; bash <<EOF\ngit${X}reset${X}--hard\nEOF",
        ],
    );
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn values_the_shell_does_not_use_there_are_not_read() {
    // Bash runs no git for any of these (t_416fd788 review 2).
    assert_both(
        "allow",
        &[
            // A quoted heredoc body is not expanded by the outer shell, and X
            // is not exported: the inner bash runs `gitreset--hard`.
            "X=' '; bash <<'EOF'\ngit${X}reset${X}--hard\nEOF",
            // Heredoc lines are data, not bindings: X is unset.
            "cat > notes.txt <<'EOF'\nX=' '\nEOF\ngit${X}reset${X}--hard",
            // A write through a nameref changes the variable it names.
            r"X=' '; declare -n r=X; r=a; git${X}reset${X}--hard",
            r#"X=t; declare -n r=X; r=x; "gi${X}" reset --hard"#,
            // Unset, or set to nothing: the alternate word is not used.
            r#"unset X; "gi${X+t}" reset --hard"#,
            r#"X=; "gi${X:+t}" reset --hard"#,
            // Every element of an array is not element 0.
            r#"X=(g x); "${X[@]}it" reset --hard"#,
        ],
    );
}

/// The binding proof follows each copy once: copies of copies used to be
/// re-proven from scratch at every level, which took seconds on a 740-byte
/// command (t_416fd788 review 2: 16 s, then a timeout denial).
#[test]
fn copy_chains_are_proven_in_linear_time() {
    let mut command = String::from("C=' '");
    for (name, source) in [("B", "C"), ("A", "B"), ("Y", "A"), ("X", "Y")] {
        for _ in 0..30 {
            command.push_str("; ");
            command.push_str(name);
            command.push_str("=$");
            command.push_str(source);
        }
    }
    command.push_str("; git${X}status");
    let started = std::time::Instant::now();
    assert_both("allow", &[&command]);
    let mut denied = command.clone();
    denied.push_str("; git${X}reset${X}--hard");
    assert_both("deny", &[&denied]);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "four hook runs took {:?}",
        started.elapsed()
    );
}

/// Statements in front of the use do not hide it: 128, and later 1,024,
/// used to end the view without a verdict. Every statement is read; the
/// evaluation deadline bounds the cost.
#[test]
fn padding_does_not_hide_a_use() {
    for count in [300, 1100] {
        let padding = ": ; ".repeat(count);
        let command = format!("{padding}X=' '; git${{X}}reset${{X}}--hard");
        assert_both("deny", &[&command]);
        let harmless = format!("{padding}X=' '; git${{X}}status");
        assert_both("allow", &[&harmless]);
    }
}

/// Large file writes are data, however many lines they have (t_416fd788
/// review 3: a 1,100-line quoted heredoc was denied by the statement cap).
#[test]
fn large_heredoc_file_writes_allow() {
    let lines = |line: &dyn Fn(usize) -> String| (0..1100).map(line).collect::<Vec<_>>().concat();
    let typescript = lines(&|i| format!("const v{i} = `${{a{i}}}` + b;\n"));
    let script = lines(&|i| format!("x{i}=$((x{i}+1)); echo \"$x{i}\" > /tmp/out{i}\n"));
    let data = lines(&|i| format!("a=$HOME/x{i}\n"));
    assert_both(
        "allow",
        &[
            &format!("cat > src/gen.ts <<'EOF'\n{typescript}EOF"),
            &format!("cat > run.sh <<'EOF'\n{script}EOF\nchmod +x run.sh"),
            &format!("cat > big.txt <<EOF\n{data}EOF"),
        ],
    );
}

/// A whole-word command name whose value only the deny-only proof knows
/// (copies, appends, `printf -v`, arrays, operators, indirection, namerefs,
/// rebinding, eval) is judged as that program (t_416fd788 review 3). Bash
/// runs `git reset --hard` for each.
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn whole_word_command_names_use_the_proven_value() {
    assert_both(
        "deny",
        &[
            "Y=git; X=$Y; \"$X\" reset --hard",
            "X=g; X+=it; \"$X\" reset --hard",
            "printf -v X git; \"$X\" reset --hard",
            "X=(git x); \"$X\" reset --hard",
            "X=' git'; \"${X:1}\" reset --hard",
            "X=$(date); X=git; \"$X\" reset --hard",
            "v=X; X=git; \"${!v}\" reset --hard",
            "declare -n r=X; X=git; \"$r\" reset --hard",
            "X=a; \"${X:+git}\" reset --hard",
            "X=git eval '\"$X\" reset --hard'",
            "Y=git; X=$Y; $X reset --hard",
        ],
    );
    // Earlier state that binds the name to another program keeps it, and a
    // harmless subcommand stays allowed.
    assert_both(
        "allow",
        &[
            "Y=git; X=$Y; hash -p /usr/bin/printf git; \"$X\" reset --hard",
            "git() { :; }; Y=git; X=$Y; \"$X\" reset --hard",
            "Y=git; X=$Y; \"$X\" status",
            "X=python3; \"$X\" -c 'print(1)'",
            "PY=/usr/bin/python3; \"$PY\" -c 'print(1)'",
        ],
    );
}

/// Every reference re-read the statements before it, so 3,000 statements
/// that read one variable took over a second and timed out (t_416fd788
/// review 3 follow-up). Each read now resumes where the previous read of
/// the same name stopped.
#[test]
fn many_references_to_one_name_are_read_in_linear_time() {
    let uses = (0..2000)
        .map(|i| format!("echo \"${{X}}{i}\"\n"))
        .collect::<Vec<_>>()
        .concat();
    let mut command = format!("X=a\n{uses}");
    let started = std::time::Instant::now();
    assert_both("allow", &[&command]);
    command.push_str("Y=' '; git${Y}reset${Y}--hard");
    assert_both("deny", &[&command]);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "four hook runs took {:?}",
        started.elapsed()
    );
}
