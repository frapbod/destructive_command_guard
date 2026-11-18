//! PowerShell `Start-Process` calls: the program that runs and the command
//! lines it reads.
//!
//! `Start-Process` (aliases `saps` and `start`) binds its parameters as any
//! cmdlet does: by name, unique prefix or alias, in any order, and the rest
//! by position (`FilePath` at 0, `ArgumentList` at 1). It joins the
//! argument list with spaces into one command line. cmd.exe reads that line
//! as its own command text; other programs split it into argv by the
//! Microsoft C runtime rules. [`start_process_lines`] returns, for each call
//! it can bind, the command line that program runs, spelled so that the
//! evaluator reads it as that program does (see
//! [`crate::heredoc::start_process_line_dialect`]).
//!
//! Measured with PowerShell 7.5 (`Get-Command Start-Process` metadata bound
//! through a proxy function, and real `Start-Process` of a recording program
//! in the shell-truth sandbox); Windows PowerShell 5.1's table is the same
//! without `Environment`, `ProgressAction`, `WhatIf` and `Confirm`, so both
//! tables are bound and every distinct result is read.

use std::ops::Range;

/// What a parameter takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    FilePath,
    ArgumentList,
    /// Any other parameter that takes a value.
    Value,
    Switch,
}

struct Parameter {
    name: &'static str,
    aliases: &'static [&'static str],
    role: Role,
    /// A common or ShouldProcess parameter. When a prefix matches several
    /// parameters, PowerShell takes the one cmdlet parameter among them.
    common: bool,
    /// Only in PowerShell 7 (absent from Windows PowerShell 5.1).
    only_7: bool,
}

const fn parameter(
    name: &'static str,
    aliases: &'static [&'static str],
    role: Role,
    common: bool,
    only_7: bool,
) -> Parameter {
    Parameter {
        name,
        aliases,
        role,
        common,
        only_7,
    }
}

/// `Start-Process`'s parameters with their aliases, as PowerShell 7.5
/// reports them, plus the common and ShouldProcess parameters.
const PARAMETERS: &[Parameter] = &[
    parameter(
        "FilePath",
        &["PSPath", "Path"],
        Role::FilePath,
        false,
        false,
    ),
    parameter("ArgumentList", &["Args"], Role::ArgumentList, false, false),
    parameter("Credential", &["RunAs"], Role::Value, false, false),
    parameter("WorkingDirectory", &[], Role::Value, false, false),
    parameter("LoadUserProfile", &["Lup"], Role::Switch, false, false),
    parameter("NoNewWindow", &["nnw"], Role::Switch, false, false),
    parameter("PassThru", &[], Role::Switch, false, false),
    parameter("RedirectStandardError", &["RSE"], Role::Value, false, false),
    parameter("RedirectStandardInput", &["RSI"], Role::Value, false, false),
    parameter(
        "RedirectStandardOutput",
        &["RSO"],
        Role::Value,
        false,
        false,
    ),
    parameter("Verb", &[], Role::Value, false, false),
    parameter("WindowStyle", &[], Role::Value, false, false),
    parameter("Wait", &[], Role::Switch, false, false),
    parameter("UseNewEnvironment", &[], Role::Switch, false, false),
    parameter("Environment", &[], Role::Value, false, true),
    parameter("Verbose", &["vb"], Role::Switch, true, false),
    parameter("Debug", &["db"], Role::Switch, true, false),
    parameter("ErrorAction", &["ea"], Role::Value, true, false),
    parameter("WarningAction", &["wa"], Role::Value, true, false),
    parameter("InformationAction", &["infa"], Role::Value, true, false),
    parameter("ProgressAction", &["proga"], Role::Value, true, true),
    parameter("ErrorVariable", &["ev"], Role::Value, true, false),
    parameter("WarningVariable", &["wv"], Role::Value, true, false),
    parameter("InformationVariable", &["iv"], Role::Value, true, false),
    parameter("OutVariable", &["ov"], Role::Value, true, false),
    parameter("OutBuffer", &["ob"], Role::Value, true, false),
    parameter("PipelineVariable", &["pv"], Role::Value, true, false),
    parameter("WhatIf", &["wi"], Role::Switch, true, true),
    parameter("Confirm", &["cf"], Role::Switch, true, true),
];

enum Resolved {
    Found(&'static Parameter),
    /// No parameter has this name; PowerShell stops with an error unless
    /// the word is a value (`-ArgumentList -x` binds `-x`).
    Unknown,
    /// Several parameters match; PowerShell stops with an error.
    Ambiguous,
}

/// PowerShell's parameter-name resolution: an exact name or alias, else
/// the only name or alias the word begins, else the only cmdlet parameter
/// among those (`-Ver` is `-Verb`, not `-Verbose`; `-W` is ambiguous).
fn resolve(name: &str, version_7: bool) -> Resolved {
    let table = || {
        PARAMETERS
            .iter()
            .filter(move |parameter| version_7 || !parameter.only_7)
    };
    let names = |parameter: &'static Parameter| {
        std::iter::once(parameter.name).chain(parameter.aliases.iter().copied())
    };
    if let Some(found) = table()
        .find(|parameter| names(parameter).any(|candidate| candidate.eq_ignore_ascii_case(name)))
    {
        return Resolved::Found(found);
    }
    let lower = name.to_ascii_lowercase();
    let matches: Vec<&'static Parameter> = table()
        .filter(|parameter| {
            names(parameter).any(|candidate| candidate.to_ascii_lowercase().starts_with(&lower))
        })
        .collect();
    match matches.as_slice() {
        [] => Resolved::Unknown,
        [one] => Resolved::Found(one),
        _ => {
            let mut own = matches.iter().filter(|parameter| !parameter.common);
            match (own.next(), own.next()) {
                (Some(one), None) => Resolved::Found(one),
                _ => Resolved::Ambiguous,
            }
        }
    }
}

/// One syntactic unit of a command's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unit {
    /// `-Name`, or `-Name:<elements>` with its value attached.
    Parameter {
        name: Range<usize>,
        attached: Option<Vec<Range<usize>>>,
    },
    /// An argument: one element, or a comma list of elements.
    Argument(Vec<Range<usize>>),
    /// `--`: every later word is an argument.
    EndOfParameters,
}

/// A bound value: elements of the text, or a word PowerShell passed as is
/// (`-x` given to a parameter that takes a value, a word after `--`).
#[derive(Debug, Clone)]
enum Value {
    Elements(Vec<Range<usize>>),
    Literal(String),
}

fn horizontal_space_len(text: &str, at: usize) -> Option<usize> {
    let character = text.get(at..)?.chars().next()?;
    (character.is_whitespace() && !matches!(character, '\r' | '\n')).then(|| character.len_utf8())
}

/// Skip blanks, backtick line continuations and comments; with `lines`,
/// line breaks too (after a comma the list goes on on the next line).
fn skip_blanks(text: &str, mut at: usize, lines: bool) -> usize {
    let bytes = text.as_bytes();
    loop {
        if let Some(width) = horizontal_space_len(text, at) {
            at += width;
        } else if bytes.get(at) == Some(&b'`') && matches!(bytes.get(at + 1), Some(b'\n')) {
            at += 2;
        } else if bytes.get(at) == Some(&b'`')
            && bytes.get(at + 1) == Some(&b'\r')
            && bytes.get(at + 2) == Some(&b'\n')
        {
            at += 3;
        } else if lines && matches!(bytes.get(at), Some(b'\r' | b'\n')) {
            at += 1;
        } else if bytes.get(at..at + 2) == Some(b"<#") {
            at = text
                .get(at + 2..)
                .and_then(|tail| tail.find("#>"))
                .map_or(text.len(), |offset| at + 2 + offset + 2);
        } else if bytes.get(at) == Some(&b'#') {
            at += bytes
                .get(at..)
                .unwrap_or_default()
                .iter()
                .take_while(|byte| !matches!(byte, b'\r' | b'\n'))
                .count();
        } else {
            return at;
        }
    }
}

/// Whether the byte at `at` ends the statement (or the argument list):
/// a statement or pipeline operator, a line break, a closing bracket of an
/// enclosing block, or a redirection (read through the redirect view).
fn ends_statement(bytes: &[u8], at: usize) -> bool {
    bytes.get(at).is_none_or(|byte| {
        matches!(
            byte,
            b';' | b'|' | b'&' | b'\r' | b'\n' | b')' | b'}' | b'>' | b'<'
        )
    })
}

/// End of a quoted string that starts at `at` (its opening quote).
fn quoted_end(bytes: &[u8], at: usize) -> usize {
    let quote = bytes[at];
    let mut index = at + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'`' if quote == b'"' => index += 2,
            byte if byte == quote => {
                if bytes.get(index + 1) == Some(&quote) {
                    index += 2;
                } else {
                    return index + 1;
                }
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

/// End of a bracketed group whose opening `(` or `{` is at `at`, past
/// nested groups and quoted strings; the end of the text when unclosed.
fn group_end(bytes: &[u8], at: usize) -> usize {
    let mut depth = 0usize;
    let mut index = at;
    while index < bytes.len() {
        match bytes[index] {
            b'(' | b'{' => {
                depth += 1;
                index += 1;
            }
            b')' | b'}' => {
                depth = depth.saturating_sub(1);
                index += 1;
                if depth == 0 {
                    return index;
                }
            }
            b'\'' | b'"' => index = quoted_end(bytes, index),
            b'`' => index += 2,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// End of a here-string (`@'`/`@"`, a line break, the body, a line that
/// starts with the closing quote and `@`) that starts at `at`, if one does.
fn here_string_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(at + 1)?;
    if bytes.get(at) != Some(&b'@') || !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut index = at + 2;
    while let Some(width) = horizontal_space_len(text, index) {
        index += width;
    }
    if !matches!(bytes.get(index), Some(b'\r' | b'\n')) {
        return None;
    }
    let close = [b'\n', quote, b'@'];
    let offset = bytes
        .get(index..)?
        .windows(3)
        .position(|window| window == close)?;
    Some(index + offset + 3)
}

/// End of one element (a word, string, group or here-string) at `at`.
fn element_end(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    if let Some(end) = here_string_end(text, at) {
        return end;
    }
    let mut index = match bytes.get(at) {
        // A string that starts a word ends the word (`'a'b` is two).
        Some(b'\'' | b'"') => return quoted_end(bytes, at),
        Some(b'(' | b'{') => group_end(bytes, at),
        Some(b'@' | b'$') if matches!(bytes.get(at + 1), Some(b'(' | b'{')) => {
            group_end(bytes, at + 1)
        }
        _ => at,
    };
    // A bare word, or what follows a group (`(Get-Command git).Source`):
    // quoted parts and escapes belong to it.
    while index < bytes.len() {
        if horizontal_space_len(text, index).is_some()
            || ends_statement(bytes, index)
            || matches!(bytes[index], b',' | b'(' | b'{')
        {
            break;
        }
        index = match bytes[index] {
            b'\'' | b'"' => quoted_end(bytes, index),
            b'`' => index + 2,
            _ => index + 1,
        };
    }
    index.min(bytes.len())
}

/// The elements of an argument at `at`: one element, then any number of
/// `,` and another element (blanks and line breaks may follow the comma).
fn element_list(text: &str, at: usize) -> (Vec<Range<usize>>, usize) {
    let bytes = text.as_bytes();
    let mut elements = Vec::new();
    let mut start = at;
    loop {
        let end = element_end(text, start).max(start + 1).min(text.len());
        elements.push(start..end);
        let next = skip_blanks(text, end, false);
        if bytes.get(next) != Some(&b',') {
            return (elements, end);
        }
        start = skip_blanks(text, next + 1, true);
        if start >= text.len() || ends_statement(bytes, start) {
            return (elements, start);
        }
    }
}

fn is_parameter_start(bytes: &[u8], at: usize) -> bool {
    bytes.get(at) == Some(&b'-')
        && bytes
            .get(at + 1)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'?'))
}

/// The argument units of the command whose arguments start at `at`, up to
/// the end of its statement, and that end. Scanning stops after `limit`
/// units: no binding needs more (each parameter binds once).
fn units(text: &str, mut at: usize, limit: usize) -> (Vec<Unit>, usize) {
    let bytes = text.as_bytes();
    let mut units = Vec::new();
    let mut end = at;
    while units.len() < limit {
        at = skip_blanks(text, at, false);
        if at >= bytes.len() || ends_statement(bytes, at) {
            break;
        }
        if bytes.get(at..at + 2) == Some(b"--")
            && (at + 2 >= bytes.len()
                || horizontal_space_len(text, at + 2).is_some()
                || ends_statement(bytes, at + 2))
        {
            units.push(Unit::EndOfParameters);
            at += 2;
            end = at;
            continue;
        }
        if is_parameter_start(bytes, at) {
            let name_start = at + 1;
            let mut name_end = name_start;
            while bytes
                .get(name_end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'?'))
            {
                name_end += 1;
            }
            let attached = if bytes.get(name_end) == Some(&b':') {
                let value_start = skip_blanks(text, name_end + 1, false);
                if value_start >= bytes.len() || ends_statement(bytes, value_start) {
                    // `-Wait:` with nothing after it: PowerShell stops.
                    units.push(Unit::Parameter {
                        name: name_start..name_end,
                        attached: Some(Vec::new()),
                    });
                    end = value_start;
                    break;
                }
                let (elements, value_end) = element_list(text, value_start);
                at = value_end;
                Some(elements)
            } else {
                at = element_end(text, at).max(name_end);
                None
            };
            units.push(Unit::Parameter {
                name: name_start..name_end,
                attached,
            });
            end = at;
            continue;
        }
        let (elements, list_end) = element_list(text, at);
        units.push(Unit::Argument(elements));
        at = list_end;
        end = at;
    }
    (units, end)
}

/// A bound call: the program (`None` when it is not a literal) and the
/// argument list (`None` when it was not given).
#[derive(Debug, Clone)]
struct Bound {
    file: Value,
    arguments: Option<Value>,
}

/// Bind `units` to `Start-Process`'s parameters as PowerShell `version_7`
/// (else 5.1) does. `None` when PowerShell stops with a binding error, and
/// so starts nothing.
fn bind(text: &str, units: &[Unit], version_7: bool) -> Option<Bound> {
    let mut file = None;
    let mut arguments = None;
    let mut bound: Vec<&'static str> = Vec::new();
    let mut positionals: Vec<Value> = Vec::new();
    let mut pending: Option<&'static Parameter> = None;
    let mut parameters_ended = false;
    let mut assign = |parameter: &'static Parameter, value: Option<Value>| -> Option<()> {
        if bound.contains(&parameter.name) {
            return None;
        }
        bound.push(parameter.name);
        match parameter.role {
            Role::FilePath => file = value,
            Role::ArgumentList => arguments = value,
            Role::Value | Role::Switch => {}
        }
        Some(())
    };
    for unit in units {
        match (unit, pending) {
            (Unit::EndOfParameters, _) if !parameters_ended => parameters_ended = true,
            (Unit::EndOfParameters, None) => positionals.push(Value::Literal("--".into())),
            (Unit::EndOfParameters, Some(parameter)) => {
                assign(parameter, Some(Value::Literal("--".into())))?;
                pending = None;
            }
            (Unit::Argument(elements), Some(parameter)) => {
                assign(parameter, Some(Value::Elements(elements.clone())))?;
                pending = None;
            }
            (Unit::Argument(elements), None) => {
                positionals.push(Value::Elements(elements.clone()));
            }
            (Unit::Parameter { name, attached }, _) if parameters_ended => {
                // After `--` a parameter-like word is a plain argument.
                let start = name.start.saturating_sub(1);
                let end = attached
                    .as_ref()
                    .and_then(|elements| elements.last())
                    .map_or(name.end, |last| last.end);
                let word = Value::Literal(text.get(start..end)?.to_string());
                match pending.take() {
                    Some(parameter) => assign(parameter, Some(word))?,
                    None => positionals.push(word),
                }
            }
            (Unit::Parameter { name, attached }, Some(parameter)) => {
                let raw = text.get(name.clone())?;
                if !matches!(resolve(raw, version_7), Resolved::Unknown) || attached.is_some() {
                    // A parameter where a value belongs: MissingArgument.
                    return None;
                }
                let word = text.get(name.start.saturating_sub(1)..name.end)?;
                assign(parameter, Some(Value::Literal(word.to_string())))?;
                pending = None;
            }
            (Unit::Parameter { name, attached }, None) => {
                let Resolved::Found(parameter) = resolve(text.get(name.clone())?, version_7) else {
                    return None;
                };
                match (attached, parameter.role) {
                    (Some(elements), _) if elements.is_empty() => return None,
                    (Some(elements), _) => {
                        assign(parameter, Some(Value::Elements(elements.clone())))?;
                    }
                    (None, Role::Switch) => assign(parameter, None)?,
                    (None, _) => pending = Some(parameter),
                }
            }
        }
    }
    if pending.is_some() {
        return None;
    }
    for value in positionals {
        if !bound.contains(&"FilePath") {
            bound.push("FilePath");
            file = Some(value);
        } else if !bound.contains(&"ArgumentList") {
            bound.push("ArgumentList");
            arguments = Some(value);
        } else {
            return None;
        }
    }
    Some(Bound {
        file: file?,
        arguments,
    })
}

/// A here-string's text, when it is a literal one.
fn here_string_text(raw: &str) -> Option<String> {
    let quote = raw.as_bytes().get(1).copied()?;
    let body_start = raw.find('\n')? + 1;
    let body_end = raw.len().checked_sub(3)?;
    let body = raw.get(body_start..body_end.max(body_start))?;
    let body = body.strip_suffix('\r').unwrap_or(body);
    if quote == b'"' && body.contains(['$', '`']) {
        return None;
    }
    Some(body.to_string())
}

/// Split `inner` at the top-level `separators` (outside strings and groups).
fn split_top_level<'a>(inner: &'a str, separators: &[u8]) -> Vec<&'a str> {
    let bytes = inner.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => index = quoted_end(bytes, index),
            b'(' | b'{' => index = group_end(bytes, index),
            b'`' => index += 2,
            byte if separators.contains(&byte) => {
                parts.push(&inner[start..index]);
                index += 1;
                start = index;
            }
            _ => index += 1,
        }
    }
    parts.push(inner.get(start..).unwrap_or_default());
    parts
}

/// Literal groups nested deeper than this are not reduced (read as not a
/// literal), which bounds the recursion below.
const GROUP_DEPTH: usize = 8;

/// The strings an element stands for, or `None` when it is not a literal
/// (a variable, a call, an expression dcg does not reduce).
fn element_strings(raw: &str) -> Option<Vec<String>> {
    element_strings_within(raw, GROUP_DEPTH)
}

fn element_strings_within(raw: &str, depth: usize) -> Option<Vec<String>> {
    use crate::packs::careful_company_running_windows::transfer::{
        decode_powershell_literal_expression, decode_powershell_static_word,
    };
    let raw = raw.trim();
    let depth = depth.checked_sub(1)?;
    if raw.eq_ignore_ascii_case("$null") {
        return Some(Vec::new());
    }
    if raw.starts_with("@'") || raw.starts_with("@\"") {
        return here_string_text(raw).map(|text| vec![text]);
    }
    if let Some(inner) = raw
        .strip_prefix("@(")
        .and_then(|tail| tail.strip_suffix(')'))
    {
        let mut strings = Vec::new();
        for part in split_top_level(inner, b",;\r\n") {
            if !part.trim().is_empty() {
                strings.extend(element_strings_within(part, depth)?);
            }
        }
        return Some(strings);
    }
    if let Some(inner) = raw
        .strip_prefix('(')
        .and_then(|tail| tail.strip_suffix(')'))
    {
        let parts = split_top_level(inner, b",");
        if parts.len() > 1 {
            let mut strings = Vec::new();
            for part in parts {
                strings.extend(element_strings_within(part, depth)?);
            }
            return Some(strings);
        }
        if let Some(text) = decode_powershell_literal_expression(raw) {
            return Some(vec![text]);
        }
        return element_strings_within(inner, depth);
    }
    decode_powershell_static_word(raw).map(|text| vec![text])
}

fn value_strings(text: &str, value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Literal(word) => Some(vec![word.clone()]),
        Value::Elements(elements) => {
            let mut strings = Vec::new();
            for element in elements {
                strings.extend(element_strings(text.get(element.clone())?)?);
            }
            Some(strings)
        }
    }
}

/// Split a Windows command line into argv by the Microsoft C runtime rules:
/// blanks separate words outside double quotes; `2n` backslashes before a
/// quote are `n` backslashes and the quote opens or closes; `2n+1` are `n`
/// and a literal quote; `""` inside quotes is a literal quote; other
/// backslashes are literal.
#[must_use]
pub(crate) fn windows_argv(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut argv = Vec::new();
    let mut index = 0usize;
    loop {
        while chars.get(index).is_some_and(|c| matches!(c, ' ' | '\t')) {
            index += 1;
        }
        if index >= chars.len() {
            return argv;
        }
        let mut word = String::new();
        let mut quoted = false;
        while let Some(&character) = chars.get(index) {
            match character {
                ' ' | '\t' if !quoted => break,
                '\\' => {
                    let run = chars[index..].iter().take_while(|c| **c == '\\').count();
                    index += run;
                    if chars.get(index) == Some(&'"') {
                        word.extend(std::iter::repeat_n('\\', run / 2));
                        if run % 2 == 1 {
                            word.push('"');
                            index += 1;
                        }
                    } else {
                        word.extend(std::iter::repeat_n('\\', run));
                    }
                }
                '"' => {
                    if quoted && chars.get(index + 1) == Some(&'"') {
                        word.push('"');
                        index += 2;
                    } else {
                        quoted = !quoted;
                        index += 1;
                    }
                }
                _ => {
                    word.push(character);
                    index += 1;
                }
            }
        }
        argv.push(word);
    }
}

/// A PowerShell single-quoted literal of `text`.
fn powershell_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The shells whose command line is read as a whole (see
/// [`crate::heredoc::start_process_line_dialect`]); a program that is not a
/// literal may be any of them.
const SHELL_READERS: [&str; 3] = ["cmd", "powershell", "sh"];

/// The command lines a bound call runs, each spelled for the dialect
/// [`crate::heredoc::start_process_line_dialect`] picks for it.
/// The word that stands for an argument-list element that is not a
/// literal (`'reset','--hard',$rest` still runs a hard reset).
const DYNAMIC_ARGUMENT: &str = "DCG_START_PROCESS_ARGUMENT";

/// The argument list's strings, each element that is not a literal as one
/// [`DYNAMIC_ARGUMENT`]; `None` when no element is a literal.
fn argument_strings(text: &str, value: &Value) -> Option<Vec<String>> {
    let Value::Elements(elements) = value else {
        return value_strings(text, value);
    };
    let mut strings = Vec::new();
    let mut literal = false;
    for element in elements {
        match element_strings(text.get(element.clone())?) {
            Some(decoded) => {
                literal = true;
                strings.extend(decoded);
            }
            None => strings.push(DYNAMIC_ARGUMENT.to_string()),
        }
    }
    literal.then_some(strings)
}

fn bound_lines(text: &str, bound: &Bound) -> Vec<String> {
    let Some(arguments) = bound.arguments.as_ref() else {
        return Vec::new();
    };
    let Some(arguments) = argument_strings(text, arguments) else {
        return Vec::new();
    };
    let joined = arguments.join(" ");
    let file = match value_strings(text, &bound.file) {
        Some(strings) if strings.len() == 1 => strings.into_iter().next(),
        Some(_) => return Vec::new(),
        None => None,
    };
    let Some(file) = file else {
        // Any program: read the line as each shell would.
        return SHELL_READERS
            .iter()
            .map(|shell| format!("{shell} {joined}"))
            .collect();
    };
    if file.is_empty() {
        return Vec::new();
    }
    if crate::heredoc::start_process_target_is_shell(&file) {
        let word = if file.chars().any(char::is_whitespace) {
            crate::heredoc::start_process_target_name(&file)
        } else {
            file
        };
        return vec![format!("{word} {joined}")];
    }
    let mut line = format!("& {}", powershell_literal(&file));
    for word in windows_argv(&joined) {
        line.push(' ');
        line.push_str(&powershell_literal(&word));
    }
    vec![line]
}

/// The PowerShell names of `Start-Process` at a command start: `start` and
/// `saps` are its aliases, and a module-qualified name is the same command.
static START_PROCESS_NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)(?:^|[\s;|&({=\\])(start-process|saps|start)")
        .expect("start-process name regex compiles")
});

/// At most this many units bind: each parameter once, two positions.
const UNIT_LIMIT: usize = PARAMETERS.len() + 3;

/// Every `Start-Process` call in `text` that binds, as (the call's range,
/// the command lines its program runs).
#[must_use]
pub(crate) fn start_process_lines(text: &str) -> Vec<(Range<usize>, Vec<String>)> {
    let mut calls = Vec::new();
    for found in START_PROCESS_NAME.captures_iter(text) {
        let name = found.get(1).expect("group 1 always present");
        // The name is a whole word: blanks or a line continuation follow.
        let after = name.end();
        let tail = text.get(after..).unwrap_or_default();
        if horizontal_space_len(text, after).is_none()
            && !tail.starts_with("`\n")
            && !tail.starts_with("`\r\n")
        {
            continue;
        }
        let (units, end) = units(text, name.end(), UNIT_LIMIT);
        let mut lines: Vec<String> = Vec::new();
        for version_7 in [true, false] {
            if let Some(bound) = bind(text, &units, version_7) {
                for line in bound_lines(text, &bound) {
                    if !lines.contains(&line) {
                        lines.push(line);
                    }
                }
            }
        }
        if !lines.is_empty() {
            calls.push((name.start()..end.max(name.end()), lines));
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        start_process_lines(text)
            .into_iter()
            .flat_map(|(_, lines)| lines)
            .collect()
    }

    /// Bindings measured with PowerShell 7.5 (proxy of Start-Process's own
    /// parameter metadata): spelling, then the program and argument list.
    #[test]
    fn binds_as_powershell_does() {
        for (spelling, expected) in [
            ("Start-Process cmd '/c x'", "cmd /c x"),
            ("Start-Process -FilePath cmd '/c x'", "cmd /c x"),
            ("Start-Process cmd -A '/c x'", "cmd /c x"),
            ("Start-Process cmd -Arg '/c x'", "cmd /c x"),
            (
                "Start-Process cmd -NoNewWindow -ArgumentList '/c x'",
                "cmd /c x",
            ),
            (
                "Start-Process -FilePath cmd -Verb RunAs -ArgumentList '/c x'",
                "cmd /c x",
            ),
            ("Start-Process -Wait cmd -ArgumentList '/c x'", "cmd /c x"),
            (
                "Start-Process -ArgumentList '/c x' -FilePath cmd",
                "cmd /c x",
            ),
            ("Start-Process -ArgumentList '/c x' cmd", "cmd /c x"),
            ("start cmd -ArgumentList '/c x'", "cmd /c x"),
            ("saps cmd -ArgumentList '/c x'", "cmd /c x"),
            ("Start-Process -Path cmd -ArgumentList '/c x'", "cmd /c x"),
            ("Start-Process -PSPath cmd -ArgumentList '/c x'", "cmd /c x"),
            ("Start-Process cmd -ArgumentList ('/c x')", "cmd /c x"),
            ("Start-Process cmd -ArgumentList:'/c x'", "cmd /c x"),
            ("Start-Process cmd -ArgumentList: '/c x'", "cmd /c x"),
            ("Start-Process -Ver RunAs cmd '/c x'", "cmd /c x"),
            ("Start-Process -Wai cmd '/c x'", "cmd /c x"),
            ("Start-Process -E @{a=1} cmd '/c x'", "cmd /c x"),
            ("Start-Process -- cmd '/c x'", "cmd /c x"),
            ("Start-Process cmd -ArgumentList -- '/c x'", "cmd /c x"),
            (
                "Start-Process cmd <# c #> -ArgumentList '/c x' # c",
                "cmd /c x",
            ),
            (
                "Microsoft.PowerShell.Management\\Start-Process cmd '/c x'",
                "cmd /c x",
            ),
            ("Start-Process git reset,--hard", "& 'git' 'reset' '--hard'"),
            (
                "Start-Process git -ArgumentList 'reset','--hard'",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git 'reset', '--hard' -Wait",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git reset ,--hard",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git reset,\n--hard",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git @('reset'; '--hard')",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git ('reset','--hard')",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git -ArgumentList @'\nreset --hard\n'@",
                "& 'git' 'reset' '--hard'",
            ),
            (
                "Start-Process git -ArgumentList ('re'+'set'),'--hard'",
                "& 'git' 'reset' '--hard'",
            ),
            ("Start-Process git -ArgumentList -x", "& 'git' '-x'"),
            ("Start-Process git -ArgumentList a'b c'", "& 'git' 'ab' 'c'"),
        ] {
            assert_eq!(lines(spelling), vec![expected.to_string()], "{spelling:?}");
        }
    }

    /// Spellings PowerShell 7.5 refuses to bind (nothing starts).
    #[test]
    fn binding_errors_start_nothing() {
        for spelling in [
            "Start-Process git reset --hard",
            "Start-Process git -ArgumentList reset --hard",
            "Start-Process -W git reset",
            "Start-Process -P git reset",
            "Start-Process git -ArgumentList -Wait",
            "Start-Process -Verb -Wait git reset",
            "Start-Process git -ArgumentList reset -ArgumentList hard",
            "Start-Process git 'a'b",
            "Start-Process git reset -Wait:",
        ] {
            assert!(
                lines(spelling).is_empty(),
                "{spelling:?}: {:?}",
                lines(spelling)
            );
        }
    }

    /// Windows PowerShell 5.1 has no `-Confirm`, so `-C` is `-Credential`
    /// there and binds the next word as its value; 7 reads it the same way.
    /// It has no `-Environment` either, so `-E` is ambiguous in 5.1 only.
    #[test]
    fn binds_under_both_parameter_tables() {
        assert_eq!(
            lines("Start-Process -C x git reset,--hard"),
            vec!["& 'git' 'reset' '--hard'".to_string()]
        );
        assert_eq!(
            lines("Start-Process -E @{} git reset,--hard"),
            vec!["& 'git' 'reset' '--hard'".to_string()]
        );
        assert!(matches!(resolve("E", false), Resolved::Ambiguous));
        assert!(matches!(resolve("Co", false), Resolved::Unknown));
    }

    /// A program that is not a literal may be a shell.
    #[test]
    fn dynamic_program_is_read_as_each_shell() {
        assert_eq!(
            lines("Start-Process -FilePath $env:ComSpec -ArgumentList '/c git reset --hard'"),
            vec![
                "cmd /c git reset --hard".to_string(),
                "powershell /c git reset --hard".to_string(),
                "sh /c git reset --hard".to_string(),
            ]
        );
        assert!(lines("Start-Process git -ArgumentList $rest").is_empty());
        assert!(lines("Start-Process $tool -ArgumentList $rest").is_empty());
    }

    /// An element that is not a literal stands for one word; the literal
    /// rest of the list is still read.
    #[test]
    fn dynamic_elements_keep_the_literal_ones() {
        assert_eq!(
            lines("Start-Process git -ArgumentList 'reset','--hard',$rest"),
            vec!["& 'git' 'reset' '--hard' 'DCG_START_PROCESS_ARGUMENT'".to_string()]
        );
        assert_eq!(
            lines("Start-Process git -ArgumentList 'push',$remote,'--force'"),
            vec!["& 'git' 'push' 'DCG_START_PROCESS_ARGUMENT' '--force'".to_string()]
        );
    }

    /// Deeply nested groups are not reduced, and do not exhaust the stack.
    #[test]
    fn nested_groups_are_bounded() {
        assert_eq!(element_strings("((('x')))"), Some(vec!["x".to_string()]));
        let deep = format!("{}'x'{}", "(".repeat(40_000), ")".repeat(40_000));
        assert_eq!(element_strings(&deep), None);
        let deep = format!("git -ArgumentList {deep},'--hard'");
        assert_eq!(
            lines(&format!("Start-Process {deep}")),
            vec!["& 'git' 'DCG_START_PROCESS_ARGUMENT' '--hard'".to_string()]
        );
    }

    /// Measured with real Start-Process of a recording program (PowerShell
    /// 7.5, .NET's Windows argv rules): the joined line, then its argv.
    #[test]
    fn windows_argv_rules() {
        for (line, argv) in [
            ("reset --hard", vec!["reset", "--hard"]),
            ("'reset' --hard", vec!["'reset'", "--hard"]),
            ("\"reset\" --hard", vec!["reset", "--hard"]),
            ("\"re set\" x", vec!["re set", "x"]),
            ("re\"set --hard", vec!["reset --hard"]),
            ("a\\\"b c", vec!["a\"b", "c"]),
            ("a\\\\\"b c\" d", vec!["a\\b c", "d"]),
            ("a\\b c", vec!["a\\b", "c"]),
            ("\"a\"\"b\" c", vec!["a\"b", "c"]),
            ("\"a b c", vec!["a b c"]),
            ("a\tb", vec!["a", "b"]),
            ("\"\" x", vec!["", "x"]),
            ("\"a\"b\"c d\"", vec!["abc d"]),
            ("\"C:\\work\\\" x", vec!["C:\\work\" x"]),
            ("reset  --hard", vec!["reset", "--hard"]),
        ] {
            assert_eq!(windows_argv(line), argv, "{line:?}");
        }
    }
}
