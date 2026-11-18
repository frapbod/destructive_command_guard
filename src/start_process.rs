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
    /// `-Name`, or `-Name:<elements>` with its value attached. `start` is
    /// where its dash is (one byte for `-`, three for `–`, `—` or `―`).
    Parameter {
        start: usize,
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

/// The width of a dash at `at`: PowerShell takes `-` and the en dash, em
/// dash and horizontal bar (U+2013, U+2014, U+2015) alike before a
/// parameter name and in `--` (measured with PowerShell 7.5; U+2012 and
/// U+2212 are not dashes to it).
fn dash_len(text: &str, at: usize) -> Option<usize> {
    match text.get(at..)?.chars().next()? {
        '-' => Some(1),
        '\u{2013}' | '\u{2014}' | '\u{2015}' => Some(3),
        _ => None,
    }
}

fn is_parameter_start(text: &str, at: usize) -> bool {
    dash_len(text, at).is_some_and(|width| {
        text.as_bytes()
            .get(at + width)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'?'))
    })
}

/// The end of `--` (any two dashes) at `at` when it stands alone.
fn end_of_parameters(text: &str, at: usize) -> Option<usize> {
    let first = dash_len(text, at)?;
    let end = at + first + dash_len(text, at + first)?;
    (end >= text.len()
        || horizontal_space_len(text, end).is_some()
        || ends_statement(text.as_bytes(), end))
    .then_some(end)
}

/// The end of a redirection at `at` (`>`, `>>`, `2>`, `*>>`, `3>&1`, with
/// its target), which PowerShell takes out of the arguments wherever it
/// stands: `Start-Process git *>&1 reset,--hard` binds `reset,--hard`.
/// A redirection starts a word: `>` inside a bare word is part of it.
fn redirection_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = at;
    if matches!(bytes.get(index), Some(b'*' | b'1'..=b'6')) {
        index += 1;
    }
    if bytes.get(index) != Some(&b'>') {
        return None;
    }
    index += 1;
    if bytes.get(index) == Some(&b'>') {
        index += 1;
    }
    if bytes.get(index) == Some(&b'&') && bytes.get(index + 1).is_some_and(u8::is_ascii_digit) {
        return Some(index + 2);
    }
    let target = skip_blanks(text, index, false);
    if target >= bytes.len() || ends_statement(bytes, target) {
        return Some(target);
    }
    Some(element_end(text, target).max(target + 1).min(text.len()))
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
        if let Some(after) = redirection_end(text, at) {
            at = after;
            end = at;
            continue;
        }
        if at >= bytes.len() || ends_statement(bytes, at) {
            break;
        }
        if let Some(after) = end_of_parameters(text, at) {
            units.push(Unit::EndOfParameters);
            at = after;
            end = at;
            continue;
        }
        if is_parameter_start(text, at) {
            let start = at;
            let name_start = at + dash_len(text, at).unwrap_or(1);
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
                        start,
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
                start,
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
    if units.len() > UNIT_LIMIT {
        // More units than any binding uses: PowerShell stops.
        return None;
    }
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
            (
                Unit::Parameter {
                    start,
                    name,
                    attached,
                },
                _,
            ) if parameters_ended => {
                // After `--` a parameter-like word is a plain argument.
                let end = attached
                    .as_ref()
                    .and_then(|elements| elements.last())
                    .map_or(name.end, |last| last.end);
                let word = Value::Literal(text.get(*start..end)?.to_string());
                match pending.take() {
                    Some(parameter) => assign(parameter, Some(word))?,
                    None => positionals.push(word),
                }
            }
            (
                Unit::Parameter {
                    start,
                    name,
                    attached,
                },
                Some(parameter),
            ) => {
                let raw = text.get(name.clone())?;
                if !matches!(resolve(raw, version_7), Resolved::Unknown) || attached.is_some() {
                    // A parameter where a value belongs: MissingArgument.
                    return None;
                }
                let word = text.get(*start..name.end)?;
                assign(parameter, Some(Value::Literal(word.to_string())))?;
                pending = None;
            }
            (Unit::Parameter { name, attached, .. }, None) => {
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

/// `value` without a leading cast that keeps strings as they are
/// (`[string]`, `[string[]]`, `[object[]]`, `[array]`, with or without
/// `System.`), as in `-ArgumentList ([string[]]('reset','--hard'))`. Only
/// an expression has casts: in argument mode `[string]'x'` is the word
/// `[string]x`.
fn strip_string_cast(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let close = value.strip_prefix('[')?.find(']')? + 1;
    let mut name = value[1..close].to_ascii_lowercase();
    let rest = &value[close + 1..];
    let rest = if let Some(tail) = rest.strip_prefix(']') {
        // `[string[]]`: the first `]` closed the `[]`; this one the cast.
        name.push(']');
        tail
    } else {
        rest
    };
    let name = name.strip_prefix("system.").unwrap_or(&name);
    matches!(
        name,
        "string" | "string[]" | "object" | "object[]" | "array"
    )
    .then(|| rest.trim_start())
    .filter(|rest| !rest.is_empty())
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
        if let Some(cast) = strip_string_cast(inner) {
            return element_strings_within(cast, depth);
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

/// `text` as one PowerShell argument-mode word: bare when PowerShell reads
/// it as itself (so rules that match bare words see it as written), else a
/// single-quoted literal.
fn powershell_word(text: &str) -> String {
    let bare = !text.is_empty()
        && text != "--%"
        && text != "--"
        && !text.starts_with(['@', '#', '~'])
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./\\:=+%^*?!-".contains(&byte));
    if bare {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "''"))
    }
}

/// `text` as one POSIX shell word: bare when the shell reads it as itself
/// (globs and a leading `~` keep their shell meaning, as the program's own
/// runtime may give them), else a single-quoted literal. A program name
/// with `=` is quoted, or the shell would read an assignment.
fn posix_word(text: &str, program: bool) -> String {
    let bare = !text.is_empty()
        && (!program || !text.contains('='))
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./:=+%^*?,@~-".contains(&byte));
    if bare {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// Whether a word has Windows path syntax (a backslash, or a drive letter
/// and colon), which a POSIX reading misreads (`C:\\work\\f` as host `C`).
fn has_windows_path_syntax(word: &str) -> bool {
    let bytes = word.as_bytes();
    word.contains('\\') || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
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

/// How a program's reader spells an element that is not a literal: a
/// shell reads it as its own variable, unknown text it fails closed on
/// (`cmd /c %DCG_START_PROCESS_ARGUMENT%`); another program gets one argv
/// word.
fn dynamic_argument(program: &str) -> String {
    match crate::heredoc::start_process_target_name(program).as_str() {
        "cmd" => format!("%{DYNAMIC_ARGUMENT}%"),
        "powershell" | "pwsh" => format!("${DYNAMIC_ARGUMENT}"),
        "bash" | "sh" | "wsl" => format!("\"${DYNAMIC_ARGUMENT}\""),
        _ => DYNAMIC_ARGUMENT.to_string(),
    }
}

/// The argument list joined as Start-Process joins it, each element that
/// is not a literal as `dynamic`; `None` when no element is a literal and
/// `need_literal` is set (nothing about the line is known).
fn joined_arguments(
    text: &str,
    value: &Value,
    dynamic: &str,
    need_literal: bool,
) -> Option<String> {
    let Value::Elements(elements) = value else {
        return value_strings(text, value).map(|strings| strings.join(" "));
    };
    let mut strings = Vec::new();
    let mut literal = false;
    for element in elements {
        match element_strings(text.get(element.clone())?) {
            Some(decoded) => {
                literal = true;
                strings.extend(decoded);
            }
            None => strings.push(dynamic.to_string()),
        }
    }
    (literal || !need_literal).then(|| strings.join(" "))
}

fn bound_lines(text: &str, bound: &Bound) -> Vec<String> {
    let Some(arguments) = bound.arguments.as_ref() else {
        return Vec::new();
    };
    let file = match value_strings(text, &bound.file) {
        Some(strings) if strings.len() == 1 => strings.into_iter().next(),
        Some(_) => return Vec::new(),
        None => None,
    };
    let Some(file) = file else {
        // Any program: read the line as each shell would, when some of it
        // is known.
        return SHELL_READERS
            .iter()
            .filter_map(|shell| {
                joined_arguments(text, arguments, &dynamic_argument(shell), true)
                    .map(|joined| format!("{shell} {joined}"))
            })
            .collect();
    };
    if file.is_empty() {
        return Vec::new();
    }
    if crate::heredoc::start_process_target_is_shell(&file) {
        // A shell runs its line as code even when none of it is known.
        let Some(joined) = joined_arguments(text, arguments, &dynamic_argument(&file), false)
        else {
            return Vec::new();
        };
        let word = if file.chars().any(char::is_whitespace) {
            crate::heredoc::start_process_target_name(&file)
        } else {
            file
        };
        return vec![format!("{word} {joined}")];
    }
    let Some(joined) = joined_arguments(text, arguments, DYNAMIC_ARGUMENT, true) else {
        return Vec::new();
    };
    // Another program reads the line as argv by Windows' rules. That argv
    // is read as a PowerShell call, where the packs know Windows paths;
    // when no word has Windows path syntax it is also read as a POSIX
    // command, which is exact then and keeps the POSIX-only readings
    // (`env`, `timeout` and other wrappers) that a single string always had.
    let argv = windows_argv(&joined);
    let mut line = format!("& {}", powershell_word(&file));
    for word in &argv {
        line.push(' ');
        line.push_str(&powershell_word(word));
    }
    let mut lines = vec![line];
    if !std::iter::once(&file)
        .chain(&argv)
        .any(|word| has_windows_path_syntax(word))
        && crate::heredoc::start_process_line_dialect(&file)
            == crate::normalize::ShellDialect::Posix
    {
        let mut posix = posix_word(&file, true);
        for word in &argv {
            posix.push(' ');
            posix.push_str(&posix_word(word, false));
        }
        lines.push(posix);
    }
    lines
}

/// The PowerShell names of `Start-Process` at a command start: `start` and
/// `saps` are its aliases, and a module-qualified name is the same command.
static START_PROCESS_NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)(?:^|[\s;|&({=\\])(start-process|saps|start)")
        .expect("start-process name regex compiles")
});

/// At most this many units bind: each parameter once, as its name and a
/// value, two positions and one `--`. A call with more stops with a binding
/// error, so the scan reads one more unit to tell.
const UNIT_LIMIT: usize = 2 * PARAMETERS.len() + 3;

/// Every `Start-Process` call in `text` that binds, as (the call's range,
/// the command lines its program runs).
#[must_use]
pub(crate) fn start_process_lines(text: &str) -> Vec<(Range<usize>, Vec<String>)> {
    let mut calls = Vec::new();
    for found in START_PROCESS_NAME.captures_iter(text) {
        let name = found.get(1).expect("group 1 always present");
        // The name is a whole word: blanks, a line continuation, or a `(`
        // or `{` that starts the first argument (`Start-Process('git')`)
        // follow. Any other character continues the command name.
        let after = name.end();
        let tail = text.get(after..).unwrap_or_default();
        if horizontal_space_len(text, after).is_none()
            && !tail.starts_with("`\n")
            && !tail.starts_with("`\r\n")
            && !tail.starts_with(['(', '{'])
        {
            continue;
        }
        let (units, end) = units(text, name.end(), UNIT_LIMIT + 1);
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

    /// The readings of a program that is not a shell, whose argv has no
    /// Windows path syntax: a PowerShell call and the POSIX command.
    fn program(argv: &str) -> Vec<String> {
        vec![format!("& {argv}"), argv.to_string()]
    }

    /// The expected readings: a shell's own line, or another program's.
    fn expected(line: &str) -> Vec<String> {
        if line.starts_with("cmd ") {
            vec![line.to_string()]
        } else {
            program(line)
        }
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
            ("Start-Process git reset,--hard", "git reset --hard"),
            (
                "Start-Process git -ArgumentList 'reset','--hard'",
                "git reset --hard",
            ),
            (
                "Start-Process git 'reset', '--hard' -Wait",
                "git reset --hard",
            ),
            ("Start-Process git reset ,--hard", "git reset --hard"),
            ("Start-Process git reset,\n--hard", "git reset --hard"),
            ("Start-Process git @('reset'; '--hard')", "git reset --hard"),
            ("Start-Process git ('reset','--hard')", "git reset --hard"),
            (
                "Start-Process git -ArgumentList @'\nreset --hard\n'@",
                "git reset --hard",
            ),
            (
                "Start-Process git -ArgumentList ('re'+'set'),'--hard'",
                "git reset --hard",
            ),
            ("Start-Process git -ArgumentList -x", "git -x"),
            ("Start-Process git -ArgumentList a'b c'", "git ab c"),
        ] {
            assert_eq!(
                lines(spelling),
                super::tests::expected(expected),
                "{spelling:?}"
            );
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
            program("git reset --hard")
        );
        assert_eq!(
            lines("Start-Process -E @{} git reset,--hard"),
            program("git reset --hard")
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
            program("git reset --hard DCG_START_PROCESS_ARGUMENT")
        );
        assert_eq!(
            lines("Start-Process git -ArgumentList 'push',$remote,'--force'"),
            program("git push DCG_START_PROCESS_ARGUMENT --force")
        );
    }

    /// A shell reads an element that is not a literal as its own variable,
    /// also when no element is a literal: it runs that text as code.
    #[test]
    fn shells_read_dynamic_elements_as_variables() {
        for (spelling, line) in [
            (
                "$x = 'git reset --hard'; Start-Process cmd -ArgumentList '/c',$x",
                "cmd /c %DCG_START_PROCESS_ARGUMENT%",
            ),
            (
                "Start-Process cmd -ArgumentList $x",
                "cmd %DCG_START_PROCESS_ARGUMENT%",
            ),
            (
                "Start-Process cmd \"/c gi$('')t reset --hard\"",
                "cmd %DCG_START_PROCESS_ARGUMENT%",
            ),
            (
                "Start-Process pwsh -ArgumentList '-c',$x",
                "pwsh -c $DCG_START_PROCESS_ARGUMENT",
            ),
            (
                "Start-Process bash -ArgumentList '-c',$x",
                "bash -c \"$DCG_START_PROCESS_ARGUMENT\"",
            ),
        ] {
            assert_eq!(lines(spelling), vec![line.to_string()], "{spelling:?}");
        }
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
            program("git DCG_START_PROCESS_ARGUMENT --hard")
        );
    }

    /// Measured with PowerShell 7.5: a `(` or `{` right after the name
    /// starts the first argument; a quote, `$`, `@`, `#` or `<#` there
    /// continues the command name (`Start-Process'git'` is another command).
    #[test]
    fn a_group_right_after_the_name_is_the_first_argument() {
        for spelling in [
            "Start-Process('git') -ArgumentList 'reset','--hard'",
            "Start-Process(\"git\") 'reset','--hard'",
            "saps('git') reset,--hard",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(
            lines("Start-Process('cmd') '/c x'"),
            vec!["cmd /c x".to_string()]
        );
        for spelling in [
            "Start-Process'git' reset,--hard",
            "Start-Process$x reset,--hard",
            "Start-Process<#c#> git reset,--hard",
        ] {
            assert!(lines(spelling).is_empty(), "{spelling:?}");
        }
    }

    /// PowerShell takes U+2013, U+2014 and U+2015 as a parameter dash and in
    /// `--`; U+2012 is not one. A dash in a value is passed as written.
    #[test]
    fn unicode_dashes_start_parameters() {
        for spelling in [
            "Start-Process git \u{2013}ArgumentList 'reset','--hard' \u{2013}Wait \u{2013}NoNewWindow",
            "Start-Process git \u{2014}ArgumentList 'reset','--hard' -Wait -NoNewWindow",
            "Start-Process git \u{2015}ArgumentList 'reset','--hard'",
            "Start-Process git 'reset','--hard' \u{2013}Wait -NoNewWindow",
            "Start-Process \u{2013}FilePath git 'reset','--hard' -Wait -NoNewWindow",
            "Start-Process git \u{2013}ArgumentList:reset,--hard",
            "Start-Process \u{2013}\u{2013} git reset,--hard",
            "Start-Process -\u{2013} git reset,--hard",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert!(lines("Start-Process git \u{2012}ArgumentList reset").is_empty());
        assert_eq!(
            lines("Start-Process git -ArgumentList \u{2013}x"),
            vec![
                "& git '\u{2013}x'".to_string(),
                "git '\u{2013}x'".to_string()
            ]
        );
    }

    /// Every parameter may be bound before the program, each as a name and
    /// a value: the scan reads them all.
    #[test]
    fn every_parameter_may_come_before_the_program() {
        let all = "-ErrorAction Continue -WarningAction Continue -InformationAction Continue \
                   -ProgressAction Continue -ErrorVariable e1 -WarningVariable w1 \
                   -InformationVariable i1 -OutVariable o1 -OutBuffer 1 -PipelineVariable p1 \
                   -WorkingDirectory . -RedirectStandardError e.txt -RedirectStandardOutput o.txt \
                   -RedirectStandardInput i.txt -Credential c -Verb RunAs -WindowStyle Hidden \
                   -Environment @{A='1'} -Wait -NoNewWindow -PassThru -Verbose -Debug \
                   -LoadUserProfile -UseNewEnvironment";
        assert_eq!(
            lines(&format!("Start-Process {all} git reset,--hard")),
            program("git reset --hard")
        );
        assert_eq!(
            lines(&format!("Start-Process {all} -- cmd '/c x'")),
            vec!["cmd /c x".to_string()]
        );
        // One unit more than any binding uses: PowerShell stops.
        assert!(lines(&format!("Start-Process {all} -- cmd '/c x' extra")).is_empty());
    }

    /// Measured with PowerShell 7.5: a redirection anywhere in the
    /// arguments is taken out of them.
    #[test]
    fn redirections_are_not_arguments() {
        for spelling in [
            "Start-Process git *>&1 -ArgumentList 'reset','--hard'",
            "Start-Process git -Wait -NoNewWindow *>$null 'reset','--hard'",
            "Start-Process git 2>&1 reset,--hard",
            "Start-Process git 2> e.txt reset,--hard",
            "Start-Process git > o.txt reset,--hard",
            "Start-Process git *>> o.txt reset,--hard",
            "Start-Process git 2>&1 3>&1 6>&1 reset,--hard",
            "Start-Process git reset,--hard 2>&1 | Out-Null",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(lines("Start-Process git 2>&1reset"), program("git reset"));
        // `reset` is the redirection's target; no argument list.
        assert!(lines("Start-Process git > reset").is_empty());
    }

    /// A string cast in an expression keeps its strings.
    #[test]
    fn string_casts_keep_their_strings() {
        for spelling in [
            "Start-Process git -ArgumentList ([string[]]('reset','--hard'))",
            "Start-Process git -ArgumentList ([System.String[]] ('reset','--hard'))",
            "Start-Process git -ArgumentList ([object[]]('reset','--hard'))",
            "Start-Process git -ArgumentList ([array]('reset','--hard'))",
            "Start-Process git -ArgumentList ([string] 'reset'),'--hard'",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(
            lines("Start-Process git -ArgumentList ([string]$rest),'--hard'"),
            program("git DCG_START_PROCESS_ARGUMENT --hard")
        );
    }

    /// Words are bare where the reader takes them as written, else quoted;
    /// an argv with Windows path syntax is read only as PowerShell, where
    /// `C:\\work` is a path.
    #[test]
    fn argv_spelling() {
        assert_eq!(
            lines("Start-Process git -ArgumentList 'commit','-m','\"a b\"',\"it's\""),
            vec![
                "& git commit -m 'a b' 'it''s'".to_string(),
                "git commit -m 'a b' 'it'\\''s'".to_string()
            ]
        );
        assert_eq!(
            lines("Start-Process cipher -ArgumentList '/w:C:\\'"),
            vec!["& cipher /w:C:\\".to_string()]
        );
        assert_eq!(
            lines(
                "Start-Process scp.exe -ArgumentList 'outside.example:/in/r.csv','C:\\work\\r.csv'"
            ),
            vec!["& scp.exe outside.example:/in/r.csv C:\\work\\r.csv".to_string()]
        );
        assert_eq!(
            lines("Start-Process env -ArgumentList 'FOO=1 git reset --hard'"),
            vec![
                "& env FOO=1 git reset --hard".to_string(),
                "env FOO=1 git reset --hard".to_string()
            ]
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
