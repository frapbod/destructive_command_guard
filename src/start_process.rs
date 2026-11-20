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
    /// Arguments glued to each other with no blank (`'reset'.Foo`, where
    /// PowerShell may go on in a way the scan does not model), read as one
    /// argument whose value is unknown. Only made when the call as scanned
    /// does not bind (see [`merge_glued`]).
    Unknown,
}

/// A bound value: elements of the text, or a word PowerShell passed as is
/// (`-x` given to a parameter that takes a value, a word after `--`).
#[derive(Debug, Clone)]
enum Value {
    Elements(Vec<Range<usize>>),
    Literal(String),
    /// A value dcg cannot read (see [`Unit::Unknown`]).
    Unknown,
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

/// End of a `[...]` index whose `[` is at `at`, past nested brackets,
/// groups and quoted strings; the end of the text when unclosed.
fn index_end(bytes: &[u8], at: usize) -> usize {
    let mut depth = 0usize;
    let mut index = at;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => {
                depth += 1;
                index += 1;
            }
            b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
                if depth == 0 {
                    return index;
                }
            }
            b'(' | b'{' => index = group_end(bytes, index),
            b'\'' | b'"' => index = quoted_end(bytes, index),
            b'`' => index += 2,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// The end of what follows a primary expression that ends at `at` (a
/// group, `@( )`, `$( )`, `@{ }`, a script block, a quoted string, a
/// here-string or a `$` variable) and still belongs to its argument:
/// member access (`.Name`, `::Name`, a quoted or `$` name), a method call
/// right after a member (`.Trim()`), an index (`[1]`), and their
/// null-conditional forms `?.` and `?[` (PowerShell 7.1 and later), with
/// no blank before them. Anything else starts the next argument:
/// PowerShell 7.5 binds `('reset')x`, `'reset'('--hard')` and
/// `('reset','--hard')-Wait` as two arguments, and `('x') ?.Trim()` is a
/// parse error.
fn postfix_end(text: &str, mut at: usize) -> usize {
    let bytes = text.as_bytes();
    loop {
        let null_conditional =
            bytes.get(at) == Some(&b'?') && matches!(bytes.get(at + 1), Some(b'.' | b'['));
        let operator = at + usize::from(null_conditional);
        let name_start = match bytes.get(operator) {
            Some(b'[') => {
                at = index_end(bytes, operator);
                continue;
            }
            Some(b'.') if bytes.get(operator + 1) != Some(&b'.') => operator + 1,
            Some(b':') if !null_conditional && bytes.get(operator + 1) == Some(&b':') => {
                operator + 2
            }
            _ => return at,
        };
        let name_end = match bytes.get(name_start) {
            Some(b'\'' | b'"') => quoted_end(bytes, name_start),
            Some(b'(' | b'{') => group_end(bytes, name_start),
            Some(_) => {
                let start = name_start + usize::from(bytes[name_start] == b'$');
                start
                    + bytes[start..]
                        .iter()
                        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                        .count()
            }
            None => name_start,
        };
        if name_end == name_start {
            // `(x).` with no member: PowerShell stops with a parse error;
            // keep the dot with the element.
            return name_end;
        }
        at = name_end;
        if bytes.get(at) == Some(&b'(') {
            at = group_end(bytes, at);
        }
    }
}

/// The end of a variable that starts at `at` (`$name`, `$scope:name`,
/// `${name}`, `$_`, `$$`, `$?`, `$^`), if one does.
fn variable_end(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'$') {
        return None;
    }
    match bytes.get(at + 1)? {
        b'{' => Some(group_end(bytes, at + 1)),
        b'$' | b'?' | b'^' => Some(at + 2),
        byte if byte.is_ascii_alphanumeric() || *byte == b'_' => {
            let mut index = at + 1;
            loop {
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    index += 1;
                }
                // A scope or drive (`$env:ComSpec`), not `::`.
                if bytes.get(index) == Some(&b':')
                    && bytes
                        .get(index + 1)
                        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    index += 1;
                } else {
                    return Some(index);
                }
            }
        }
        _ => None,
    }
}

/// The end of the primary expression at `at` that member access or an
/// index may follow: a here-string, a quoted string, or a group (`( )`,
/// `{ }`, `@( )`, `@{ }`, `$( )`).
fn primary_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if let Some(end) = here_string_end(text, at) {
        return Some(end);
    }
    match bytes.get(at)? {
        b'\'' | b'"' => Some(quoted_end(bytes, at)),
        b'(' | b'{' => Some(group_end(bytes, at)),
        b'@' if matches!(bytes.get(at + 1), Some(b'(' | b'{')) => Some(group_end(bytes, at + 1)),
        b'$' if bytes.get(at + 1) == Some(&b'(') => Some(group_end(bytes, at + 1)),
        _ => None,
    }
}

/// End of one element (a word, string, group or here-string) at `at`.
/// Every primary expression ends its element through [`postfix_end`].
fn element_end(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    // A string that starts a word ends the word (`'a'b` is two), and a
    // group ends its element, unless member access or an index follows.
    if let Some(end) = primary_end(text, at) {
        return postfix_end(text, end);
    }
    let mut index = match variable_end(bytes, at) {
        // A variable with member access or an index (`$a.Trim()`,
        // `${a}[0]`) is one expression.
        Some(end) if postfix_end(text, end) > end => return postfix_end(text, end),
        // `${name}` is a variable: the word goes on (`${a}x` is one word),
        // as after `$name` (`$HOME\x`).
        Some(end) if bytes.get(at + 1) == Some(&b'{') => end,
        _ => at,
    };
    // A bare word: quoted parts and escapes belong to it.
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
            // `$( )` and `${ }` inside a word belong to it (`gi$('')t`).
            b'$' if matches!(bytes.get(index + 1), Some(b'(' | b'{')) => {
                group_end(bytes, index + 1)
            }
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

/// PowerShell's quote characters: ASCII and the typographic ones it
/// accepts alike (‘ ’ ‚ ‛ “ ” „).
fn is_powershell_quote(character: char) -> bool {
    matches!(character, '\'' | '"' | '\u{2018}'..='\u{201E}')
}

/// The end of the parameter name at `at`, when a parameter starts there.
/// A quote right after the name makes the whole one plain word instead:
/// PowerShell 7.5 passes `-r'f x'` to the program as `-rf x`, and
/// `-ArgumentList'reset'` as `-ArgumentListreset`.
fn parameter_name_end(text: &str, at: usize) -> Option<usize> {
    if !is_parameter_start(text, at) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut end = at + dash_len(text, at)?;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'?'))
    {
        end += 1;
    }
    let quote_follows = text
        .get(end..)
        .and_then(|tail| tail.chars().next())
        .is_some_and(is_powershell_quote);
    (!quote_follows).then_some(end)
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
/// the end of its statement, whether each starts right where the one before
/// it ends (glued, with no blank or redirection between), and that end.
/// Scanning stops after `limit` units: no binding needs more (each
/// parameter binds once).
fn units(text: &str, mut at: usize, limit: usize) -> (Vec<Unit>, Vec<bool>, usize) {
    let bytes = text.as_bytes();
    let mut units = Vec::new();
    let mut glued = Vec::new();
    let mut end = at;
    let mut previous_end = None;
    while units.len() < limit {
        at = skip_blanks(text, at, false);
        if let Some(after) = redirection_end(text, at) {
            at = after;
            end = at;
            previous_end = None;
            continue;
        }
        let starts_glued = previous_end == Some(at);
        if at >= bytes.len() || ends_statement(bytes, at) {
            break;
        }
        if let Some(after) = end_of_parameters(text, at) {
            units.push(Unit::EndOfParameters);
            glued.push(starts_glued);
            at = after;
            end = at;
            previous_end = Some(at);
            continue;
        }
        if let Some(name_end) = parameter_name_end(text, at) {
            let start = at;
            let name_start = at + dash_len(text, at).unwrap_or(1);
            let attached = if bytes.get(name_end) == Some(&b':') {
                let value_start = skip_blanks(text, name_end + 1, false);
                if value_start >= bytes.len() || ends_statement(bytes, value_start) {
                    // `-Wait:` with nothing after it: PowerShell stops.
                    units.push(Unit::Parameter {
                        start,
                        name: name_start..name_end,
                        attached: Some(Vec::new()),
                    });
                    glued.push(starts_glued);
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
            glued.push(starts_glued);
            end = at;
            previous_end = Some(at);
            continue;
        }
        let (elements, list_end) = element_list(text, at);
        units.push(Unit::Argument(elements));
        glued.push(starts_glued);
        at = list_end;
        end = at;
        previous_end = Some(at);
    }
    (units, glued, end)
}

/// The units with every argument glued to the argument before it merged
/// into one [`Unit::Unknown`], or `None` when no argument is glued to
/// another. An argument glued to a parameter name stays its value
/// (`-ArgumentList('reset')`). PowerShell continues an argument after a
/// primary expression in ways the scan may not model; when the call as
/// scanned does not bind, this reading fails closed on that argument
/// instead of reading nothing.
fn merge_glued(units: &[Unit], glued: &[bool]) -> Option<Vec<Unit>> {
    let mut merged: Vec<Unit> = Vec::with_capacity(units.len());
    let mut changed = false;
    for (unit, glued) in units.iter().zip(glued) {
        let joins = *glued
            && matches!(unit, Unit::Argument(_) | Unit::Unknown)
            && matches!(merged.last(), Some(Unit::Argument(_) | Unit::Unknown));
        if joins {
            *merged.last_mut()? = Unit::Unknown;
            changed = true;
        } else {
            merged.push(unit.clone());
        }
    }
    changed.then_some(merged)
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
            (Unit::Unknown, Some(parameter)) => {
                assign(parameter, Some(Value::Unknown))?;
                pending = None;
            }
            (Unit::Unknown, None) => positionals.push(Value::Unknown),
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
        // Only a here-string that is the whole element is its text.
        if here_string_end(raw, 0) != Some(raw.len()) {
            return None;
        }
        return here_string_text(raw).map(|text| vec![text]);
    }
    if raw.starts_with('{') && group_end(raw.as_bytes(), 0) == raw.len() {
        // A script block given where a string belongs is its text as
        // written, between the braces (PowerShell 7.5: `{reset --hard}`
        // runs `git reset --hard`).
        return raw
            .get(1..raw.len() - 1)
            .map(|inner| vec![inner.to_string()]);
    }
    // `@( )` and `$( )` both give their statements' output: here, the
    // strings of literal statements (`$('reset','--hard')`).
    if let Some(inner) = raw
        .strip_prefix("@(")
        .or_else(|| raw.strip_prefix("$("))
        .filter(|_| group_end(raw.as_bytes(), 1) == raw.len())
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
        .filter(|_| group_end(raw.as_bytes(), 0) == raw.len())
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

/// The strings of the literal that an element applies member access or an
/// index to (`('-rf','/')?[0..1]`, `'reset --hard'.Trim()`), or `None`.
/// The element's own value is unknown, but it is most often made from
/// these strings, so they are read along with one unknown word.
fn derived_strings(raw: &str) -> Option<Vec<String>> {
    let raw = raw.trim();
    let end = primary_end(raw, 0)?;
    (end < raw.len() && postfix_end(raw, end) == raw.len())
        .then(|| element_strings(&raw[..end]))
        .flatten()
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
        Value::Unknown => None,
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

/// The variable that stands for a program that is not a literal and may
/// be any program (`Start-Process $g.Trim() reset,--hard`).
const DYNAMIC_PROGRAM: &str = "DCG_START_PROCESS_PROGRAM";

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
    let elements = match value {
        Value::Elements(elements) => elements,
        Value::Unknown => return (!need_literal).then(|| dynamic.to_string()),
        Value::Literal(_) => {
            return value_strings(text, value).map(|strings| strings.join(" "));
        }
    };
    let mut strings = Vec::new();
    let mut literal = false;
    for element in elements {
        let raw = text.get(element.clone())?;
        match element_strings(raw) {
            Some(decoded) => {
                literal = true;
                strings.extend(decoded);
            }
            None => {
                if let Some(derived) = derived_strings(raw) {
                    literal = true;
                    strings.extend(derived);
                }
                strings.push(dynamic.to_string());
            }
        }
    }
    (literal || !need_literal).then(|| strings.join(" "))
}

/// The program `(Get-Command <literal>)` (or `gcm`, optionally `-Name`)
/// names: PowerShell resolves the literal and Start-Process runs that
/// command. The evaluator spells an unresolved `$tool` program this way
/// when it checks the transfer pack's scp reading.
fn get_command_program(text: &str, value: &Value) -> Option<String> {
    let Value::Elements(elements) = value else {
        return None;
    };
    let [element] = elements.as_slice() else {
        return None;
    };
    let inner = text
        .get(element.clone())?
        .trim()
        .strip_prefix('(')?
        .strip_suffix(')')?
        .trim();
    let mut words = inner.split_ascii_whitespace();
    let command = words.next()?;
    if !command.eq_ignore_ascii_case("Get-Command") && !command.eq_ignore_ascii_case("gcm") {
        return None;
    }
    let mut word = words.next()?;
    if word.eq_ignore_ascii_case("-Name") {
        word = words.next()?;
    }
    if words.next().is_some() {
        return None;
    }
    match element_strings(word)?.as_slice() {
        [name] if !name.is_empty() => Some(name.clone()),
        _ => None,
    }
}

/// Whether a program value is computed by an expression: not a literal
/// and not a plain variable (`$tool`, `$env:ComSpec`, `${tool}`), whose
/// assignments other readings resolve (the transfer pack keeps
/// `$tool = "notepad.exe"; Start-Process $tool …` allowed).
fn is_computed_program(text: &str, value: &Value) -> bool {
    match value {
        Value::Literal(_) => false,
        Value::Unknown => true,
        Value::Elements(elements) => match elements.as_slice() {
            [element] => text.get(element.clone()).is_none_or(|raw| {
                let raw = raw.trim();
                variable_end(raw.as_bytes(), 0) != Some(raw.len())
            }),
            _ => true,
        },
    }
}

/// A program name taken from the literal parts of a program dcg cannot
/// read whole: the one string a member access or index applies to, blanks
/// around it trimmed (`('git ')?.Trim()` names `git`,
/// `('C:\Program Files\Git\cmd\git.exe').Trim()` that path), or the last path part of an
/// expandable string or word (`"$env:ProgramFiles\Git\cmd\git.exe"` names
/// `git.exe`).
fn derived_program(text: &str, value: &Value) -> Option<String> {
    let Value::Elements(elements) = value else {
        return None;
    };
    let [element] = elements.as_slice() else {
        return None;
    };
    let raw = text.get(element.clone())?.trim();
    if let Some(strings) = derived_strings(raw) {
        // Read as the same literal program (a path with blanks included);
        // `.Trim()` and the like make surrounding blanks likely to go.
        return match strings.as_slice() {
            [name] if !name.trim().is_empty() => Some(name.trim().to_string()),
            _ => None,
        };
    }
    let inner = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(raw);
    let (head, tail) = inner.rsplit_once(['\\', '/'])?;
    (head.contains('$')
        && !tail.is_empty()
        && tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-+~ ".contains(&byte)))
    .then(|| tail.to_string())
}

/// The lines of a call whose program dcg cannot name (a variable, an
/// expression, an expandable string).
///
/// - It may be a shell, when that shell's own reader reaches its command
///   text: cmd at an exact `/C` or `/K` past switches that run nothing
///   and words that are not switches
///   ([`crate::evaluator::cmd_host_may_run_inline`]); PowerShell at
///   `-Command`, an `-EncodedCommand` that decodes, or a command string
///   ([`crate::evaluator::powershell_host_may_run_inline`]); sh always
///   (its reading allows a script name or an option it does not know).
///   The cmd and PowerShell readers fail closed on a switch they do not
///   know, so a reading given past one would deny an install
///   (`'/S'`, `'/configure'`, `'-e','console.log(1)'`) because of its
///   argv, not because of code a shell runs; the same direct call allows.
/// - A program computed by an expression is read as the same program
///   called directly, as written (`Start-Process $i.FullName '/S'` as
///   `& $i.FullName /S`): never stricter than the direct call, and as
///   strict as it. A plain variable is left to the readings that resolve
///   its assignment (the transfer pack keeps `$tool = 'notepad.exe'` …
///   allowed), as the direct `& $tool` is in a Bash hook.
/// - A name taken from its literal parts ([`derived_program`]) is read as
///   that program.
fn unnamed_program_lines(text: &str, program: &Value, arguments: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for shell in SHELL_READERS {
        let Some(joined) = joined_arguments(text, arguments, &dynamic_argument(shell), true) else {
            continue;
        };
        let invokes = match shell {
            "cmd" => crate::evaluator::cmd_host_may_run_inline(&windows_argv(&joined)),
            "powershell" => {
                crate::evaluator::powershell_host_may_run_inline(&windows_argv(&joined), |word| {
                    word.contains(DYNAMIC_ARGUMENT)
                })
            }
            _ => true,
        };
        if invokes {
            lines.push(format!("{shell} {joined}"));
        }
    }
    if is_computed_program(text, program) {
        if let Some(joined) = joined_arguments(text, arguments, DYNAMIC_ARGUMENT, true) {
            let written = match program {
                Value::Elements(elements) if elements.len() == 1 => text
                    .get(elements[0].clone())
                    .map(|raw| raw.trim().to_string()),
                _ => None,
            };
            let mut line = format!(
                "& {}",
                written.unwrap_or_else(|| format!("${DYNAMIC_PROGRAM}"))
            );
            for word in windows_argv(&joined) {
                line.push(' ');
                line.push_str(&powershell_word(&word));
            }
            lines.push(line);
        }
    }
    if let Some(name) = derived_program(text, program) {
        let named = Bound {
            file: Value::Literal(name),
            arguments: Some(arguments.clone()),
        };
        lines.extend(bound_lines(text, &named));
    }
    lines
}

fn bound_lines(text: &str, bound: &Bound) -> Vec<String> {
    let Some(arguments) = bound.arguments.as_ref() else {
        return Vec::new();
    };
    let file = match value_strings(text, &bound.file) {
        Some(strings) if strings.len() == 1 => strings.into_iter().next(),
        Some(_) => return Vec::new(),
        None => get_command_program(text, &bound.file),
    };
    let Some(file) = file else {
        return unnamed_program_lines(text, &bound.file, arguments);
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
    // A known program reads its line even when none of the list is known,
    // as the same program called directly does (`& git $x` is judged).
    let Some(joined) = joined_arguments(text, arguments, DYNAMIC_ARGUMENT, false) else {
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
/// Group 1 is a bare name. Group 3 is a name quoted after the call or
/// dot-source operator (`& 'Start-Process'`, `.'saps'`, `& ("…")`, any of
/// PowerShell's quote characters), with group 2 and 4 the optional
/// parentheses around it. `start` is an alias on Windows only (Microsoft's
/// Start-Process documentation), where `& 'start'` resolves it too.
static START_PROCESS_NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)(?:^|[\s;|&({=\\])(start-process|saps|start)|(?:^|[\s;|&({=])[&.][^\S\r\n]*(\([^\S\r\n]*)?['"\x{2018}-\x{201E}](?:microsoft\.powershell\.management\\)?(start-process|saps|start)['"\x{2018}-\x{201E}]([^\S\r\n]*\))?"#,
    )
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
        let (name, after) = if let Some(name) = found.get(1) {
            // A bare name is a whole word: blanks, a line continuation, or
            // a `(` or `{` that starts the first argument
            // (`Start-Process('git')`) follow. Any other character
            // continues the command name.
            let after = name.end();
            let tail = text.get(after..).unwrap_or_default();
            if horizontal_space_len(text, after).is_none()
                && !tail.starts_with("`\n")
                && !tail.starts_with("`\r\n")
                && !tail.starts_with(['(', '{'])
            {
                continue;
            }
            (name, after)
        } else {
            // A quoted name ends at its closing quote: the arguments may
            // follow at once (`& 'Start-Process'git reset,--hard`).
            let name = found.get(3).expect("one name group is present");
            let quote_end = name.end()
                + text
                    .get(name.end()..)
                    .and_then(|tail| tail.chars().next())
                    .map_or(0, char::len_utf8);
            match (found.get(2), found.get(4)) {
                (Some(_), Some(close)) => (name, close.end()),
                (Some(_), None) => continue,
                (None, _) => (name, quote_end),
            }
        };
        let (units, glued, end) = units(text, after, UNIT_LIMIT + 1);
        let bind_both = |units: &[Unit]| -> Vec<Bound> {
            [true, false]
                .into_iter()
                .filter_map(|version_7| bind(text, units, version_7))
                .collect()
        };
        let mut bindings = bind_both(&units);
        if bindings.is_empty() {
            if let Some(merged) = merge_glued(&units, &glued) {
                bindings = bind_both(&merged);
            }
        }
        let mut lines: Vec<String> = Vec::new();
        for bound in &bindings {
            for line in bound_lines(text, bound) {
                if !lines.contains(&line) {
                    lines.push(line);
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
        assert!(lines("Start-Process $tool -ArgumentList $rest").is_empty());
    }

    /// A known program reads its line even when none of the list is known,
    /// as the program called directly does (`& git $a`).
    #[test]
    fn known_programs_read_unknown_lists() {
        for spelling in [
            "$a = 'reset','--hard'; Start-Process git -ArgumentList $a -Wait -NoNewWindow",
            "Start-Process git -ArgumentList $rest",
            "Start-Process git -ArgumentList ('reset --hard'.ToString())",
            "Start-Process git -ArgumentList (\"{0} --hard\" -f 'reset')",
            "Start-Process git -ArgumentList ('reset','--hard' -join ' ')",
            "Start-Process git -ArgumentList @{a='reset --hard'}.a",
        ] {
            assert_eq!(
                lines(spelling),
                program("git DCG_START_PROCESS_ARGUMENT"),
                "{spelling:?}"
            );
        }
        assert_eq!(
            lines("Start-Process notepad $file"),
            program("notepad DCG_START_PROCESS_ARGUMENT")
        );
        // Member access or an index on a literal: its strings and one
        // unknown word.
        assert_eq!(
            lines("Start-Process git ('a','reset --hard')[1] -Wait"),
            program("git a reset --hard DCG_START_PROCESS_ARGUMENT")
        );
        for spelling in [
            "Start-Process git (' reset --hard ').Trim() -Wait",
            "Start-Process git {reset --hard}.ToString() -Wait",
        ] {
            assert_eq!(
                lines(spelling),
                program("git reset --hard DCG_START_PROCESS_ARGUMENT"),
                "{spelling:?}"
            );
        }
    }

    /// Measured with PowerShell 7.5: a script block where a string belongs
    /// is its text between the braces, and `$( )` gives its statements'
    /// strings as `@( )` does.
    #[test]
    fn script_blocks_and_subexpressions_are_their_strings() {
        for spelling in [
            "Start-Process git {reset --hard} -Wait -NoNewWindow",
            "Start-Process git -ArgumentList { reset   --hard } -Wait",
            "Start-Process git -ArgumentList $('reset','--hard')",
            "Start-Process git -ArgumentList $('reset';'--hard')",
            "Start-Process git -ArgumentList $(\"reset --hard\")",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(
            lines("Start-Process git {reset \"a b\" 'c d'}"),
            vec![
                "& git reset 'a b' '''c' 'd'''".to_string(),
                "git reset 'a b' ''\\''c' 'd'\\'''".to_string(),
            ]
        );
        assert_eq!(
            lines("Start-Process git {status},{log}"),
            program("git status log")
        );
        assert_eq!(
            lines("Start-Process cmd {/c git reset --hard}"),
            vec!["cmd /c git reset --hard".to_string()]
        );
    }

    /// Measured with PowerShell 7.5: after `&` or `.` the name may be
    /// quoted (any PowerShell quote), parenthesized, or followed at once
    /// by the arguments.
    #[test]
    fn quoted_names_after_the_call_operator() {
        for spelling in [
            "& 'Start-Process' git 'reset','--hard'",
            "&'Start-Process' git reset,--hard",
            "& 'Start-Process'git reset,--hard",
            "& \"Start-Process\" git reset,--hard",
            ". 'Start-Process' git reset,--hard",
            ".'Start-Process' git reset,--hard",
            "& 'saps' git reset,--hard",
            "& 'start' git reset,--hard",
            "& 'Microsoft.PowerShell.Management\\Start-Process' git reset,--hard",
            "& \u{2018}Start-Process\u{2019} git reset,--hard",
            "& \u{201C}Start-Process\u{201D} git reset,--hard",
            "& ('Start-Process') git reset,--hard",
            "& 'Start-Process'('git') reset,--hard",
            "$p = & 'Start-Process' git reset,--hard -PassThru",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(
            lines("& 'Start-Process' cmd '/c x'"),
            vec!["cmd /c x".to_string()]
        );
        for spelling in [
            "& ('Start-Process' git reset,--hard",
            "$o.'Start-Process' git reset,--hard",
            "Write-Output 'Start-Process' git reset,--hard",
        ] {
            assert!(lines(spelling).is_empty(), "{spelling:?}");
        }
    }

    /// Measured with PowerShell 7.5: a group ends its argument unless
    /// member access, a method call or an index follows it.
    #[test]
    fn a_group_ends_its_argument() {
        for spelling in [
            "Start-Process git ('reset','--hard')-Wait -NoNewWindow",
            "Start-Process git ('reset','--hard')-NoNewWindow -Wait",
            "Start-Process git @('reset','--hard')-Wait",
            "Start-Process git $('reset','--hard')-Wait",
            "Start-Process git {reset --hard}-Wait",
        ] {
            assert_eq!(lines(spelling), program("git reset --hard"), "{spelling:?}");
        }
        assert_eq!(
            lines("Start-Process rm ('-rf','/')-Wait -NoNewWindow"),
            program("rm -rf /")
        );
        // PowerShell 7.5 stops on these with a binding error (two
        // arguments). The glued arguments are read as one unknown argument
        // instead, which fails closed (see `glued_arguments_fail_closed`).
        for spelling in [
            "Start-Process git -ArgumentList ('reset')x",
            "Start-Process git -ArgumentList ('reset')'--hard'",
            "Start-Process git $('reset')x",
            "Start-Process git @('reset')x",
            "Start-Process git {reset}x",
            "Start-Process git @{a='reset'}x",
            "Start-Process git ('reset --hard').Trim()x",
        ] {
            assert_eq!(
                lines(spelling),
                program("git DCG_START_PROCESS_ARGUMENT"),
                "{spelling:?}"
            );
        }
        // `${a}` is a variable: the word goes on.
        assert_eq!(
            lines("Start-Process git ${a}x -Wait"),
            program("git DCG_START_PROCESS_ARGUMENT")
        );
        assert_eq!(
            lines("Start-Process git re$('s')et,--hard"),
            program("git DCG_START_PROCESS_ARGUMENT --hard")
        );
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

    /// Measured with PowerShell 7.5: member access, a method call after a
    /// member, an index and their null-conditional forms continue the
    /// argument after every primary expression, with no blank before them.
    #[test]
    fn primary_expressions_continue_their_argument() {
        let unknown = program("git DCG_START_PROCESS_ARGUMENT");
        let derived = program("git reset --hard DCG_START_PROCESS_ARGUMENT");
        for (spelling, expected) in [
            ("Start-Process git $a.Trim() -Wait -NoNewWindow", &unknown),
            ("Start-Process git ${a}.Trim()", &unknown),
            ("Start-Process git $a.Substring(0)", &unknown),
            ("Start-Process git $a.Trim( )", &unknown),
            ("Start-Process git $a.Split(' ')", &unknown),
            ("Start-Process git $a.'Trim'()", &unknown),
            ("Start-Process git $a.Trim()-Wait -NoNewWindow", &unknown),
            ("Start-Process git -ArgumentList $a.Trim() -Wait", &unknown),
            (
                "Start-Process -FilePath git -ArgumentList:$a.Trim()",
                &unknown,
            ),
            ("Start-Process git $a.Clone()", &unknown),
            ("Start-Process git $_.Trim() -Wait", &unknown),
            ("Start-Process git $a.Trim()[0]", &unknown),
            ("Start-Process git $env:A.Trim()", &unknown),
            ("Start-Process git @{a='reset --hard'}?['a']", &unknown),
            ("Start-Process git 'reset --hard'.Trim() -Wait", &derived),
            ("Start-Process git \"reset --hard\".Trim()", &derived),
            (
                "Start-Process git 'reset --hard'.Trim().ToString()",
                &derived,
            ),
            ("Start-Process git 'reset --hard'.'Trim'()", &derived),
            ("Start-Process git 'reset --hard'?.Trim()", &derived),
            ("Start-Process git 'reset','--hard'.Trim()", &derived),
            ("Start-Process git @'\nreset --hard\n'@.Trim()", &derived),
            ("Start-Process git ('reset --hard')?.Trim() -Wait", &derived),
            ("Start-Process git ('reset','--hard')?[0..1]", &derived),
            ("Start-Process git @('reset','--hard')?[0..1]", &derived),
            ("Start-Process git $('reset --hard')?.Trim()", &derived),
            ("Start-Process git {reset --hard}?.ToString()", &derived),
            ("Start-Process git ('reset --hard')?.'Trim'()", &derived),
            (
                "Start-Process git ('reset --hard')?.Trim()?.ToString()",
                &derived,
            ),
            ("Start-Process git ('reset --hard')?.Trim()-Wait", &derived),
            (
                "Start-Process git -ArgumentList:('reset --hard')?.Trim()",
                &derived,
            ),
        ] {
            assert_eq!(&lines(spelling), expected, "{spelling:?}");
        }
        assert_eq!(
            lines("Start-Process git 'a'.Replace('a','reset --hard')"),
            program("git a DCG_START_PROCESS_ARGUMENT")
        );
        assert_eq!(
            lines("Start-Process rm ('-rf','x')?[0..1] -Wait -NoNewWindow"),
            program("rm -rf x DCG_START_PROCESS_ARGUMENT")
        );
        assert_eq!(
            lines("Start-Process cmd $c.Trim()"),
            vec!["cmd %DCG_START_PROCESS_ARGUMENT%".to_string()]
        );
        assert_eq!(
            lines("Start-Process cmd ('/c git reset --hard')?.Trim()"),
            vec!["cmd /c git reset --hard %DCG_START_PROCESS_ARGUMENT%".to_string()]
        );
        assert_eq!(
            lines("Start-Process notepad $f.FullName"),
            program("notepad DCG_START_PROCESS_ARGUMENT")
        );
        assert_eq!(
            lines("Start-Process msedge 'https://example.com'.Trim()"),
            program("msedge https://example.com DCG_START_PROCESS_ARGUMENT")
        );
        // A blank before `?.` is a parse error; nothing binds.
        assert!(lines("Start-Process git ('reset --hard') ?.Trim()").is_empty());
    }

    /// A program dcg cannot name is read as the same program called
    /// directly, as written, when an expression computes it; as a shell
    /// only when the line invokes that shell's command reader; and as the
    /// program its literal parts name.
    #[test]
    fn unnamed_programs_read_as_the_direct_call() {
        let strings = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            lines("Start-Process $g.Trim() reset,--hard -Wait -NoNewWindow"),
            strings(&[
                "powershell reset --hard",
                "sh reset --hard",
                "& $g.Trim() reset --hard",
            ])
        );
        for spelling in [
            "Start-Process ('git')?.Trim() reset,--hard",
            "Start-Process -FilePath ('git')?.Trim() reset,--hard",
        ] {
            assert_eq!(
                lines(spelling),
                strings(&[
                    "powershell reset --hard",
                    "sh reset --hard",
                    "& ('git')?.Trim() reset --hard",
                    "& git reset --hard",
                    "git reset --hard",
                ]),
                "{spelling:?}"
            );
        }
        // A derived name is read as the same literal program: blanks
        // around it trimmed, a path with blanks kept whole.
        for spelling in [
            "Start-Process ('git ')?.Trim() reset,--hard",
            "Start-Process (' git')?.Trim() reset,--hard",
        ] {
            assert!(
                lines(spelling).contains(&"& git reset --hard".to_string()),
                "{spelling:?}"
            );
        }
        for spelling in [
            "Start-Process ('C:\\Program Files\\Git\\cmd\\git.exe')?.Trim() reset,--hard",
            "Start-Process ('C:\\Program Files\\Git\\cmd\\git.exe').Trim() -ArgumentList 'reset','--hard'",
        ] {
            assert!(
                lines(spelling)
                    .contains(&"& 'C:\\Program Files\\Git\\cmd\\git.exe' reset --hard".to_string()),
                "{spelling:?}: {:?}",
                lines(spelling)
            );
        }
        assert_eq!(
            lines(
                "Start-Process \"$env:ProgramFiles\\Git\\cmd\\git.exe\" -ArgumentList 'reset','--hard'"
            ),
            strings(&[
                "powershell reset --hard",
                "sh reset --hard",
                "& \"$env:ProgramFiles\\Git\\cmd\\git.exe\" reset --hard",
                "& git.exe reset --hard",
                "git.exe reset --hard",
            ])
        );
        // An install: no shell reads `/S`, the direct call is read as is,
        // and the program is the installer its path names.
        assert_eq!(
            lines("Start-Process \"$env:TEMP\\installer.exe\" -ArgumentList '/S' -Wait"),
            strings(&[
                "sh /S",
                "& \"$env:TEMP\\installer.exe\" /S",
                "& installer.exe /S",
                "installer.exe /S",
            ])
        );
        assert_eq!(
            lines("Start-Process $exe.FullName -ArgumentList '--version'"),
            strings(&["sh --version", "& $exe.FullName --version"])
        );
        assert_eq!(
            lines("Start-Process (Get-Command 'git') reset,--hard"),
            program("git reset --hard")
        );
        assert_eq!(
            lines("Start-Process (gcm -Name git.exe) reset,--hard"),
            program("git.exe reset --hard")
        );
        // A plain variable keeps the shell readings only.
        for spelling in [
            "Start-Process $g reset,--hard",
            "Start-Process ${g} reset,--hard",
        ] {
            assert_eq!(
                lines(spelling),
                strings(&["powershell reset --hard", "sh reset --hard"]),
                "{spelling:?}"
            );
        }
        assert_eq!(
            lines("Start-Process $exe -ArgumentList '/S','/D=C:\\Tools'"),
            strings(&["sh /S /D=C:\\Tools"])
        );
        // A shell's own command switches.
        assert_eq!(
            lines("Start-Process $exe -ArgumentList '/s','/c','git reset --hard'"),
            strings(&["cmd /s /c git reset --hard", "sh /s /c git reset --hard",])
        );
        assert_eq!(
            lines("Start-Process $exe -ArgumentList '-NoProfile','-c','git reset --hard'"),
            strings(&[
                "powershell -NoProfile -c git reset --hard",
                "sh -NoProfile -c git reset --hard",
            ])
        );
        // An element dcg cannot read is not a command string it can judge.
        assert_eq!(
            lines("Start-Process $exe -ArgumentList $flag,'/S'"),
            strings(&["sh \"$DCG_START_PROCESS_ARGUMENT\" /S"])
        );
    }

    /// A cmd.exe line runs a command only at an exact `/C` or `/K` reached
    /// past switches that run nothing and words that are not switches; a
    /// PowerShell line only at `-Command`,
    /// a decodable `-EncodedCommand` or a 5.1 command string.
    #[test]
    fn shell_command_gates() {
        let argv = |line: &str| windows_argv(line);
        let cmd = |line: &str| crate::evaluator::cmd_host_may_run_inline(&argv(line));
        assert!(cmd("/c git reset --hard"));
        assert!(cmd("/S /K dir"));
        assert!(cmd("/Q /C git reset --hard"));
        assert!(cmd("/d /e:on /v:off /c dir"));
        assert!(cmd("foo /c git reset --hard"));
        assert!(cmd("/d x.y /k dir"));
        for line in [
            "/S /D=C:\\Tools",
            "/quiet /norestart",
            "--install -c x",
            "/configure config.xml",
            "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "/SILENT /COMPONENTS=main",
            "/S /RESTARTAPPLICATIONS",
            "/quiet /Config C:\\x.xml",
            "/S /KEEPSETTINGS",
            "/repair",
            "/reset",
            "/R",
            "/s/c dir",
            "/v:on/c dir",
            "/S /D=C:\\Tools /c x",
            "install C:/repo/x",
            "foo/c dir",
            "/d %DCG_START_PROCESS_ARGUMENT%",
            "",
        ] {
            assert!(!cmd(line), "{line:?}");
        }
        let unknown = |word: &str| word.contains(DYNAMIC_ARGUMENT);
        let ps =
            |line: &str| crate::evaluator::powershell_host_may_run_inline(&argv(line), unknown);
        assert!(ps("-NoProfile -Command git"));
        assert!(ps("-c print(1)"));
        assert!(ps("-EncodedCommand ZwBpAHQAIABzAHQAYQB0AHUAcwA="));
        assert!(ps("-enc DCG_START_PROCESS_ARGUMENT"));
        assert!(ps("git reset --hard"));
        for line in [
            "-e console.log(1)",
            "-ec production",
            "-enc utf8 in.txt",
            "-EncodedCommand",
            "-s",
            "-s file.txt",
            "-imp file.txt",
            "-ImportSystemModules -c git",
            "/S /C dir",
            "/S",
            "--install",
            "-y",
            "-p 8080",
            "-File build.ps1",
            "DCG_START_PROCESS_ARGUMENT",
        ] {
            assert!(!ps(line), "{line:?}");
        }
    }

    /// Measured with PowerShell 7.5: a quote right after a parameter name
    /// makes one plain word, which the program receives (`-r'f x'` is
    /// `-rf x`).
    #[test]
    fn a_quote_after_a_parameter_name_makes_a_word() {
        for (spelling, expected) in [
            ("Start-Process rm -r'f /' -Wait -NoNewWindow", "rm -rf /"),
            ("Start-Process rm -R'f /'", "rm -Rf /"),
            ("Start-Process rm -f'r /'", "rm -fr /"),
            ("Start-Process -FilePath rm -r'f /'", "rm -rf /"),
            ("Start-Process rm -Wait -NoNewWindow -r'f /'", "rm -rf /"),
            (
                "Start-Process git -C'. reset --hard' -Wait",
                "git -C. reset --hard",
            ),
            (
                "Start-Process git -C\". reset --hard\"",
                "git -C. reset --hard",
            ),
            (
                "Start-Process git -ArgumentList'reset','--hard'",
                "git -ArgumentListreset --hard",
            ),
        ] {
            assert_eq!(lines(spelling), program(expected), "{spelling:?}");
        }
        // A parameter followed by a group or script block keeps its value.
        assert_eq!(
            lines("Start-Process git -Args{reset --hard}"),
            program("git reset --hard")
        );
        assert_eq!(
            lines("Start-Process git -Args('reset --hard')"),
            program("git reset --hard")
        );
    }

    /// Arguments glued with no blank that do not bind as scanned are read
    /// as one argument of unknown value, so a continuation the scan does
    /// not model fails closed instead of reading nothing.
    #[test]
    fn glued_arguments_fail_closed() {
        for spelling in [
            "Start-Process git 'a'b",
            "Start-Process git ('reset')--hard -Wait",
            "Start-Process git ('reset','--hard')('x')",
            "Start-Process git 'reset'('--hard')",
            "Start-Process git -ArgumentList('reset')x",
        ] {
            assert_eq!(
                lines(spelling),
                program("git DCG_START_PROCESS_ARGUMENT"),
                "{spelling:?}"
            );
        }
        // Glued arguments that bind as scanned keep their reading.
        assert_eq!(
            lines("Start-Process git 'reset','--hard'-Wait"),
            program("git reset --hard")
        );
        // A call that does not bind with nothing glued still reads nothing.
        assert!(lines("Start-Process git reset --hard").is_empty());
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
