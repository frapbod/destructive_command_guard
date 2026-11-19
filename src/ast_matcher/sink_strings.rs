//! String literals of the interpreter languages, read the way the language
//! builds the string an exec sink receives.
//!
//! The exec-sink readers (`exec_argv_operands`, the region scanners and the
//! reconstruction for the packs) knew only `'…'` and `"…"`, so every other
//! spelling of a string was an unknown value or, worse, broke the scan of the
//! call: Python's triple-quoted, raw and f-strings, Perl's `q()`/`qq()`, Ruby's
//! `%q()`/`%Q()`/`%()`, a JavaScript template holding a quote. A double-quoted
//! string that interpolates was kept as written with one unknown value added
//! at its end, so the shell quotes around an interpolation
//! (`system("'gi${x}t' reset --hard")`) were read as literal text. Here each
//! literal kind of each language is delimited and decoded, and every part only
//! known at run time (an interpolation, an f-string field, an escape not
//! modeled) becomes one `runtime` marker where it sits.

use crate::heredoc::ScriptLanguage;

/// How deep interpolations may nest inside one literal before it is not read.
const MAX_NESTING: usize = 32;

/// How a literal's body is read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Body {
    /// Only `\\` and an escaped delimiter are escapes: `'…'` in Ruby, Perl
    /// and PHP, Perl `q()`, Ruby `%q()`.
    Verbatim,
    /// No escapes at all: a Go raw string.
    Raw,
    /// Python: `raw` keeps backslashes, `fields` makes `{…}` code.
    Python { raw: bool, fields: bool },
    /// Escapes, and with `interpolates` the language's interpolation.
    Escaped { interpolates: bool },
    /// A JavaScript template literal.
    Template,
    /// Whitespace-separated words: Perl `qw()`, Ruby `%w()`.
    Words,
}

/// One string literal of a language in a source text.
#[derive(Clone, Copy, Debug)]
pub(super) struct Literal {
    /// Where the body starts and ends (delimiters excluded).
    pub body: (usize, usize),
    /// One past the closing delimiter.
    pub end: usize,
    pub open: u8,
    pub close: u8,
    pub kind: Body,
    /// The literal runs its text as a command (backticks, Perl `qx`, Ruby
    /// `%x`) rather than being a string value.
    pub command: bool,
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn closing_delimiter(open: u8) -> u8 {
    match open {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        other => other,
    }
}

/// The literal of `language` starting exactly at `at` in `text`, prefix or
/// sigil included (`f"…"`, `q(…)`, `%Q[…]`), or `None` when none starts there
/// or it never closes.
pub(super) fn literal_at(text: &str, at: usize, language: ScriptLanguage) -> Option<Literal> {
    literal_at_depth(text, at, language, 0)
}

fn literal_at_depth(
    text: &str,
    at: usize,
    language: ScriptLanguage,
    depth: usize,
) -> Option<Literal> {
    if depth > MAX_NESTING {
        return None;
    }
    let bytes = text.as_bytes();
    let &first = bytes.get(at)?;
    let previous = at.checked_sub(1).map(|index| bytes[index]);
    let after_identifier = previous.is_some_and(is_identifier_byte);
    match language {
        ScriptLanguage::Python => {
            let mut quote_at = at;
            while bytes.get(quote_at).is_some_and(u8::is_ascii_alphabetic) && quote_at - at < 2 {
                quote_at += 1;
            }
            if quote_at > at {
                if after_identifier {
                    return None;
                }
                let prefix = text[at..quote_at].to_ascii_lowercase();
                if !prefix
                    .bytes()
                    .all(|byte| matches!(byte, b'r' | b'b' | b'u' | b'f' | b't'))
                {
                    return None;
                }
            }
            let &quote = bytes.get(quote_at)?;
            if !matches!(quote, b'\'' | b'"') {
                return None;
            }
            let prefix = text[at..quote_at].to_ascii_lowercase();
            let fields = prefix.contains('f') || prefix.contains('t');
            let raw = prefix.contains('r');
            let (body, end) = super::python_string_end(bytes, quote_at, fields)?;
            Some(Literal {
                body: (body.start, body.end),
                end,
                open: quote,
                close: quote,
                kind: Body::Python { raw, fields },
                command: false,
            })
        }
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => match first {
            b'\'' | b'"' => quoted(
                bytes,
                at,
                Body::Escaped {
                    interpolates: false,
                },
                false,
            ),
            b'`' => {
                let end = super::js_template_end(text, at, depth)?;
                Some(Literal {
                    body: (at + 1, end - 1),
                    end,
                    open: b'`',
                    close: b'`',
                    kind: Body::Template,
                    command: false,
                })
            }
            _ => None,
        },
        ScriptLanguage::Go => match first {
            b'"' => quoted(
                bytes,
                at,
                Body::Escaped {
                    interpolates: false,
                },
                false,
            ),
            b'`' => {
                let close = memchr::memchr(b'`', &bytes[at + 1..])? + at + 1;
                Some(Literal {
                    body: (at + 1, close),
                    end: close + 1,
                    open: b'`',
                    close: b'`',
                    kind: Body::Raw,
                    command: false,
                })
            }
            _ => None,
        },
        ScriptLanguage::Php => match first {
            b'\'' => quoted(bytes, at, Body::Verbatim, false),
            b'"' | b'`' => interpolating(text, at, first, first, language, depth, first == b'`'),
            _ => None,
        },
        ScriptLanguage::Ruby => match first {
            b'\'' => quoted(bytes, at, Body::Verbatim, false),
            b'"' | b'`' => interpolating(text, at, first, first, language, depth, first == b'`'),
            b'%' => ruby_percent_literal(text, at, depth),
            _ => None,
        },
        ScriptLanguage::Perl => match first {
            b'\'' => quoted(bytes, at, Body::Verbatim, false),
            b'"' | b'`' => interpolating(text, at, first, first, language, depth, first == b'`'),
            b'q' if !after_identifier
                && !previous.is_some_and(|byte| b"$@%&>:-".contains(&byte)) =>
            {
                perl_quote_operator(text, at, depth)
            }
            _ => None,
        },
        ScriptLanguage::Bash | ScriptLanguage::Unknown => match first {
            b'\'' | b'"' => quoted(
                bytes,
                at,
                Body::Escaped {
                    interpolates: false,
                },
                false,
            ),
            _ => None,
        },
    }
}

/// A literal closed by the first unescaped `open` byte after it.
fn quoted(bytes: &[u8], at: usize, kind: Body, command: bool) -> Option<Literal> {
    let open = bytes[at];
    let mut index = at + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == open => {
                return Some(Literal {
                    body: (at + 1, index),
                    end: index + 1,
                    open,
                    close: open,
                    kind,
                    command,
                });
            }
            _ => index += 1,
        }
    }
    None
}

/// A delimited body whose opening delimiter is at `open_at`: bracket pairs
/// nest, an escaped delimiter does not count, and with `interpolates` the
/// language's interpolations (which may hold quotes and delimiters of their
/// own) are skipped whole.
fn interpolating(
    text: &str,
    open_at: usize,
    open: u8,
    close: u8,
    language: ScriptLanguage,
    depth: usize,
    command: bool,
) -> Option<Literal> {
    delimited(
        text,
        open_at,
        open,
        close,
        language,
        depth,
        Body::Escaped { interpolates: true },
        command,
    )
}

#[allow(clippy::too_many_arguments)]
fn delimited(
    text: &str,
    open_at: usize,
    open: u8,
    close: u8,
    language: ScriptLanguage,
    depth: usize,
    kind: Body,
    command: bool,
) -> Option<Literal> {
    let bytes = text.as_bytes();
    let interpolates = matches!(kind, Body::Escaped { interpolates: true });
    let mut nesting = 0usize;
    let mut index = open_at + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            index += 2;
            continue;
        }
        if interpolates && let Some(end) = interpolation_end(text, index, language, depth) {
            index = end;
            continue;
        }
        if open != close && byte == open {
            nesting += 1;
        } else if byte == close {
            if nesting == 0 {
                return Some(Literal {
                    body: (open_at + 1, index),
                    end: index + 1,
                    open,
                    close,
                    kind,
                    command,
                });
            }
            nesting -= 1;
        }
        index += 1;
    }
    None
}

/// Ruby `%` literals: `%q`, `%Q`, `%w`, `%W`, `%i`, `%I`, `%x` and a bare
/// `%` with any punctuation delimiter. A bare `%` after an operand is the
/// modulo operator instead.
fn ruby_percent_literal(text: &str, at: usize, depth: usize) -> Option<Literal> {
    let bytes = text.as_bytes();
    let mut open_at = at + 1;
    let letter = bytes
        .get(open_at)
        .copied()
        .filter(|byte| b"qQwWiIxrs".contains(byte));
    if letter.is_some() {
        open_at += 1;
    }
    let &open = bytes.get(open_at)?;
    if open.is_ascii_alphanumeric() || open.is_ascii_whitespace() || open == b'=' {
        return None;
    }
    let before = text[..at].trim_end();
    let spaced = before.len() < at;
    let operand_before = before
        .bytes()
        .next_back()
        .is_some_and(|byte| is_identifier_byte(byte) || b")]}'\"`".contains(&byte));
    // `x %(3)` is modulo; `system %(…)` with a space before and none after
    // is a literal, as Ruby reads it.
    let spaced_literal = spaced && !bytes.get(open_at + 1).is_some_and(u8::is_ascii_whitespace);
    if operand_before && !spaced_literal {
        return None;
    }
    let close = closing_delimiter(open);
    let (kind, command) = match letter {
        Some(b'q') => (Body::Verbatim, false),
        Some(b'w' | b'i') => (Body::Words, false),
        Some(b'W' | b'I') => (Body::Words, false),
        Some(b'x') => (Body::Escaped { interpolates: true }, true),
        Some(b'r' | b's') => (Body::Verbatim, false),
        _ => (Body::Escaped { interpolates: true }, false),
    };
    delimited(
        text,
        open_at,
        open,
        close,
        ScriptLanguage::Ruby,
        depth,
        kind,
        command,
    )
}

/// Perl `q`, `qq`, `qw` and `qx` with any punctuation delimiter. After
/// whitespace a `#` starts a comment, and `q =>` is a hash key.
fn perl_quote_operator(text: &str, at: usize, depth: usize) -> Option<Literal> {
    let bytes = text.as_bytes();
    let mut index = at + 1;
    let second = bytes
        .get(index)
        .copied()
        .filter(|byte| b"qwx".contains(byte));
    if second.is_some() {
        index += 1;
    }
    if bytes
        .get(index)
        .is_some_and(|byte| is_identifier_byte(*byte))
    {
        return None;
    }
    let mut open_at = index;
    while bytes.get(open_at).is_some_and(u8::is_ascii_whitespace) {
        open_at += 1;
    }
    let &open = bytes.get(open_at)?;
    let spaced = open_at > index;
    if !open.is_ascii_punctuation()
        || open == b'_'
        || (spaced && open == b'#')
        || matches!(open, b',' | b';' | b')' | b']' | b'}' | b'>')
        || (open == b'=' && bytes.get(open_at + 1) == Some(&b'>'))
    {
        return None;
    }
    let close = closing_delimiter(open);
    let (kind, command) = match second {
        None => (Body::Verbatim, false),
        Some(b'w') => (Body::Words, false),
        Some(b'x') if open == b'\'' => (Body::Verbatim, true),
        Some(b'x') => (Body::Escaped { interpolates: true }, true),
        _ => (Body::Escaped { interpolates: true }, false),
    };
    delimited(
        text,
        open_at,
        open,
        close,
        ScriptLanguage::Perl,
        depth,
        kind,
        command,
    )
}

/// One past the interpolation starting at `at` inside an interpolating
/// literal of `language`, or `None` when none starts there.
fn interpolation_end(
    text: &str,
    at: usize,
    language: ScriptLanguage,
    depth: usize,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let next = bytes.get(at + 1).copied();
    match (language, bytes[at]) {
        (ScriptLanguage::Ruby, b'#') => match next? {
            b'{' => code_block_end(text, at + 1, language, depth),
            b'@' => {
                let mut index = at + 2;
                if bytes.get(index) == Some(&b'@') {
                    index += 1;
                }
                Some(identifier_end(bytes, index)).filter(|&end| end > index)
            }
            b'$' => Some(identifier_end(bytes, at + 2)).filter(|&end| end > at + 2),
            _ => None,
        },
        (ScriptLanguage::Perl, b'$' | b'@') => perl_variable_end(text, at, depth),
        (ScriptLanguage::Php, b'$') => match next? {
            b'{' => code_block_end(text, at + 1, language, depth),
            byte if byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80 => {
                php_variable_end(text, at, depth)
            }
            _ => None,
        },
        (ScriptLanguage::Php, b'{') if next == Some(b'$') => {
            code_block_end(text, at, language, depth)
        }
        _ => None,
    }
}

fn identifier_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while bytes
        .get(index)
        .is_some_and(|byte| is_identifier_byte(*byte) || *byte >= 0x80)
    {
        index += 1;
    }
    index
}

/// One past the bracket closing the `{`, `[` or `(` at `open`, skipping the
/// language's literals inside it.
fn code_block_end(
    text: &str,
    open: usize,
    language: ScriptLanguage,
    depth: usize,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut stack = vec![closing_delimiter(*bytes.get(open)?)];
    let mut index = open + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"' | b'`')
            && let Some(literal) = literal_at_depth(text, index, language, depth + 1)
        {
            index = literal.end;
            continue;
        }
        match byte {
            b'\\' => {
                index += 2;
                continue;
            }
            b'(' | b'[' | b'{' => {
                if stack.len() > MAX_NESTING {
                    return None;
                }
                stack.push(closing_delimiter(byte));
            }
            b')' | b']' | b'}' => {
                if stack.pop()? != byte {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// A Perl scalar or array interpolation: `$x`, `${x}`, `${ expr }`, `$x::y`,
/// `@x`, `@{…}`, the punctuation variables, and the subscripts and arrows
/// after them. `None` for a `$` or `@` that stays literal text.
fn perl_variable_end(text: &str, at: usize, depth: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let sigil = bytes[at];
    let next = *bytes.get(at + 1)?;
    let mut index = match next {
        b'{' => code_block_end(text, at + 1, ScriptLanguage::Perl, depth)?,
        b'$' if sigil == b'$' => {
            // `$$` is the process id; `$$x` dereferences `$x`.
            let end = identifier_end(bytes, at + 2);
            if end > at + 2 { end } else { at + 2 }
        }
        b':' if bytes.get(at + 2) == Some(&b':') => identifier_end(bytes, at + 3),
        byte if byte.is_ascii_alphabetic() || byte == b'_' => {
            let mut end = identifier_end(bytes, at + 1);
            while bytes.get(end) == Some(&b':') && bytes.get(end + 1) == Some(&b':') {
                end = identifier_end(bytes, end + 2);
            }
            end
        }
        byte if sigil == b'$' && byte.is_ascii_digit() => identifier_end(bytes, at + 1),
        b'&' | b'`' | b'\'' | b'+' | b'!' | b'0' | b';' | b',' | b'.' | b'/' | b'\\' | b'^'
            if sigil == b'$' =>
        {
            at + 2
        }
        _ => return None,
    };
    loop {
        let rest = &bytes[index..];
        if rest.starts_with(b"->[") || rest.starts_with(b"->{") {
            index = code_block_end(text, index + 2, ScriptLanguage::Perl, depth)?;
        } else if matches!(rest.first(), Some(b'[' | b'{')) {
            index = code_block_end(text, index, ScriptLanguage::Perl, depth)?;
        } else {
            return Some(index);
        }
    }
}

/// A PHP simple interpolation: `$name`, then one `[…]` or `->name`.
fn php_variable_end(text: &str, at: usize, depth: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let index = identifier_end(bytes, at + 1);
    if bytes.get(index) == Some(&b'[') {
        return code_block_end(text, index, ScriptLanguage::Php, depth);
    }
    if bytes[index..].starts_with(b"->")
        && bytes
            .get(index + 2)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return Some(identifier_end(bytes, index + 2));
    }
    Some(index)
}

/// A literal's value as the language builds it, each run-time part one
/// `runtime` marker, or `None` for a word list (see [`words`]).
pub(super) fn value(
    text: &str,
    literal: &Literal,
    language: ScriptLanguage,
    runtime: &str,
) -> Option<String> {
    let body = &text[literal.body.0..literal.body.1];
    let mut out = Decoder {
        out: String::with_capacity(body.len()),
        runtime,
    };
    match literal.kind {
        Body::Words => return None,
        Body::Raw => out.text(body),
        Body::Verbatim => {
            let mut chars = body.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '\\'
                    && chars.peek().is_some_and(|next| {
                        *next == '\\'
                            || u32::from(*next) == u32::from(literal.open)
                            || u32::from(*next) == u32::from(literal.close)
                    })
                {
                    if let Some(next) = chars.next() {
                        out.out.push(next);
                    }
                    continue;
                }
                out.out.push(ch);
            }
        }
        Body::Template => {
            let template = &text[literal.body.0 - 1..literal.end];
            let (_, cooked) = super::js_template_literal(template, 0)?;
            out.out = cooked.replace(super::RUNTIME_VALUE, runtime);
        }
        Body::Python { raw, fields } => python_body(&mut out, body, raw, fields),
        Body::Escaped { interpolates } => {
            escaped_body(&mut out, text, literal, language, interpolates);
        }
    }
    Some(out.out)
}

/// The words of a `qw()` / `%w()` literal.
pub(super) fn words<'t>(text: &'t str, literal: &Literal) -> Option<Vec<&'t str>> {
    (literal.kind == Body::Words).then(|| {
        text[literal.body.0..literal.body.1]
            .split_ascii_whitespace()
            .collect()
    })
}

struct Decoder<'r> {
    out: String,
    runtime: &'r str,
}

impl Decoder<'_> {
    fn text(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn unknown(&mut self) {
        if !self.out.ends_with(self.runtime) {
            self.out.push_str(self.runtime);
        }
    }

    fn code_point(&mut self, digits: &str, radix: u32) {
        match u32::from_str_radix(digits, radix)
            .ok()
            .and_then(char::from_u32)
        {
            Some(ch) if !digits.is_empty() => self.out.push(ch),
            _ => self.unknown(),
        }
    }
}

fn take_while_max(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    max: usize,
    f: impl Fn(char) -> bool,
) -> String {
    let mut taken = String::new();
    while taken.len() < max && chars.peek().is_some_and(|ch| f(*ch)) {
        taken.push(chars.next().unwrap_or_default());
    }
    taken
}

fn python_body(out: &mut Decoder<'_>, body: &str, raw: bool, fields: bool) {
    let bytes = body.as_bytes();
    let mut index = 0;
    let chars_from = |out: &mut Decoder<'_>, from: usize, to: usize| {
        let segment = &body[from..to];
        if raw {
            out.text(segment);
        } else {
            python_escapes(out, segment);
        }
    };
    let mut literal_start = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'{' if fields => {
                chars_from(out, literal_start, index);
                if bytes.get(index + 1) == Some(&b'{') {
                    out.text("{");
                    index += 2;
                } else {
                    out.unknown();
                    index = super::python_replacement_field_end(bytes, index + 1)
                        .unwrap_or(bytes.len());
                }
                literal_start = index;
            }
            b'}' if fields && bytes.get(index + 1) == Some(&b'}') => {
                chars_from(out, literal_start, index);
                out.text("}");
                index += 2;
                literal_start = index;
            }
            _ => index += 1,
        }
    }
    chars_from(out, literal_start.min(bytes.len()), bytes.len());
}

fn python_escapes(out: &mut Decoder<'_>, segment: &str) {
    let mut chars = segment.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.out.push(ch);
            continue;
        }
        match chars.next() {
            None => out.out.push('\\'),
            Some('\n') => {}
            Some(escaped @ ('\\' | '\'' | '"')) => out.out.push(escaped),
            Some('n') => out.out.push('\n'),
            Some('r') => out.out.push('\r'),
            Some('t') => out.out.push('\t'),
            Some('a') => out.out.push('\u{7}'),
            Some('b') => out.out.push('\u{8}'),
            Some('f') => out.out.push('\u{c}'),
            Some('v') => out.out.push('\u{b}'),
            Some('x') => {
                let digits = take_while_max(&mut chars, 2, |ch| ch.is_ascii_hexdigit());
                if digits.len() == 2 {
                    out.code_point(&digits, 16);
                } else {
                    out.unknown();
                }
            }
            Some('u') => {
                let digits = take_while_max(&mut chars, 4, |ch| ch.is_ascii_hexdigit());
                if digits.len() == 4 {
                    out.code_point(&digits, 16);
                } else {
                    out.unknown();
                }
            }
            Some('U') => {
                let digits = take_while_max(&mut chars, 8, |ch| ch.is_ascii_hexdigit());
                if digits.len() == 8 {
                    out.code_point(&digits, 16);
                } else {
                    out.unknown();
                }
            }
            Some(first @ '0'..='7') => {
                let mut digits = first.to_string();
                digits.push_str(&take_while_max(&mut chars, 2, |ch| {
                    ('0'..='7').contains(&ch)
                }));
                out.code_point(&digits, 8);
            }
            Some('N') => {
                // A named character: not modeled.
                if chars.peek() == Some(&'{') {
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            break;
                        }
                    }
                }
                out.unknown();
            }
            // Python keeps an unrecognized escape as written.
            Some(other) => {
                out.out.push('\\');
                out.out.push(other);
            }
        }
    }
}

fn escaped_body(
    out: &mut Decoder<'_>,
    text: &str,
    literal: &Literal,
    language: ScriptLanguage,
    interpolates: bool,
) {
    let (start, end) = literal.body;
    let mut index = start;
    while index < end {
        if interpolates
            && let Some(after) =
                interpolation_end(text, index, language, 0).filter(|&after| after <= end)
        {
            out.unknown();
            index = after;
            continue;
        }
        let ch = text[index..end].chars().next().unwrap_or_default();
        index += ch.len_utf8();
        if ch != '\\' {
            out.out.push(ch);
            continue;
        }
        let Some(escaped) = text[index..end].chars().next() else {
            out.out.push('\\');
            break;
        };
        index += escaped.len_utf8();
        let tail = &text[index..end];
        index += escape(out, escaped, tail, literal, language);
    }
}

/// The ASCII digits of `radix` at the start of `tail`, at most `max`.
fn leading_digits(tail: &str, max: usize, radix: u32) -> &str {
    let len = tail
        .bytes()
        .take(max)
        .take_while(|byte| char::from(*byte).is_digit(radix))
        .count();
    &tail[..len]
}

/// Decode the escape `\\escaped` whose following text is `tail`; returns how
/// many bytes of `tail` it also used.
fn escape(
    out: &mut Decoder<'_>,
    escaped: char,
    tail: &str,
    literal: &Literal,
    language: ScriptLanguage,
) -> usize {
    let braced = |out: &mut Decoder<'_>| -> usize {
        let digits = leading_digits(&tail[1..], 8, 16);
        if tail[1 + digits.len()..].starts_with('}') {
            out.code_point(digits, 16);
            digits.len() + 2
        } else {
            out.unknown();
            1
        }
    };
    if escaped == '\n' && language != ScriptLanguage::Php {
        return 0;
    }
    if u32::from(escaped) == u32::from(literal.open)
        || u32::from(escaped) == u32::from(literal.close)
    {
        out.out.push(escaped);
        return 0;
    }
    match escaped {
        'x' if language == ScriptLanguage::Perl && tail.starts_with('{') => braced(out),
        'x' => {
            let digits = leading_digits(tail, 2, 16);
            if digits.is_empty() && language == ScriptLanguage::Php {
                out.text("\\x");
            } else {
                out.code_point(digits, 16);
            }
            digits.len()
        }
        'u' if language == ScriptLanguage::Php => {
            if tail.starts_with('{') {
                braced(out)
            } else {
                out.text("\\u");
                0
            }
        }
        'u' if matches!(
            language,
            ScriptLanguage::Ruby
                | ScriptLanguage::JavaScript
                | ScriptLanguage::TypeScript
                | ScriptLanguage::Go
        ) =>
        {
            if tail.starts_with('{') {
                braced(out)
            } else {
                let digits = leading_digits(tail, 4, 16);
                if digits.len() == 4 {
                    out.code_point(digits, 16);
                } else {
                    out.unknown();
                }
                digits.len()
            }
        }
        '0'..='7' => {
            let digits = leading_digits(tail, 2, 8);
            let mut all = escaped.to_string();
            all.push_str(digits);
            out.code_point(&all, 8);
            digits.len()
        }
        'n' => push(out, '\n'),
        'r' => push(out, '\r'),
        't' => push(out, '\t'),
        'f' => push(out, '\u{c}'),
        'v' if language != ScriptLanguage::Perl => push(out, '\u{b}'),
        'a' if language != ScriptLanguage::Php => push(out, '\u{7}'),
        'b' if language != ScriptLanguage::Php => push(out, '\u{8}'),
        'e' if language != ScriptLanguage::Go => push(out, '\u{1b}'),
        's' if language == ScriptLanguage::Ruby => push(out, ' '),
        '\\' | '"' | '\'' | '`' | '$' => push(out, escaped),
        other => {
            match language {
                // PHP keeps an unknown escape as written.
                ScriptLanguage::Php => {
                    out.out.push('\\');
                    out.out.push(other);
                }
                // Ruby and JavaScript drop the backslash of an unknown
                // escape; Ruby's control and meta escapes are not modeled.
                ScriptLanguage::Ruby if matches!(other, 'c' | 'C' | 'M') => out.unknown(),
                ScriptLanguage::Ruby | ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => {
                    out.out.push(other);
                }
                // Perl: punctuation is itself; a letter (a case change, a
                // control or a name) changes what follows.
                ScriptLanguage::Perl if !other.is_ascii_alphanumeric() => out.out.push(other),
                _ => out.unknown(),
            }
            0
        }
    }
}

fn push(out: &mut Decoder<'_>, ch: char) -> usize {
    out.out.push(ch);
    0
}
