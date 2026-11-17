//! Gate for tests that hand text to a real shell.
//!
//! A test that runs case text, a generated hook command or a quoting round
//! trip in `/bin/sh`, `bash` or any other shell executes that text with the
//! machine's real binaries and the real HOME. `set -- <text>` still runs
//! command substitutions, and `env_clear()` stops neither absolute paths nor
//! redirections, so one wrong fixture or one quoting regression acts on real
//! files. Such a test therefore runs its shell only inside the shell-truth
//! suite sandbox (`scripts/shell-truth --suite` in frapbod/infra), which sets
//! `SHELL_TRUTH_SANDBOX=suite` and runs the whole suite under macOS
//! `sandbox-exec`. The variable alone proves nothing, so the kernel must also
//! report this process as sandboxed. Everywhere else, plain `cargo test`
//! included, the test skips its shell part and says so.
//!
//! `tests/real_shell_gate_audit.rs` fails when a shell spawn is not gated.
//!
//! The library includes this file for its unit tests; integration tests
//! include it with `#[path = "../src/real_shell_gate.rs"] mod real_shell_gate;`.

// The shell tests are Unix-only, so elsewhere nothing calls the gate.
#![cfg_attr(not(unix), allow(dead_code))]

use std::io::Write as _;

/// Set to `suite` by the shell-truth suite sandbox.
pub const MARKER: &str = "SHELL_TRUTH_SANDBOX";

/// Whether `test` may run text in a real shell. When it may not, prints the
/// skip and why, and the caller must skip every shell spawn.
#[must_use]
pub fn allowed(test: &str) -> bool {
    let marker = std::env::var_os(MARKER).is_some_and(|value| value == "suite");
    let sandboxed = kernel_sandboxed();
    if marker && sandboxed {
        return true;
    }
    // Not eprintln!: libtest captures that and drops it when the test passes.
    // A direct write to the stderr handle is not captured, so plain
    // `cargo test` shows the skip.
    let _ = writeln!(
        std::io::stderr(),
        "{test}: SKIPPED its real-shell part ({MARKER}=suite: {marker}, kernel sandbox: \
         {sandboxed}). Shell text runs only inside `scripts/shell-truth --suite` \
         (frapbod/infra docs/runbooks/shell-ground-truth.md)."
    );
    false
}

/// macOS: whether a sandbox profile is applied to this process.
#[cfg(target_os = "macos")]
fn kernel_sandboxed() -> bool {
    unsafe extern "C" {
        // libsystem_sandbox, part of libSystem. With no operation and filter
        // type SANDBOX_FILTER_NONE (0) it returns 1 when the process is
        // sandboxed and 0 when it is not.
        fn sandbox_check(
            pid: libc::pid_t,
            operation: *const libc::c_char,
            filter_type: libc::c_int,
            ...
        ) -> libc::c_int;
    }
    // SAFETY: a query about our own pid with a null operation; it reads no
    // memory of ours and passes no variadic arguments.
    unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) == 1 }
}

/// No kernel-verified sandbox route exists here, so shells never run.
#[cfg(not(target_os = "macos"))]
const fn kernel_sandboxed() -> bool {
    false
}
