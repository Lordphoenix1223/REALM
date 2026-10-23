//! Private terminal capability reserved for a future same-run evidence join.
//!
//! The type intentionally has no constructor, serialization, deserialization,
//! clone, or public re-export. Nothing in this lane can mint it. The Kepler
//! generation lane may eventually consume it after one host-owned join binds:
//! run/execution identity, measured launch, closed custody and descendants,
//! V2 semantic result, immutable freeze epoch, and generation-parent CAS.
//!
//! A caller-supplied result, claim, guest reply, root, or journal state is not
//! a substitute for this capability.
//!
//! ```compile_fail
//! use realm_v6::terminal_authority::TerminalAuthorization;
//! let _forged = TerminalAuthorization(());
//! ```

#[allow(dead_code)]
pub(crate) struct TerminalAuthorization(());
