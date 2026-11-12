//! Opcode and bytecode wire-format contract (version 1).
//!
//! # File layout (`RUSO` + version byte)
//!
//! 1. Metadata (name, description, impact, severity, author, report title)
//! 2. Probe table (HTTP / DNS / TCP specs)
//! 3. String pool
//! 4. Matcher pool (`QualifiedMatch`)
//! 5. Extract pool (`ExtractSource`)
//! 6. Evidence pool (`EvidenceKind`)
//! 7. Payload pool (raw bytes for `Send` overrides)
//! 8. Instruction stream (`Opcode` discriminants)
//!
//! # Instruction opcodes (wire `u8`)
//!
//! | Byte | Variant     | Payload                          |
//! |------|-------------|----------------------------------|
//! | 1    | Set         | `name_id: u32`, `value_id: u32`  |
//! | 2    | Send        | `probe_id: u32`, optional payload index |
//! | 3    | Match       | `matcher_id: u32`                |
//! | 4    | MatchAll    | `start: u32`, `len: u16`         |
//! | 5    | MatchAny    | `start: u32`, `len: u16`         |
//! | 6    | Assert      | `matcher_id: u32`                |
//! | 7    | Extract     | `name_id: u32`, `source_id: u32` |
//! | 8    | IfMatch     | `matcher_id: u32`, `else_pc: u32`|
//! | 9    | Save        | `from_id: u32`, `to_id: u32`     |
//! | 10   | Evidence    | `kind_id: u32`                   |
//! | 11   | Retry       | `probe_id: u32`, `count: u32`    |
//! | 12   | RetryDelay  | `duration_id: u32`               |
//! | 13   | Sleep       | `duration_id: u32`               |
//! | 14   | Stop        | —                                |
//! | 15   | Fail        | —                                |
//! | 16   | Continue    | —                                |
//! | 17   | Exit        | —                                |
//! | 18   | (reserved)  | was `Repeat`, removed            |
//! | 19   | LoopBack    | —                                |
//! | 20   | Break       | —                                |
//! | 21   | SetList     | `name_id: u32`, `start: u32`, `len: u16` |
//! | 22   | ForList     | `item_id: u32`, `start: u32`, `len: u16`, `end_pc: u32` |
//! | 23   | ForVar      | `item_id: u32`, `list_id: u32`, `end_pc: u32` |
//!
//! Compilers must emit [`crate::BytecodeProgram`] compatible with [`crate::VERSION`].

pub use crate::runtime::binary::{MAGIC, VERSION};
pub use crate::runtime::bytecode::{BytecodeProgram, Instr as Opcode, Pc};

/// Bind a variable: `name_id: u32`, `value_id: u32` (both string-pool indices).
pub const OP_SET: u8 = 1;
/// Fire a probe: `probe_id: u32`, plus an optional payload-pool index that
/// overrides the probe's own body.
pub const OP_SEND: u8 = 2;
/// Evaluate one matcher and record the outcome: `matcher_id: u32`.
pub const OP_MATCH: u8 = 3;
/// Evaluate a contiguous run of matchers; holds only if *all* of them do.
/// Payload is `start: u32`, `len: u16`.
pub const OP_MATCH_ALL: u8 = 4;
/// Evaluate a contiguous run of matchers; holds if *any* of them does.
/// Payload is `start: u32`, `len: u16`.
pub const OP_MATCH_ANY: u8 = 5;
/// Evaluate a matcher and abort the script when it fails: `matcher_id: u32`.
pub const OP_ASSERT: u8 = 6;
/// Pull a value out of the last response into a variable:
/// `name_id: u32`, `source_id: u32` (an extract-pool index).
pub const OP_EXTRACT: u8 = 7;
/// Branch on a matcher: run the following block when it holds, otherwise jump
/// to `else_pc`. Payload is `matcher_id: u32`, `else_pc: u32`.
pub const OP_IF_MATCH: u8 = 8;
/// Copy one variable into another: `from_id: u32`, `to_id: u32`.
pub const OP_SAVE: u8 = 9;
/// Attach proof to the finding this script emits: `kind_id: u32`, an
/// evidence-pool index naming the source (body, whole response, or a header).
pub const OP_EVIDENCE: u8 = 10;
/// Re-send a probe up to `count` times while it keeps failing:
/// `probe_id: u32`, `count: u32`.
pub const OP_RETRY: u8 = 11;
/// Set the delay inserted between [`OP_RETRY`] attempts: `duration_id: u32`
/// (a string-pool duration literal).
pub const OP_RETRY_DELAY: u8 = 12;
/// Pause execution: `duration_id: u32`.
pub const OP_SLEEP: u8 = 13;
/// Halt the script and report whatever has matched so far.
pub const OP_STOP: u8 = 14;
/// Halt the script and mark the run as failed.
pub const OP_FAIL: u8 = 15;
/// Skip the rest of the current loop iteration and start the next one.
pub const OP_CONTINUE: u8 = 16;
/// Halt the script immediately without emitting a finding.
pub const OP_EXIT: u8 = 17;
// 18 reserved: was `Repeat`, removed from the language and VM.
/// Jump back to the top of the enclosing loop.
pub const OP_LOOP_BACK: u8 = 19;
/// Leave the enclosing loop.
pub const OP_BREAK: u8 = 20;
/// Bind a list variable from a contiguous run of string-pool entries:
/// `name_id: u32`, `start: u32`, `len: u16`.
pub const OP_SET_LIST: u8 = 21;
/// Loop over a literal list: `item_id: u32` (the loop variable),
/// `start: u32`, `len: u16` (the elements), `end_pc: u32` (where to resume).
pub const OP_FOR_LIST: u8 = 22;
/// Loop over a list held in a variable: `item_id: u32` (the loop variable),
/// `list_id: u32` (the list variable), `end_pc: u32` (where to resume).
pub const OP_FOR_VAR: u8 = 23;
