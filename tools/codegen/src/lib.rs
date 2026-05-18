//! codegen library — exposed so other workspace crates (rscaller-runner)
//! can drive the same code generation pipeline used by the `codegen` binary.

pub mod codegen;
pub mod syscall_table;
pub mod tracefs;
pub mod version;
