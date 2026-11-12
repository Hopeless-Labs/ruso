//! The front end: grammar, parser, and the AST they produce.

pub mod ast;
mod grammar;
pub mod parser;

#[cfg(test)]
mod syntax_tests;

pub use ast::Program;
pub use parser::{ParseError, parse};
