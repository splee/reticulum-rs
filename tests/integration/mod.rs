//! Integration tests for Python-Rust Reticulum interoperability.
//!
//! These tests verify that the Rust implementation can communicate with
//! the Python reference implementation. Tests spawn actual processes
//! using the Python RNS package from PyPI.
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration
//!
//! # Run a specific test
//! cargo test --test integration test_python_hub_starts
//!
//! # Run with verbose output
//! cargo test --test integration -- --nocapture
//! ```
//!
//! ## First Run
//!
//! On first run, the tests will create a Python virtual environment at
//! `tests/integration/.venv` and install the required dependencies.
//! This may take a minute or two.

pub mod common;
mod tests;

// Re-export commonly used items for convenience
pub use common::{
    IntegrationTestContext, ManagedProcess, ProcessError, PythonHub, PythonVenv, RustNode,
    TestConfig, TestError, TestOutput, VenvError,
};
