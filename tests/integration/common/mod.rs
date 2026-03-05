//! Common utilities for integration tests.
//!
//! This module provides the infrastructure for running integration tests
//! that verify Python-Rust interoperability.

pub mod config;
pub mod output;
pub mod ports;
pub mod process;
pub mod venv;

pub use config::TestConfig;
pub use output::TestOutput;
pub use ports::{allocate_port, allocate_ports};
pub use process::{
    cleanup_stale_processes, register_pid, spawn_tracked, unregister_pid, ChildGuard,
    ManagedProcess, ProcessError, ProcessGroup,
};
pub use venv::{PythonVenv, VenvError};

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Ensures stale process cleanup runs once per test process.
static STALE_CLEANUP: OnceLock<()> = OnceLock::new();

/// Poll until a TCP port on 127.0.0.1 accepts connections, or timeout.
///
/// Used to wait for a daemon's TCP listener to become ready instead of
/// relying on blind `thread::sleep()` which is unreliable under CPU contention
/// from parallel test execution.
fn wait_for_tcp_port(port: u16, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let addr = format!("127.0.0.1:{}", port);
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "port {} did not become ready within {:?}",
        port, timeout
    ))
}

/// Error type for integration test operations.
#[derive(Debug)]
pub struct TestError(pub String);

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestError: {}", self.0)
    }
}

impl std::error::Error for TestError {}

impl From<VenvError> for TestError {
    fn from(err: VenvError) -> Self {
        TestError(err.0)
    }
}

impl From<ProcessError> for TestError {
    fn from(err: ProcessError) -> Self {
        TestError(err.0)
    }
}

impl From<std::io::Error> for TestError {
    fn from(err: std::io::Error) -> Self {
        TestError(err.to_string())
    }
}

/// A running Python hub node.
pub struct PythonHub {
    /// The managed rnsd process.
    pub process: ManagedProcess,
    /// The TCP port the hub is listening on.
    pub port: u16,
    /// The configuration for this hub.
    pub config: TestConfig,
}

impl PythonHub {
    /// Get the TCP port the hub is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the configuration directory path.
    pub fn config_dir(&self) -> &std::path::Path {
        self.config.config_dir()
    }
}

/// A running Rust node.
pub struct RustNode {
    /// The managed rnsd process.
    pub process: ManagedProcess,
    /// The TCP port (if running a server).
    pub port: u16,
    /// The configuration for this node.
    pub config: TestConfig,
}

impl RustNode {
    /// Get the TCP port the node is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Context for an integration test.
///
/// Manages Python venv, configurations, and running processes.
/// All resources are cleaned up when the context is dropped.
pub struct IntegrationTestContext {
    /// The Python virtual environment.
    venv: &'static PythonVenv,
    /// Running processes (will be killed on drop).
    #[allow(dead_code)]
    processes: ProcessGroup,
    /// Active configurations (temp dirs cleaned up on drop).
    #[allow(dead_code)]
    configs: Vec<TestConfig>,
}

impl IntegrationTestContext {
    /// Create a new test context.
    ///
    /// This will initialize the Python venv if it doesn't exist.
    /// On first call per process, cleans up any stale test processes from
    /// previous runs.
    pub fn new() -> Result<Self, TestError> {
        // Clean up stale processes from previous test runs (once per process)
        STALE_CLEANUP.get_or_init(|| {
            cleanup_stale_processes();
        });

        let venv = PythonVenv::get_or_create()?;

        Ok(Self {
            venv,
            processes: ProcessGroup::new(),
            configs: Vec::new(),
        })
    }

    /// Start a Python hub daemon.
    ///
    /// The hub runs rnsd with a TCP server interface that other nodes
    /// can connect to.
    pub fn start_python_hub(&mut self) -> Result<PythonHub, TestError> {
        let config = TestConfig::python_hub()?;
        let port = config.tcp_port;

        let mut cmd = self.venv.rnsd();
        cmd.args(["-v", "--config", config.config_dir().to_str().unwrap()]);

        let process = ManagedProcess::spawn("python-hub", &mut cmd)?;

        // Wait for the hub's TCP port to accept connections.
        // A blind sleep is unreliable under parallel execution / CPU contention.
        wait_for_tcp_port(port, Duration::from_secs(15))
            .map_err(|e| TestError(format!("Python hub failed to start: {}", e)))?;

        Ok(PythonHub {
            process,
            port,
            config,
        })
    }

    /// Start a Rust node connected to a hub.
    pub fn start_rust_node(&mut self, hub_port: u16) -> Result<RustNode, TestError> {
        let config = TestConfig::rust_node(hub_port, None)?;
        let port = config.tcp_port;

        let mut cmd = Command::new(self.rust_binary("rnsd"));
        cmd.args(["-v", "--config", config.config_dir().to_str().unwrap()]);

        let process = ManagedProcess::spawn("rust-node", &mut cmd)?;

        // Wait for the node's TCP port to accept connections (if it has a server).
        // Fall back to a sleep if there's no own TCP port to probe.
        std::thread::sleep(Duration::from_secs(2));

        Ok(RustNode {
            process,
            port,
            config,
        })
    }

    /// Run a Python helper script.
    ///
    /// Returns a managed process that can be queried for output.
    pub fn run_python_helper(
        &self,
        script_name: &str,
        args: &[&str],
    ) -> Result<ManagedProcess, TestError> {
        let mut cmd = self.venv.run_helper(script_name)?;
        cmd.args(args);

        let process = ManagedProcess::spawn(script_name, &mut cmd)?;
        Ok(process)
    }

    /// Run a Python helper script with a specific config directory.
    pub fn run_python_helper_with_config(
        &self,
        script_name: &str,
        config: &TestConfig,
        args: &[&str],
    ) -> Result<ManagedProcess, TestError> {
        let mut cmd = self.venv.run_helper(script_name)?;
        cmd.env("RNS_CONFIG_DIR", config.config_dir());
        cmd.args(args);

        let process = ManagedProcess::spawn(script_name, &mut cmd)?;
        Ok(process)
    }

    /// Get the path to a Rust test binary.
    pub fn rust_binary(&self, name: &str) -> PathBuf {
        // Try CARGO_BIN_EXE first (set by cargo test)
        if let Ok(path) = std::env::var(format!("CARGO_BIN_EXE_{}", name)) {
            return PathBuf::from(path);
        }

        // Fall back to target directory
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("target");
        path.push("debug");
        path.push(name);
        path
    }

    /// Run a Rust test binary.
    pub fn run_rust_binary(&self, name: &str, args: &[&str]) -> Result<ManagedProcess, TestError> {
        let binary = self.rust_binary(name);
        let mut cmd = Command::new(&binary);
        cmd.args(args);

        let process = ManagedProcess::spawn(name, &mut cmd)?;
        Ok(process)
    }

    /// Run a Rust test binary with a specific config directory.
    pub fn run_rust_binary_with_config(
        &self,
        name: &str,
        config: &TestConfig,
        args: &[&str],
    ) -> Result<ManagedProcess, TestError> {
        let binary = self.rust_binary(name);
        let mut cmd = Command::new(&binary);
        cmd.env("RNS_CONFIG_DIR", config.config_dir());
        cmd.args(args);

        let process = ManagedProcess::spawn(name, &mut cmd)?;
        Ok(process)
    }

    /// Get a reference to the Python venv.
    pub fn venv(&self) -> &PythonVenv {
        self.venv
    }

    /// Get the path to the helpers directory.
    pub fn helpers_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("integration");
        path.push("helpers");
        path
    }

    /// Get the path to the integration test directory.
    pub fn integration_test_dir(&self) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("integration");
        path
    }

    /// Create a Python hub configuration without starting it.
    pub fn create_python_hub_config(&mut self) -> Result<TestConfig, TestError> {
        let config = TestConfig::python_hub()?;
        self.configs.push(TestConfig::minimal()?); // Track for cleanup
        Ok(config)
    }

    /// Create a Rust node configuration without starting it.
    pub fn create_rust_node_config(&mut self, hub_port: u16) -> Result<TestConfig, TestError> {
        let config = TestConfig::rust_node(hub_port, None)?;
        Ok(config)
    }

    /// Spawn a command as a tracked ManagedProcess.
    ///
    /// Use this instead of `std::process::Command::new().spawn()` to ensure
    /// the process is registered for cleanup on test exit.
    pub fn spawn_managed(&self, name: &str, cmd: &mut Command) -> Result<ManagedProcess, TestError> {
        let process = ManagedProcess::spawn(name, cmd)?;
        Ok(process)
    }

    /// Spawn a raw command and register it for cleanup.
    ///
    /// Returns a `ChildGuard` that will automatically kill the process and
    /// unregister its PID on drop. This is panic-safe — the process will be
    /// cleaned up even if the test panics.
    pub fn spawn_child(
        &self,
        cmd: &mut Command,
    ) -> Result<ChildGuard, TestError> {
        let guard = spawn_tracked(cmd)?;
        Ok(guard)
    }

    /// Run a command to completion and return its output.
    ///
    /// The process is registered for cleanup while running.
    /// Note: This configures stdout/stderr as piped to capture output.
    pub fn run_to_completion(&self, cmd: &mut Command) -> Result<std::process::Output, TestError> {
        // Configure pipes to capture output (required for wait_with_output)
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut guard = spawn_tracked(cmd)?;
        // Take ownership of the child for wait_with_output (consumes Child).
        // The guard's drop will still unregister the PID.
        let child = guard.take_child().expect("child already consumed");
        let output = child.wait_with_output()?;
        Ok(output)
    }
}

impl Default for IntegrationTestContext {
    fn default() -> Self {
        Self::new().expect("Failed to create integration test context")
    }
}

/// Assert that a condition is true, with a custom error message including output.
#[macro_export]
macro_rules! assert_test {
    ($cond:expr, $msg:expr, $output:expr) => {
        if !$cond {
            panic!(
                "Assertion failed: {}\nOutput:\n{}",
                $msg,
                $output.chars().take(2000).collect::<String>()
            );
        }
    };
}

/// Assert that output contains a specific field.
#[macro_export]
macro_rules! assert_has_field {
    ($output:expr, $field:expr) => {
        let parsed = $crate::common::TestOutput::parse(&$output);
        if !parsed.has($field) {
            panic!(
                "Expected field '{}' not found in output:\n{}",
                $field,
                $output.chars().take(2000).collect::<String>()
            );
        }
    };
}

/// Assert that output has a specific field with a specific value.
#[macro_export]
macro_rules! assert_field_eq {
    ($output:expr, $field:expr, $expected:expr) => {
        let parsed = $crate::common::TestOutput::parse(&$output);
        match parsed.get($field) {
            Some(value) if value == $expected => {}
            Some(value) => panic!(
                "Field '{}' has value '{}', expected '{}'",
                $field, value, $expected
            ),
            None => panic!(
                "Expected field '{}' not found in output:\n{}",
                $field,
                $output.chars().take(2000).collect::<String>()
            ),
        }
    };
}
