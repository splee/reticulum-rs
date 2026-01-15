//! Process management utilities for integration tests.
//!
//! Provides managed process spawning with output capture, timeout handling,
//! and automatic cleanup on drop.
//!
//! All spawned processes are registered in a global registry and will be
//! killed when the test process exits (via atexit handler).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lazy_static::lazy_static;

lazy_static! {
    /// Global registry of all spawned process PIDs for cleanup.
    /// This ensures processes are killed even if tests panic or exit unexpectedly.
    static ref PROCESS_REGISTRY: Mutex<Vec<u32>> = Mutex::new(Vec::new());
}

/// One-time registration of the atexit cleanup handler.
static CLEANUP_REGISTERED: Once = Once::new();

/// Register a process PID for cleanup on exit.
pub fn register_pid(pid: u32) {
    // Ensure cleanup handler is registered
    ensure_cleanup_registered();

    if let Ok(mut registry) = PROCESS_REGISTRY.lock() {
        registry.push(pid);
    }
}

/// Unregister a PID (called when process exits normally or is killed).
pub fn unregister_pid(pid: u32) {
    if let Ok(mut registry) = PROCESS_REGISTRY.lock() {
        registry.retain(|&p| p != pid);
    }
}

/// Kill all registered processes.
/// Called automatically on process exit via atexit handler.
pub fn kill_all_registered() {
    if let Ok(mut registry) = PROCESS_REGISTRY.lock() {
        for pid in registry.drain(..) {
            #[cfg(unix)]
            {
                // Send SIGKILL to ensure process dies
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
            #[cfg(not(unix))]
            {
                // On non-Unix, we can't do much here without the Child handle
                let _ = pid;
            }
        }
    }
}

/// Ensure the atexit cleanup handler is registered.
/// This is called automatically when the first process is registered.
pub fn ensure_cleanup_registered() {
    CLEANUP_REGISTERED.call_once(|| {
        #[cfg(unix)]
        {
            extern "C" fn cleanup() {
                // Note: We can't use the full kill_all_registered here because
                // lazy_static may have been cleaned up. Do minimal cleanup.
                if let Ok(registry) = PROCESS_REGISTRY.lock() {
                    for &pid in registry.iter() {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                    }
                }
            }
            unsafe {
                libc::atexit(cleanup);
            }
        }
    });
}

/// Error type for process operations.
#[derive(Debug)]
pub struct ProcessError(pub String);

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProcessError: {}", self.0)
    }
}

impl std::error::Error for ProcessError {}

impl From<std::io::Error> for ProcessError {
    fn from(err: std::io::Error) -> Self {
        ProcessError(err.to_string())
    }
}

/// A managed background process with output capture.
///
/// Output from stdout and stderr is captured in a buffer that can be
/// queried for specific patterns. The process is automatically killed
/// when dropped.
pub struct ManagedProcess {
    /// The child process.
    child: Option<Child>,
    /// Shared buffer for captured output.
    output_buffer: Arc<Mutex<String>>,
    /// Handle to the reader thread.
    reader_handle: Option<JoinHandle<()>>,
    /// Name for logging.
    name: String,
    /// Whether the process has been killed.
    killed: bool,
}

impl ManagedProcess {
    /// Spawn a new process with output capture.
    ///
    /// The command's stdout and stderr will be merged and captured
    /// in a buffer for later inspection. The process is automatically
    /// registered in the global registry for cleanup on exit.
    pub fn spawn(name: &str, cmd: &mut Command) -> Result<Self, ProcessError> {
        // Configure command to capture output
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Register PID for cleanup on exit
        register_pid(child.id());

        // Take ownership of stdout and stderr
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let output_buffer = Arc::new(Mutex::new(String::new()));
        let buffer_clone = Arc::clone(&output_buffer);
        let name_clone = name.to_string();

        // Spawn a thread to read output continuously
        let reader_handle = thread::spawn(move || {
            Self::read_output(stdout, stderr, buffer_clone, &name_clone);
        });

        Ok(Self {
            child: Some(child),
            output_buffer,
            reader_handle: Some(reader_handle),
            name: name.to_string(),
            killed: false,
        })
    }

    /// Read from stdout and stderr, merging into the shared buffer.
    fn read_output(
        stdout: Option<std::process::ChildStdout>,
        stderr: Option<std::process::ChildStderr>,
        buffer: Arc<Mutex<String>>,
        _name: &str,
    ) {
        // Read stdout in a separate thread
        let buffer_stdout = Arc::clone(&buffer);
        let stdout_handle = stdout.map(|stdout| {
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        let mut buf = buffer_stdout.lock().unwrap();
                        buf.push_str(&line);
                        buf.push('\n');
                    }
                }
            })
        });

        // Read stderr in current thread
        if let Some(stderr) = stderr {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let mut buf = buffer.lock().unwrap();
                    buf.push_str(&line);
                    buf.push('\n');
                }
            }
        }

        // Wait for stdout reader to finish
        if let Some(handle) = stdout_handle {
            let _ = handle.join();
        }
    }

    /// Wait for a specific pattern to appear in the output.
    ///
    /// Returns the full line containing the pattern, or an error if
    /// the timeout expires before the pattern is found.
    pub fn wait_for_output(&self, pattern: &str, timeout: Duration) -> Result<String, ProcessError> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        while start.elapsed() < timeout {
            {
                let output = self.output_buffer.lock().unwrap();
                for line in output.lines() {
                    if line.contains(pattern) {
                        return Ok(line.to_string());
                    }
                }
            }
            thread::sleep(poll_interval);
        }

        // Timeout - include current output in error message
        let output = self.output_buffer.lock().unwrap();
        Err(ProcessError(format!(
            "Timeout waiting for pattern '{}' after {:?}. Current output:\n{}",
            pattern,
            timeout,
            output.chars().take(2000).collect::<String>()
        )))
    }

    /// Wait for the process to exit with a timeout.
    pub fn wait_with_timeout(&mut self, timeout: Duration) -> Result<ExitStatus, ProcessError> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        while start.elapsed() < timeout {
            if let Some(ref mut child) = self.child {
                match child.try_wait()? {
                    Some(status) => return Ok(status),
                    None => thread::sleep(poll_interval),
                }
            } else {
                return Err(ProcessError("Process already consumed".to_string()));
            }
        }

        Err(ProcessError(format!(
            "Timeout waiting for process '{}' to exit after {:?}",
            self.name, timeout
        )))
    }

    /// Get all captured output so far.
    pub fn output(&self) -> String {
        self.output_buffer.lock().unwrap().clone()
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Get the process ID.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Kill the process gracefully (SIGTERM on Unix, terminate on Windows).
    ///
    /// If the process doesn't exit within the timeout, it will be forcefully killed.
    /// The process is automatically unregistered from the global cleanup registry.
    pub fn kill(&mut self) {
        if self.killed {
            return;
        }
        self.killed = true;

        if let Some(ref mut child) = self.child {
            // Unregister from global cleanup since we're handling it here
            unregister_pid(child.id());

            // Try graceful shutdown first
            #[cfg(unix)]
            {
                // Send SIGTERM for graceful shutdown
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGTERM);
                }
            }

            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }

            // Wait briefly for graceful shutdown
            let start = Instant::now();
            let grace_period = Duration::from_secs(2);

            while start.elapsed() < grace_period {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        // Process exited
                        break;
                    }
                    Ok(None) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }

            // Force kill if still running
            if let Ok(None) = child.try_wait() {
                eprintln!(
                    "[integration-test] Force killing process '{}' (pid: {})",
                    self.name,
                    child.id()
                );
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Wait for reader thread to finish
        if let Some(handle) = self.reader_handle.take() {
            // Give the reader thread a moment to finish
            thread::sleep(Duration::from_millis(100));
            // Don't block indefinitely - the reader will stop when the pipes close
            let _ = handle.join();
        }
    }

    /// Take ownership of the child process.
    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// A collection of managed processes that are cleaned up together.
pub struct ProcessGroup {
    processes: Vec<ManagedProcess>,
}

impl ProcessGroup {
    /// Create a new empty process group.
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
        }
    }

    /// Add a process to the group.
    pub fn add(&mut self, process: ManagedProcess) {
        self.processes.push(process);
    }

    /// Kill all processes in the group.
    pub fn kill_all(&mut self) {
        for process in &mut self.processes {
            process.kill();
        }
    }

    /// Get the number of processes in the group.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if the group is empty.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

impl Default for ProcessGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Run a command and capture its output (blocking).
///
/// Useful for short-lived commands where you just want the final output.
/// The process is registered for cleanup while running.
pub fn run_command(cmd: &mut Command, _timeout: Duration) -> Result<String, ProcessError> {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn()?;
    let pid = child.id();

    // Register for cleanup in case we're interrupted
    register_pid(pid);

    let output = child.wait_with_output()?;

    // Unregister since process has exited
    unregister_pid(pid);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProcessError(format!(
            "Command failed with status {}: {}",
            output.status, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

/// Spawn a raw command and register it for cleanup.
///
/// This is a lower-level function for cases where you need direct access
/// to the Child process. The PID is registered for cleanup on exit.
///
/// Returns the spawned Child and its PID.
pub fn spawn_tracked(cmd: &mut Command) -> Result<(Child, u32), ProcessError> {
    let child = cmd.spawn()?;
    let pid = child.id();
    register_pid(pid);
    Ok((child, pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_and_capture_output() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello world");

        let process = ManagedProcess::spawn("test-echo", &mut cmd).unwrap();

        // Wait for process to finish
        thread::sleep(Duration::from_millis(200));

        let output = process.output();
        assert!(output.contains("hello world"));
    }

    #[test]
    fn test_wait_for_pattern() {
        let mut cmd = Command::new("echo");
        cmd.arg("DESTINATION_HASH=abc123");

        let process = ManagedProcess::spawn("test-pattern", &mut cmd).unwrap();

        let line = process
            .wait_for_output("DESTINATION_HASH=", Duration::from_secs(2))
            .unwrap();

        assert!(line.contains("abc123"));
    }

    #[test]
    fn test_process_group_cleanup() {
        let mut group = ProcessGroup::new();

        let mut cmd1 = Command::new("sleep");
        cmd1.arg("10");
        let p1 = ManagedProcess::spawn("sleep1", &mut cmd1).unwrap();

        let mut cmd2 = Command::new("sleep");
        cmd2.arg("10");
        let p2 = ManagedProcess::spawn("sleep2", &mut cmd2).unwrap();

        group.add(p1);
        group.add(p2);

        assert_eq!(group.len(), 2);

        // Dropping group should kill both processes
        drop(group);
    }
}
