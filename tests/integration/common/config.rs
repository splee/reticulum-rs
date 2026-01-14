//! Configuration file generation for integration tests.
//!
//! Generates temporary Reticulum configuration directories for both
//! Python and Rust nodes during testing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::ports::allocate_ports;

/// A test configuration directory with Reticulum config.
///
/// Contains a temporary directory with a config file and tracks
/// the ports allocated for this configuration.
pub struct TestConfig {
    /// The temporary directory containing the config file.
    pub dir: TempDir,
    /// TCP server port (if configured as server).
    pub tcp_port: u16,
    /// Shared instance port.
    pub shared_port: u16,
    /// Instance control port.
    pub control_port: u16,
}

impl TestConfig {
    /// Get the path to the config directory.
    pub fn config_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Get the path to the config file.
    pub fn config_file(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    /// Create configuration for a Python hub node (TCP server).
    ///
    /// The hub acts as a central node that other nodes connect to.
    pub fn python_hub() -> io::Result<Self> {
        let ports = allocate_ports(3);
        let tcp_port = ports[0];
        let shared_port = ports[1];
        let control_port = ports[2];

        let dir = TempDir::new()?;
        let config_content = format!(
            r#"# Python Hub Configuration (generated for integration test)

[reticulum]
  enable_transport = Yes
  share_instance = No
  shared_instance_port = {shared_port}
  instance_control_port = {control_port}
  panic_on_interface_error = No

[logging]
  loglevel = 5

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = True
    listen_ip = 127.0.0.1
    listen_port = {tcp_port}
"#
        );

        fs::write(dir.path().join("config"), config_content)?;

        Ok(Self {
            dir,
            tcp_port,
            shared_port,
            control_port,
        })
    }

    /// Create configuration for a Rust node (TCP client connecting to hub).
    ///
    /// Connects to the specified hub port and optionally runs its own TCP server.
    pub fn rust_node(hub_port: u16, own_tcp_port: Option<u16>) -> io::Result<Self> {
        let ports = allocate_ports(2);
        let shared_port = ports[0];
        let control_port = ports[1];
        let tcp_port = own_tcp_port.unwrap_or_else(|| allocate_ports(1)[0]);

        let dir = TempDir::new()?;

        let tcp_server_section = if own_tcp_port.is_some() {
            format!(
                r#"
  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = True
    listen_ip = 127.0.0.1
    listen_port = {tcp_port}
"#
            )
        } else {
            String::new()
        };

        let config_content = format!(
            r#"# Rust Node Configuration (generated for integration test)

[reticulum]
  enable_transport = Yes
  share_instance = No
  shared_instance_port = {shared_port}
  instance_control_port = {control_port}
  panic_on_interface_error = No

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = True
    target_host = 127.0.0.1
    target_port = {hub_port}
{tcp_server_section}"#
        );

        fs::write(dir.path().join("config"), config_content)?;

        Ok(Self {
            dir,
            tcp_port,
            shared_port,
            control_port,
        })
    }

    /// Create a minimal configuration with no interfaces.
    ///
    /// Useful for testing CLI tools that don't need network connectivity.
    pub fn minimal() -> io::Result<Self> {
        let ports = allocate_ports(3);
        let tcp_port = ports[0];
        let shared_port = ports[1];
        let control_port = ports[2];

        let dir = TempDir::new()?;
        let config_content = format!(
            r#"# Minimal Configuration (generated for integration test)

[reticulum]
  enable_transport = No
  share_instance = No
  shared_instance_port = {shared_port}
  instance_control_port = {control_port}
  panic_on_interface_error = No

[logging]
  loglevel = 5

[interfaces]
  # No interfaces configured
"#
        );

        fs::write(dir.path().join("config"), config_content)?;

        Ok(Self {
            dir,
            tcp_port,
            shared_port,
            control_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_hub_config_created() {
        let config = TestConfig::python_hub().unwrap();
        assert!(config.config_file().exists());

        let content = fs::read_to_string(config.config_file()).unwrap();
        assert!(content.contains("TCPServerInterface"));
        assert!(content.contains(&format!("listen_port = {}", config.tcp_port)));
    }

    #[test]
    fn test_rust_node_config_connects_to_hub() {
        let hub = TestConfig::python_hub().unwrap();
        let node = TestConfig::rust_node(hub.tcp_port, None).unwrap();

        let content = fs::read_to_string(node.config_file()).unwrap();
        assert!(content.contains("TCPClientInterface"));
        assert!(content.contains(&format!("target_port = {}", hub.tcp_port)));
    }
}
