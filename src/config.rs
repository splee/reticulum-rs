//! Configuration system for Reticulum
//!
//! This module provides configuration file parsing (INI format) and storage path
//! management for Reticulum, matching the Python implementation's behavior.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Log levels matching Python implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[derive(Default)]
pub enum LogLevel {
    /// Critical errors that cause shutdown
    Critical = 0,
    /// Errors that may affect operation
    Error = 1,
    /// Warnings about potential issues
    Warning = 2,
    /// Normal operational messages
    #[default]
    Notice = 3,
    /// Informational messages
    Info = 4,
    /// Verbose debugging information
    Verbose = 5,
    /// Detailed debugging information
    Debug = 6,
    /// Extremely detailed tracing
    Extreme = 7,
}


impl From<u8> for LogLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => LogLevel::Critical,
            1 => LogLevel::Error,
            2 => LogLevel::Warning,
            3 => LogLevel::Notice,
            4 => LogLevel::Info,
            5 => LogLevel::Verbose,
            6 => LogLevel::Debug,
            _ => LogLevel::Extreme,
        }
    }
}

/// Storage paths for Reticulum data
#[derive(Debug, Clone)]
pub struct StoragePaths {
    /// Base configuration directory (e.g., ~/.reticulum)
    pub config_dir: PathBuf,
    /// Path to the config file
    pub config_path: PathBuf,
    /// Path to storage directory
    pub storage_path: PathBuf,
    /// Path to cache directory
    pub cache_path: PathBuf,
    /// Path to resource transfers
    pub resource_path: PathBuf,
    /// Path to identity storage
    pub identity_path: PathBuf,
    /// Path to blackhole list
    pub blackhole_path: PathBuf,
    /// Path to interface plugins
    pub interface_path: PathBuf,
    /// Path to announce cache
    pub announce_cache_path: PathBuf,
}

impl StoragePaths {
    /// Create storage paths from a configuration directory
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        let config_dir = config_dir.as_ref().to_path_buf();
        let storage_path = config_dir.join("storage");
        let cache_path = storage_path.join("cache");

        Self {
            config_path: config_dir.join("config"),
            storage_path: storage_path.clone(),
            cache_path: cache_path.clone(),
            resource_path: storage_path.join("resources"),
            identity_path: storage_path.join("identities"),
            blackhole_path: storage_path.join("blackhole"),
            interface_path: config_dir.join("interfaces"),
            announce_cache_path: cache_path.join("announces"),
            config_dir,
        }
    }

    /// Get the default configuration directory based on platform
    pub fn default_config_dir() -> PathBuf {
        // Check for system-wide config first
        let system_config = PathBuf::from("/etc/reticulum");
        if system_config.join("config").exists() {
            return system_config;
        }

        // Check XDG config directory
        if let Some(home) = dirs::home_dir() {
            let xdg_config = home.join(".config/reticulum");
            if xdg_config.join("config").exists() {
                return xdg_config;
            }

            // Default to ~/.reticulum
            return home.join(".reticulum");
        }

        // Fallback
        PathBuf::from(".reticulum")
    }

    /// Ensure all required directories exist
    pub fn ensure_directories(&self) -> io::Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.storage_path)?;
        fs::create_dir_all(&self.cache_path)?;
        fs::create_dir_all(&self.resource_path)?;
        fs::create_dir_all(&self.identity_path)?;
        fs::create_dir_all(&self.blackhole_path)?;
        fs::create_dir_all(&self.interface_path)?;
        fs::create_dir_all(&self.announce_cache_path)?;
        Ok(())
    }
}

/// A section in an INI configuration file
#[derive(Debug, Clone, Default)]
pub struct ConfigSection {
    /// Key-value pairs in this section
    pub values: HashMap<String, String>,
    /// Subsections (for interface configurations)
    pub subsections: HashMap<String, ConfigSection>,
}

impl ConfigSection {
    /// Get a string value from the section
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    /// Get a boolean value from the section
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.values.get(key).and_then(|v| {
            let v = v.to_lowercase();
            match v.as_str() {
                "true" | "yes" | "1" | "on" => Some(true),
                "false" | "no" | "0" | "off" => Some(false),
                _ => None,
            }
        })
    }

    /// Get an integer value from the section
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }

    /// Get a float value from the section
    pub fn get_float(&self, key: &str) -> Option<f64> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }
}

/// Parsed configuration file
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Global values (outside any section)
    pub global: ConfigSection,
    /// Named sections
    pub sections: HashMap<String, ConfigSection>,
}

impl Config {
    /// Parse a configuration file from a path
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Parse configuration from a string
    pub fn parse(content: &str) -> Self {
        let mut config = Config::default();
        let mut current_section: Option<String> = None;
        let mut current_subsection: Option<String> = None;
        let mut indent_level = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Calculate indent level for subsection detection
            let line_indent = line.len() - line.trim_start().len();

            // Section header
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let section_name = &trimmed[1..trimmed.len() - 1];

                // Check if this is a subsection (indented section header)
                if line_indent > indent_level && current_section.is_some() {
                    // This is a subsection of the current section
                    current_subsection = Some(section_name.to_string());
                    if let Some(ref section) = current_section {
                        config
                            .sections
                            .entry(section.clone())
                            .or_default()
                            .subsections
                            .insert(section_name.to_string(), ConfigSection::default());
                    }
                } else {
                    // This is a top-level section
                    current_section = Some(section_name.to_string());
                    current_subsection = None;
                    indent_level = line_indent;
                    config
                        .sections
                        .entry(section_name.to_string())
                        .or_default();
                }
                continue;
            }

            // Key-value pair
            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_string();
                let value = trimmed[eq_pos + 1..].trim().to_string();

                if let Some(ref section) = current_section {
                    if let Some(ref subsection) = current_subsection {
                        // Add to subsection
                        if let Some(sec) = config.sections.get_mut(section) {
                            sec.subsections
                                .entry(subsection.clone())
                                .or_default()
                                .values
                                .insert(key, value);
                        }
                    } else {
                        // Add to section
                        config
                            .sections
                            .entry(section.clone())
                            .or_default()
                            .values
                            .insert(key, value);
                    }
                } else {
                    // Global value
                    config.global.values.insert(key, value);
                }
            }
        }

        config
    }

    /// Get a section by name
    pub fn section(&self, name: &str) -> Option<&ConfigSection> {
        self.sections.get(name)
    }

    /// Write the configuration to a file
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = fs::File::create(path)?;

        // Write global values
        for (key, value) in &self.global.values {
            writeln!(file, "{} = {}", key, value)?;
        }

        if !self.global.values.is_empty() {
            writeln!(file)?;
        }

        // Write sections
        for (section_name, section) in &self.sections {
            writeln!(file, "[{}]", section_name)?;

            for (key, value) in &section.values {
                writeln!(file, "  {} = {}", key, value)?;
            }

            // Write subsections
            for (subsection_name, subsection) in &section.subsections {
                writeln!(file)?;
                writeln!(file, "  [[{}]]", subsection_name)?;

                for (key, value) in &subsection.values {
                    writeln!(file, "    {} = {}", key, value)?;
                }
            }

            writeln!(file)?;
        }

        Ok(())
    }
}

/// Main Reticulum configuration
#[derive(Debug, Clone)]
pub struct ReticulumConfig {
    /// Storage paths
    pub paths: StoragePaths,
    /// Parsed configuration
    pub config: Config,
    /// Whether to enable transport mode
    pub enable_transport: bool,
    /// Whether to share instance with other programs
    pub share_instance: bool,
    /// Port for shared instance interface
    pub shared_instance_port: u16,
    /// Port for RPC control
    pub control_port: u16,
    /// Whether to use implicit proofs
    pub use_implicit_proof: bool,
    /// Whether to allow probes
    pub allow_probes: bool,
    /// Current log level
    pub log_level: LogLevel,
    /// Whether link MTU discovery is enabled
    pub link_mtu_discovery: bool,
    /// Whether panic on interface error
    pub panic_on_interface_error: bool,
}

impl ReticulumConfig {
    /// Load configuration from a directory
    pub fn load(config_dir: Option<PathBuf>) -> io::Result<Self> {
        let paths = match config_dir {
            Some(dir) => StoragePaths::new(dir),
            None => StoragePaths::new(StoragePaths::default_config_dir()),
        };

        // Ensure directories exist
        paths.ensure_directories()?;

        // Load or create config file
        let config = if paths.config_path.exists() {
            Config::from_file(&paths.config_path)?
        } else {
            // Create default config
            let config = Self::default_config();
            config.write_to_file(&paths.config_path)?;
            config
        };

        Ok(Self::from_parsed_config(paths, config))
    }

    /// Create configuration from parsed config
    fn from_parsed_config(paths: StoragePaths, config: Config) -> Self {
        let reticulum_section = config.section("reticulum");

        let enable_transport = reticulum_section
            .and_then(|s| s.get_bool("enable_transport"))
            .unwrap_or(false);

        let share_instance = reticulum_section
            .and_then(|s| s.get_bool("share_instance"))
            .unwrap_or(true);

        let shared_instance_port = reticulum_section
            .and_then(|s| s.get_int("shared_instance_port"))
            .unwrap_or(37428) as u16;

        let control_port = reticulum_section
            .and_then(|s| s.get_int("instance_control_port"))
            .unwrap_or(37429) as u16;

        let use_implicit_proof = reticulum_section
            .and_then(|s| s.get_bool("use_implicit_proof"))
            .unwrap_or(true);

        let allow_probes = reticulum_section
            .and_then(|s| s.get_bool("allow_probes"))
            .unwrap_or(false);

        let panic_on_interface_error = reticulum_section
            .and_then(|s| s.get_bool("panic_on_interface_error"))
            .unwrap_or(false);

        Self {
            paths,
            config,
            enable_transport,
            share_instance,
            shared_instance_port,
            control_port,
            use_implicit_proof,
            allow_probes,
            log_level: LogLevel::Notice,
            link_mtu_discovery: true,
            panic_on_interface_error,
        }
    }

    /// Generate a default configuration
    fn default_config() -> Config {
        let mut config = Config::default();

        // Reticulum section
        let mut reticulum = ConfigSection::default();
        reticulum
            .values
            .insert("enable_transport".to_string(), "false".to_string());
        reticulum
            .values
            .insert("share_instance".to_string(), "true".to_string());
        reticulum
            .values
            .insert("shared_instance_port".to_string(), "37428".to_string());
        reticulum
            .values
            .insert("instance_control_port".to_string(), "37429".to_string());
        reticulum
            .values
            .insert("panic_on_interface_error".to_string(), "false".to_string());

        config.sections.insert("reticulum".to_string(), reticulum);

        // Logging section
        let mut logging = ConfigSection::default();
        logging
            .values
            .insert("loglevel".to_string(), "4".to_string());

        config.sections.insert("logging".to_string(), logging);

        // Interfaces section (placeholder)
        config
            .sections
            .insert("interfaces".to_string(), ConfigSection::default());

        config
    }

    /// Get interface configurations from the config
    pub fn interface_configs(&self) -> Vec<InterfaceConfig> {
        let mut interfaces = Vec::new();

        if let Some(section) = self.config.section("interfaces") {
            for (name, subsection) in &section.subsections {
                interfaces.push(InterfaceConfig {
                    name: name.clone(),
                    interface_type: subsection
                        .get("type")
                        .unwrap_or("TCPClientInterface")
                        .to_string(),
                    enabled: subsection.get_bool("interface_enabled").unwrap_or(true),
                    target_host: subsection.get("target_host").map(|s| s.to_string()),
                    target_port: subsection.get_int("target_port").map(|p| p as u16),
                    listen_ip: subsection.get("listen_ip").map(|s| s.to_string()),
                    listen_port: subsection.get_int("listen_port").map(|p| p as u16),
                    outgoing: subsection.get_bool("outgoing").unwrap_or(true),
                    bitrate: subsection.get_int("bitrate").map(|b| b as u64),
                    extra: subsection.values.clone(),
                });
            }
        }

        interfaces
    }
}

/// Configuration for a single interface
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Interface name
    pub name: String,
    /// Interface type (e.g., "TCPClientInterface")
    pub interface_type: String,
    /// Whether the interface is enabled
    pub enabled: bool,
    /// Target host for client interfaces
    pub target_host: Option<String>,
    /// Target port for client interfaces
    pub target_port: Option<u16>,
    /// Listen IP for server interfaces
    pub listen_ip: Option<String>,
    /// Listen port for server interfaces
    pub listen_port: Option<u16>,
    /// Whether this interface is for outgoing connections
    pub outgoing: bool,
    /// Interface bitrate in bits per second
    pub bitrate: Option<u64>,
    /// Additional configuration values
    pub extra: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_config() {
        let content = r#"
# Reticulum Configuration

[reticulum]
  enable_transport = true
  share_instance = true
  shared_instance_port = 37428

[logging]
  loglevel = 4

[interfaces]
  [[TCP Interface]]
    type = TCPClientInterface
    target_host = example.com
    target_port = 4242
"#;

        let config = Config::parse(content);

        assert!(config.sections.contains_key("reticulum"));
        assert!(config.sections.contains_key("logging"));
        assert!(config.sections.contains_key("interfaces"));

        let reticulum = config.section("reticulum").unwrap();
        assert_eq!(reticulum.get_bool("enable_transport"), Some(true));
        assert_eq!(reticulum.get_int("shared_instance_port"), Some(37428));
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Critical < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Warning);
        assert!(LogLevel::Debug < LogLevel::Extreme);
    }

    #[test]
    fn test_storage_paths() {
        let paths = StoragePaths::new("/tmp/test_reticulum");
        assert_eq!(paths.config_dir, PathBuf::from("/tmp/test_reticulum"));
        assert_eq!(
            paths.config_path,
            PathBuf::from("/tmp/test_reticulum/config")
        );
        assert_eq!(
            paths.storage_path,
            PathBuf::from("/tmp/test_reticulum/storage")
        );
    }
}
