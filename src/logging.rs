//! Logging system for Reticulum
//!
//! This module provides a logging system that matches the Python implementation's
//! log levels and destinations, integrating with Rust's log crate.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::LogLevel;

/// Log destination types
#[derive(Clone)]
pub enum LogDestination {
    /// Log to stdout
    Stdout,
    /// Log to a file
    File(std::path::PathBuf),
    /// Log via callback
    Callback(Arc<dyn Fn(&str) + Send + Sync>),
    /// No logging
    None,
}

impl std::fmt::Debug for LogDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogDestination::Stdout => write!(f, "Stdout"),
            LogDestination::File(path) => write!(f, "File({:?})", path),
            LogDestination::Callback(_) => write!(f, "Callback(...)"),
            LogDestination::None => write!(f, "None"),
        }
    }
}

impl Default for LogDestination {
    fn default() -> Self {
        LogDestination::Stdout
    }
}

/// Global logger state
struct LoggerState {
    level: LogLevel,
    destination: LogDestination,
    file_handle: Option<File>,
}

impl Default for LoggerState {
    fn default() -> Self {
        Self {
            level: LogLevel::Notice,
            destination: LogDestination::Stdout,
            file_handle: None,
        }
    }
}

lazy_static::lazy_static! {
    static ref LOGGER: RwLock<LoggerState> = RwLock::new(LoggerState::default());
}

/// Initialize the logging system
pub fn init(level: LogLevel, destination: LogDestination) -> io::Result<()> {
    let mut logger = LOGGER.write().map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "Failed to acquire logger lock")
    })?;

    logger.level = level;
    logger.destination = destination.clone();

    // Open file if needed
    if let LogDestination::File(ref path) = destination {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        logger.file_handle = Some(file);
    } else {
        logger.file_handle = None;
    }

    Ok(())
}

/// Set the current log level
pub fn set_level(level: LogLevel) {
    if let Ok(mut logger) = LOGGER.write() {
        logger.level = level;
    }
}

/// Get the current log level
pub fn get_level() -> LogLevel {
    LOGGER.read().map(|l| l.level).unwrap_or(LogLevel::Notice)
}

/// Format a log message with timestamp and level
fn format_message(level: LogLevel, message: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let seconds = secs % 60;
    let millis = now.subsec_millis();

    let level_str = match level {
        LogLevel::Critical => "CRITICAL",
        LogLevel::Error => "ERROR",
        LogLevel::Warning => "WARNING",
        LogLevel::Notice => "NOTICE",
        LogLevel::Info => "INFO",
        LogLevel::Verbose => "VERBOSE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Extreme => "EXTREME",
    };

    format!(
        "[{:02}:{:02}:{:02}.{:03}] [{}] {}",
        hours, mins, seconds, millis, level_str, message
    )
}

/// Log a message at the specified level
pub fn log(level: LogLevel, message: &str) {
    let logger = match LOGGER.read() {
        Ok(l) => l,
        Err(_) => return,
    };

    // Check if this message should be logged
    if level > logger.level {
        return;
    }

    let formatted = format_message(level, message);

    match &logger.destination {
        LogDestination::Stdout => {
            println!("{}", formatted);
        }
        LogDestination::File(_) => {
            // Need to drop read lock and acquire write lock for file
            drop(logger);
            if let Ok(mut logger) = LOGGER.write() {
                if let Some(ref mut file) = logger.file_handle {
                    let _ = writeln!(file, "{}", formatted);
                    let _ = file.flush();
                }
            }
        }
        LogDestination::Callback(cb) => {
            cb(&formatted);
        }
        LogDestination::None => {}
    }
}

/// Log at Critical level
pub fn critical(message: &str) {
    log(LogLevel::Critical, message);
}

/// Log at Error level
pub fn error(message: &str) {
    log(LogLevel::Error, message);
}

/// Log at Warning level
pub fn warning(message: &str) {
    log(LogLevel::Warning, message);
}

/// Log at Notice level
pub fn notice(message: &str) {
    log(LogLevel::Notice, message);
}

/// Log at Info level
pub fn info(message: &str) {
    log(LogLevel::Info, message);
}

/// Log at Verbose level
pub fn verbose(message: &str) {
    log(LogLevel::Verbose, message);
}

/// Log at Debug level
pub fn debug(message: &str) {
    log(LogLevel::Debug, message);
}

/// Log at Extreme level
pub fn extreme(message: &str) {
    log(LogLevel::Extreme, message);
}

/// Convenience macro for logging with format strings
#[macro_export]
macro_rules! rns_log {
    ($level:expr, $($arg:tt)*) => {
        $crate::logging::log($level, &format!($($arg)*))
    };
}

/// Convenience macro for critical logs
#[macro_export]
macro_rules! rns_critical {
    ($($arg:tt)*) => {
        $crate::logging::critical(&format!($($arg)*))
    };
}

/// Convenience macro for error logs
#[macro_export]
macro_rules! rns_error {
    ($($arg:tt)*) => {
        $crate::logging::error(&format!($($arg)*))
    };
}

/// Convenience macro for warning logs
#[macro_export]
macro_rules! rns_warning {
    ($($arg:tt)*) => {
        $crate::logging::warning(&format!($($arg)*))
    };
}

/// Convenience macro for notice logs
#[macro_export]
macro_rules! rns_notice {
    ($($arg:tt)*) => {
        $crate::logging::notice(&format!($($arg)*))
    };
}

/// Convenience macro for info logs
#[macro_export]
macro_rules! rns_info {
    ($($arg:tt)*) => {
        $crate::logging::info(&format!($($arg)*))
    };
}

/// Convenience macro for verbose logs
#[macro_export]
macro_rules! rns_verbose {
    ($($arg:tt)*) => {
        $crate::logging::verbose(&format!($($arg)*))
    };
}

/// Convenience macro for debug logs
#[macro_export]
macro_rules! rns_debug {
    ($($arg:tt)*) => {
        $crate::logging::debug(&format!($($arg)*))
    };
}

/// Convenience macro for extreme logs
#[macro_export]
macro_rules! rns_extreme {
    ($($arg:tt)*) => {
        $crate::logging::extreme(&format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_log_level_filtering() {
        // Initialize with Warning level
        init(LogLevel::Warning, LogDestination::None).unwrap();

        // These should not panic
        critical("Critical message");
        error("Error message");
        warning("Warning message");
        notice("Notice message"); // filtered
        debug("Debug message"); // filtered
    }

    #[test]
    fn test_log_callback() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        let callback: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |_msg| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        init(LogLevel::Debug, LogDestination::Callback(callback)).unwrap();

        debug("Test message 1");
        debug("Test message 2");

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_format_message() {
        let msg = format_message(LogLevel::Error, "Test error");
        assert!(msg.contains("[ERROR]"));
        assert!(msg.contains("Test error"));
    }
}
