//! rncp - Reticulum Network Copy
//!
//! File copy utility over Reticulum network using Resource transfers.
//! Compatible with Python rncp.
//!
//! Modes:
//! - Listen mode (`-l`): Accept incoming file transfers
//! - Send mode (default): Push file to remote destination
//! - Fetch mode (`-f`): Pull file from remote listener

mod common;
mod config;
mod fetch;
mod listen;
mod metadata;
mod progress;
mod protocol;
mod send;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, ArgAction, Command};

/// Application name used for transport and destination naming.
pub(crate) const APP_NAME: &str = "rncp";

/// Destination aspect for receiving files.
const ASPECT_RECEIVE: &str = "receive";

/// Package version from Cargo.toml.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = build_cli().get_matches();

    // Calculate log level from verbosity/quietness (matching Python: base level 3)
    let verbose_count = matches.get_count("verbose") as i32;
    let quiet_count = matches.get_count("quiet") as i32;
    let target_level = 3 + verbose_count - quiet_count;
    let log_filter = match target_level {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "info",
        4 => "debug",
        _ if target_level < 0 => "off",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_filter)).init();

    // Get timeout
    let timeout_secs: u64 = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .unwrap_or(120);
    let timeout = Duration::from_secs(timeout_secs);

    // Set up shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    let exit_code = rt.block_on(async {
        dispatch_mode(&matches, timeout, running).await
    });

    std::process::exit(exit_code);
}

/// Dispatch to the appropriate mode based on CLI arguments.
async fn dispatch_mode(
    matches: &clap::ArgMatches,
    timeout: Duration,
    running: Arc<AtomicBool>,
) -> i32 {
    let listen_mode = matches.get_flag("listen") || matches.get_flag("print-identity");
    let fetch_mode_flag = matches.get_flag("fetch");
    let has_file = matches.get_one::<String>("file").is_some();
    let has_dest = matches.get_one::<String>("destination").is_some();

    if listen_mode {
        listen::run_listen_mode(matches, timeout, running).await
    } else if fetch_mode_flag {
        if has_dest && has_file {
            fetch::run_fetch_mode(matches, timeout, running).await
        } else {
            println!();
            print_help();
            println!();
            0
        }
    } else if has_dest && has_file {
        send::run_send_mode(matches, timeout, running).await
    } else {
        println!();
        print_help();
        println!();
        0
    }
}

/// Build the CLI argument parser.
fn build_cli() -> Command {
    Command::new("rncp")
        .version(VERSION)
        .about("Reticulum File Transfer Utility")
        // Positional arguments (matching Python)
        .arg(
            Arg::new("file")
                .help("file to be transferred")
                .index(1),
        )
        .arg(
            Arg::new("destination")
                .help("hexadecimal hash of the receiver")
                .index(2),
        )
        // Config options
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("path")
                .help("path to alternative Reticulum config directory"),
        )
        .arg(
            Arg::new("identity")
                .short('i')
                .value_name("identity")
                .help("path to identity to use"),
        )
        // Verbosity (matching Python: -v for verbose, -q for quiet)
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("increase verbosity"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::Count)
                .help("decrease verbosity"),
        )
        .arg(
            Arg::new("silent")
                .short('S')
                .long("silent")
                .action(ArgAction::SetTrue)
                .help("disable transfer progress output"),
        )
        // Mode flags
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .action(ArgAction::SetTrue)
                .help("listen for incoming transfer requests"),
        )
        .arg(
            Arg::new("fetch")
                .short('f')
                .long("fetch")
                .action(ArgAction::SetTrue)
                .help("fetch file from remote listener instead of sending"),
        )
        // Transfer options
        .arg(
            Arg::new("no-compress")
                .short('C')
                .long("no-compress")
                .action(ArgAction::SetTrue)
                .help("disable automatic compression"),
        )
        .arg(
            Arg::new("timeout")
                .short('w')
                .value_name("seconds")
                .help("sender timeout before giving up")
                .default_value("120"),
        )
        .arg(
            Arg::new("phy-rates")
                .short('P')
                .long("phy-rates")
                .action(ArgAction::SetTrue)
                .help("display physical layer transfer rates"),
        )
        // Fetch server options
        .arg(
            Arg::new("allow-fetch")
                .short('F')
                .long("allow-fetch")
                .action(ArgAction::SetTrue)
                .help("allow authenticated clients to fetch files"),
        )
        .arg(
            Arg::new("jail")
                .short('j')
                .long("jail")
                .value_name("path")
                .help("restrict fetch requests to specified path"),
        )
        // Save options
        .arg(
            Arg::new("save")
                .short('s')
                .long("save")
                .value_name("path")
                .help("save received files in specified path"),
        )
        .arg(
            Arg::new("overwrite")
                .short('O')
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("allow overwriting received files, instead of adding postfix"),
        )
        // Announce options
        .arg(
            Arg::new("announce")
                .short('b')
                .value_name("seconds")
                .help("announce interval, 0 to only announce at startup")
                .default_value("-1"),
        )
        // Authentication options
        .arg(
            Arg::new("allowed")
                .short('a')
                .value_name("allowed_hash")
                .action(ArgAction::Append)
                .help("allow this identity (or add in ~/.rncp/allowed_identities)"),
        )
        .arg(
            Arg::new("no-auth")
                .short('n')
                .long("no-auth")
                .action(ArgAction::SetTrue)
                .help("accept requests from anyone"),
        )
        .arg(
            Arg::new("print-identity")
                .short('p')
                .long("print-identity")
                .action(ArgAction::SetTrue)
                .help("print identity and destination info and exit"),
        )
        // TCP interface (for testing without full Reticulum config)
        .arg(
            Arg::new("tcp-client")
                .long("tcp-client")
                .value_name("HOST:PORT")
                .help("connect to TCP interface"),
        )
        .arg(
            Arg::new("tcp-server")
                .long("tcp-server")
                .value_name("HOST:PORT")
                .help("listen on TCP interface"),
        )
}

/// Print usage help (matching Python's format).
fn print_help() {
    eprintln!("Usage: rncp [OPTIONS] [FILE] [DESTINATION]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  rncp -l                     Listen for incoming files");
    eprintln!("  rncp file.txt <dest_hash>   Send file to destination");
    eprintln!("  rncp -f path <dest_hash>    Fetch file from remote");
    eprintln!();
    eprintln!("Run 'rncp --help' for full options.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_build() {
        // Verify the CLI builds without errors
        let _cli = build_cli();
    }

    #[test]
    fn test_cli_version() {
        let cli = build_cli();
        let version = cli.get_version().unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_cli_parse_listen_mode() {
        let cli = build_cli();
        let matches = cli.try_get_matches_from(["rncp", "-l"]).unwrap();
        assert!(matches.get_flag("listen"));
    }

    #[test]
    fn test_cli_parse_fetch_mode() {
        let cli = build_cli();
        let matches = cli
            .try_get_matches_from(["rncp", "-f", "file.txt", "abc123"])
            .unwrap();
        assert!(matches.get_flag("fetch"));
        assert_eq!(
            matches.get_one::<String>("file").map(|s| s.as_str()),
            Some("file.txt")
        );
        assert_eq!(
            matches.get_one::<String>("destination").map(|s| s.as_str()),
            Some("abc123")
        );
    }

    #[test]
    fn test_cli_parse_send_mode() {
        let cli = build_cli();
        let matches = cli
            .try_get_matches_from(["rncp", "file.txt", "abc123"])
            .unwrap();
        assert!(!matches.get_flag("listen"));
        assert!(!matches.get_flag("fetch"));
        assert_eq!(
            matches.get_one::<String>("file").map(|s| s.as_str()),
            Some("file.txt")
        );
    }

    #[test]
    fn test_cli_parse_verbose() {
        let cli = build_cli();
        let matches = cli.try_get_matches_from(["rncp", "-vvv", "-l"]).unwrap();
        assert_eq!(matches.get_count("verbose"), 3);
    }

    #[test]
    fn test_cli_parse_quiet() {
        let cli = build_cli();
        let matches = cli.try_get_matches_from(["rncp", "-qq", "-l"]).unwrap();
        assert_eq!(matches.get_count("quiet"), 2);
    }

    #[test]
    fn test_cli_parse_timeout() {
        let cli = build_cli();
        let matches = cli.try_get_matches_from(["rncp", "-w", "60", "-l"]).unwrap();
        assert_eq!(
            matches.get_one::<String>("timeout").map(|s| s.as_str()),
            Some("60")
        );
    }

    #[test]
    fn test_cli_parse_tcp_interfaces() {
        let cli = build_cli();
        let matches = cli
            .try_get_matches_from([
                "rncp",
                "-l",
                "--tcp-server",
                "127.0.0.1:4242",
                "--tcp-client",
                "192.168.1.1:4242",
            ])
            .unwrap();
        assert_eq!(
            matches.get_one::<String>("tcp-server").map(|s| s.as_str()),
            Some("127.0.0.1:4242")
        );
        assert_eq!(
            matches.get_one::<String>("tcp-client").map(|s| s.as_str()),
            Some("192.168.1.1:4242")
        );
    }

    #[test]
    fn test_cli_parse_fetch_server_options() {
        let cli = build_cli();
        let matches = cli
            .try_get_matches_from(["rncp", "-l", "-F", "-j", "/tmp/jail"])
            .unwrap();
        assert!(matches.get_flag("allow-fetch"));
        assert_eq!(
            matches.get_one::<String>("jail").map(|s| s.as_str()),
            Some("/tmp/jail")
        );
    }

    #[test]
    fn test_cli_parse_save_options() {
        let cli = build_cli();
        let matches = cli
            .try_get_matches_from(["rncp", "-l", "-s", "/tmp/downloads", "-O"])
            .unwrap();
        assert_eq!(
            matches.get_one::<String>("save").map(|s| s.as_str()),
            Some("/tmp/downloads")
        );
        assert!(matches.get_flag("overwrite"));
    }

    #[test]
    fn test_app_name_constant() {
        assert_eq!(APP_NAME, "rncp");
    }

    #[test]
    fn test_aspect_receive_constant() {
        assert_eq!(ASPECT_RECEIVE, "receive");
    }
}
