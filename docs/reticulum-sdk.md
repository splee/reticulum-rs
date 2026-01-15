# Reticulum SDK Entry Point

The `Reticulum` struct is the main entry point for applications built on top of Reticulum. It handles network stack initialization, shared instance negotiation, and provides access to transport and configuration.

## Quick Start

```rust
use reticulum::reticulum::Reticulum;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with defaults
    let rns = Reticulum::builder().build().await?;

    println!("Running in {:?} mode", rns.instance_mode());

    // Your application logic here...

    // Shutdown on exit
    rns.shutdown();
    Ok(())
}
```

## Instance Modes

When Reticulum initializes, it negotiates which mode to operate in:

| Mode | Description |
|------|-------------|
| `SharedInstance` | This process owns the transport and interfaces. Acts as the daemon. |
| `ConnectedToSharedInstance` | Connected to an existing daemon via IPC. Operations route through the daemon. |
| `Standalone` | Independent operation with full transport. No IPC sharing. |

The negotiation follows this sequence:
1. Try to bind as server → `SharedInstance`
2. If bind fails, try to connect to existing server → `ConnectedToSharedInstance`
3. If both fail → `Standalone` (or error if `require_shared_instance` is set)

## Builder Configuration

```rust
let rns = Reticulum::builder()
    .config_dir("/path/to/config")      // Custom config directory
    .log_level(LogLevel::Debug)         // Override log level
    .verbosity(2)                       // Adjust verbosity (+/-)
    .require_shared_instance(true)      // Fail if no daemon available
    .cancel_token(token)                // Custom cancellation token
    .skip_interfaces(true)              // Don't spawn interfaces
    .build()
    .await?;
```

## Common Patterns

### Client Application (connects to daemon)

```rust
let rns = Reticulum::builder()
    .require_shared_instance(true)
    .build()
    .await?;

// Query network state via RPC
let stats = rns.get_interface_stats().await?;
let paths = rns.get_path_table(None).await?;
```

### Daemon Application

```rust
let rns = Reticulum::builder()
    .log_level(LogLevel::Info)
    .build()
    .await?;

// Keep running until shutdown signal
tokio::signal::ctrl_c().await?;
rns.shutdown();
```

### Standalone Application (no IPC)

Set `share_instance = false` in config, or handle the mode explicitly:

```rust
let rns = Reticulum::builder().build().await?;

if rns.is_standalone_instance() {
    // Full transport access, no daemon sharing
    let transport = rns.transport();
}
```

## Accessing Resources

```rust
// Configuration
let config = rns.config();
let paths = rns.paths();

// Transport identity
let identity = rns.identity();

// Transport (only in SharedInstance/Standalone modes)
if let Some(transport) = rns.transport_opt() {
    // Direct transport access
}

// Network queries (work in all modes)
let stats = rns.get_interface_stats().await?;
let paths = rns.get_path_table(Some(4)).await?;  // max 4 hops
let links = rns.get_link_count().await?;
```

## Error Handling

```rust
use reticulum::reticulum::{Reticulum, ReticulumError};

match Reticulum::builder().require_shared_instance(true).build().await {
    Ok(rns) => { /* connected to daemon */ }
    Err(ReticulumError::SharedInstanceRequired(msg)) => {
        eprintln!("No daemon running: {}", msg);
    }
    Err(ReticulumError::ConfigLoad(e)) => {
        eprintln!("Config error: {}", e);
    }
    Err(e) => {
        eprintln!("Initialization failed: {}", e);
    }
}
```
