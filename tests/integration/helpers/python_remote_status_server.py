#!/usr/bin/env python3
"""
Python helper for remote status testing.

Creates a transport with remote management enabled and outputs the
transport identity hash for the Rust client to connect to.

Usage:
    python3 python_remote_status_server.py --allowed-identity <hash> [--config-dir <dir>]
"""

import RNS
import time
import argparse
import sys
import signal
import os
import tempfile

# Global for signal handler
running = True


def signal_handler(sig, frame):
    global running
    running = False


def create_temp_config(allowed_identity=None):
    """Create a temporary config directory with remote management enabled."""
    config_dir = tempfile.mkdtemp(prefix="rns_remote_mgmt_")
    config_file = os.path.join(config_dir, "config")

    # Build the allowed list
    allowed_list = ""
    if allowed_identity:
        allowed_list = f"remote_management_allowed = {allowed_identity}"

    config_content = f"""# Remote management test configuration
[reticulum]
  enable_transport = Yes
  share_instance = No
  panic_on_interface_error = No
  enable_remote_management = Yes
  {allowed_list}

[logging]
  loglevel = 5

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = True
    listen_ip = 0.0.0.0
    listen_port = 4244

  [[TCP Client to Hub]]
    type = TCPClientInterface
    interface_enabled = True
    target_host = 127.0.0.1
    target_port = 4242
"""

    with open(config_file, "w") as f:
        f.write(config_content)

    return config_dir


def main():
    parser = argparse.ArgumentParser(description="Remote status test server")
    parser.add_argument(
        "--allowed-identity",
        type=str,
        help="Identity hash allowed for remote management (hex, 32 chars)",
    )
    parser.add_argument(
        "--config-dir",
        type=str,
        help="Config directory (if not specified, creates temp config with remote management)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds (default: 60)",
    )
    args = parser.parse_args()

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Determine config directory
    if args.config_dir:
        config_dir = args.config_dir
    else:
        config_dir = create_temp_config(args.allowed_identity)
        print(f"CONFIG_DIR={config_dir}", flush=True)

    # Pre-configure allowed identity if specified
    if args.allowed_identity:
        try:
            allowed_hash = bytes.fromhex(args.allowed_identity)
            RNS.Transport.remote_management_allowed.append(allowed_hash)
            print(f"REMOTE_MGMT_ALLOWED={args.allowed_identity}", flush=True)
        except Exception as e:
            print(f"ERROR: Invalid allowed-identity: {e}", file=sys.stderr, flush=True)
            sys.exit(1)

    # Initialize Reticulum with our config
    try:
        reticulum = RNS.Reticulum(configdir=config_dir, loglevel=4, require_shared_instance=False)
    except Exception as e:
        print(f"ERROR: Failed to initialize Reticulum: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    # Wait for transport to start
    time.sleep(2)

    # Get transport identity hash
    if RNS.Transport.identity:
        transport_hash = RNS.Transport.identity.hash.hex()
        print(f"TRANSPORT_HASH={transport_hash}", flush=True)
    else:
        print("ERROR: Transport identity not available", file=sys.stderr, flush=True)
        sys.exit(1)

    # Check if remote management destination was created
    if hasattr(RNS.Transport, "remote_management_destination") and RNS.Transport.remote_management_destination:
        dest_hash = RNS.Transport.remote_management_destination.hash.hex()
        print(f"REMOTE_MGMT_DEST={dest_hash}", flush=True)
        print("REMOTE_MGMT_ENABLED=1", flush=True)
    else:
        print("REMOTE_MGMT_ENABLED=0", flush=True)
        print("ERROR: Remote management not enabled. Check config.", file=sys.stderr, flush=True)

    # Output interface stats for reference
    stats = reticulum.get_interface_stats()
    if stats and "interfaces" in stats:
        for iface in stats["interfaces"]:
            name = iface.get("short_name", iface.get("name", "unknown"))
            print(f"INTERFACE={name}", flush=True)

    print("STATUS=READY", flush=True)

    # Wait for timeout or signal
    start_time = time.time()
    while running and (time.time() - start_time) < args.timeout:
        time.sleep(0.5)

    print("STATUS=SHUTDOWN", flush=True)


if __name__ == "__main__":
    main()

