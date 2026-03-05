#!/usr/bin/env python3
"""
rncp file receiver helper for integration testing.

Starts rncp in listen mode and outputs structured information about
received files including checksums for verification.

Outputs (KEY=VALUE format):
    DESTINATION_HASH=<hex>  - The destination hash for senders
    FILE_RECEIVED=<filename>:<size>:<sha256>  - For each received file
    STATUS=READY  - When listener is ready
    STATUS=COMPLETE  - When finished
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def calculate_sha256(filepath):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def monitor_directory(save_dir, initial_files, timeout, received_files):
    """Monitor directory for new files and record their checksums."""
    start_time = time.time()
    seen_files = set(initial_files)

    while time.time() - start_time < timeout:
        try:
            current_files = set(os.listdir(save_dir))
            new_files = current_files - seen_files

            for filename in new_files:
                filepath = os.path.join(save_dir, filename)
                if os.path.isfile(filepath):
                    # Wait a moment for file to be fully written
                    time.sleep(0.5)
                    try:
                        size = os.path.getsize(filepath)
                        checksum = calculate_sha256(filepath)
                        received_files.append((filename, size, checksum))
                        print(f"FILE_RECEIVED={filename}:{size}:{checksum}", flush=True)
                    except Exception as e:
                        print(f"ERROR=Failed to process {filename}: {e}", file=sys.stderr)
                seen_files.add(filename)

            time.sleep(0.5)
        except Exception as e:
            print(f"ERROR=Monitor error: {e}", file=sys.stderr)
            break


def main():
    parser = argparse.ArgumentParser(description='rncp file receiver for testing')
    parser.add_argument('--tcp-client', required=True, help='TCP server to connect to (host:port)')
    parser.add_argument('--save-dir', help='Directory to save received files (default: temp dir)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('--announce-interval', '-i', type=int, default=5, help='Announce interval')
    parser.add_argument('--no-auth', '-n', action='store_true', help='Allow any sender')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    # Create save directory
    if args.save_dir:
        save_dir = args.save_dir
        os.makedirs(save_dir, exist_ok=True)
    else:
        save_dir = tempfile.mkdtemp(prefix='rncp_recv_')

    print(f"SAVE_DIR={save_dir}", flush=True)

    # Record initial files in directory
    initial_files = set(os.listdir(save_dir)) if os.path.exists(save_dir) else set()

    # Create a temporary config for TCP client connection
    # IMPORTANT: Use --config argument, not RNS_CONFIG_DIR env var
    # (Python RNS doesn't recognize the env var)
    config_dir = tempfile.mkdtemp(prefix='rncp_config_')
    config_file = os.path.join(config_dir, 'config')

    host, port = args.tcp_client.split(':')
    config_content = f"""[reticulum]
enable_transport = false
share_instance = false

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    interface_enabled = true
    target_host = {host}
    target_port = {port}
"""

    with open(config_file, 'w') as f:
        f.write(config_content)

    # Build rncp command with --config argument
    # Use -u for unbuffered Python output to ensure we see "listening on" immediately
    cmd = [
        sys.executable, '-u', '-m', 'RNS.Utilities.rncp',
        '--config', config_dir,  # use our config directory
        '-l',  # listen mode
        '-s', save_dir,  # save directory
        '-b', str(args.announce_interval),  # announce interval
    ]

    if args.no_auth:
        cmd.append('-n')

    if args.verbose:
        cmd.append('-v')

    # Start rncp process
    env = os.environ.copy()

    received_files = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        # Start file monitor in background
        monitor_thread = threading.Thread(
            target=monitor_directory,
            args=(save_dir, initial_files, args.timeout, received_files),
            daemon=True
        )
        monitor_thread.start()

        # Process rncp output
        dest_hash = None
        for line in proc.stdout:
            line = line.strip()
            if args.verbose:
                print(f"RNCP: {line}", file=sys.stderr)

            # Look for "Listening on <hash>" or similar
            if 'listening on' in line.lower() or 'Listening on' in line:
                # Extract hash from <hash> format
                if '<' in line and '>' in line:
                    start = line.find('<') + 1
                    end = line.find('>')
                    dest_hash = line[start:end]
                    print(f"DESTINATION_HASH={dest_hash}", flush=True)
                    print("STATUS=READY", flush=True)

            # Check for transfer messages
            if 'received' in line.lower() or 'complete' in line.lower():
                print(f"TRANSFER_MSG={line}", flush=True)

        proc.wait(timeout=args.timeout)

    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as e:
        print(f"ERROR={e}", file=sys.stderr)
    finally:
        # Cleanup config directory
        try:
            import shutil
            shutil.rmtree(config_dir, ignore_errors=True)
        except:
            pass

    # Final status
    if received_files:
        print(f"TOTAL_RECEIVED={len(received_files)}", flush=True)
    print("STATUS=COMPLETE", flush=True)


if __name__ == '__main__':
    main()
