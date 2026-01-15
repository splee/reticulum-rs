#!/usr/bin/env python3
"""
rnx remote execution server helper for integration testing.

Starts rnx in listen mode and outputs structured information about
received commands for verification.

Outputs (KEY=VALUE format):
    DESTINATION_HASH=<hex>  - The destination hash for clients
    STATUS=READY  - When listener is ready
    COMMAND_RECEIVED=<command>  - When a command is received
    EXIT_CODE=<code>  - Command exit code
    STATUS=COMPLETE  - When finished
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description='rnx server for testing')
    parser.add_argument('--tcp-client', required=True, help='TCP server to connect to (host:port)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('--announce-interval', '-i', type=int, default=5, help='Announce interval')
    parser.add_argument('--noauth', '-n', action='store_true', help='Allow any client')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    # Build rnx command
    cmd = [
        sys.executable, '-m', 'RNS.Utilities.rnx',
        '-l',  # listen mode
        '-b',  # announce/broadcast
    ]

    if args.noauth:
        cmd.append('-n')

    if args.verbose:
        cmd.append('-v')

    # Start rnx process with config for TCP client
    env = os.environ.copy()

    # Create a temporary config for TCP client connection
    config_dir = tempfile.mkdtemp(prefix='rnx_config_')
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

    env['RNS_CONFIG_DIR'] = config_dir

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        dest_hash = None
        start_time = time.time()

        # Process rnx output
        for line in proc.stdout:
            line = line.strip()
            if args.verbose:
                print(f"RNX: {line}", file=sys.stderr)

            # Look for "Listening on <hash>" or similar
            if 'listening on' in line.lower() or 'Listening on' in line:
                # Extract hash from <hash> format
                if '<' in line and '>' in line:
                    start = line.find('<') + 1
                    end = line.find('>')
                    dest_hash = line[start:end]
                    print(f"DESTINATION_HASH={dest_hash}", flush=True)
                    print("STATUS=READY", flush=True)

            # Check for command indicators
            if 'received' in line.lower() or 'executing' in line.lower():
                print(f"COMMAND_MSG={line}", flush=True)

            # Check timeout
            if time.time() - start_time > args.timeout:
                break

        proc.wait(timeout=5)

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

    print("STATUS=COMPLETE", flush=True)


if __name__ == '__main__':
    main()
