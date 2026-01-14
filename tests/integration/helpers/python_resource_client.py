#!/usr/bin/env python3
"""
Python resource client helper for integration testing.

Connects to a destination, establishes a link, and sends a resource.
Used for testing Python client resource sending to Rust server.
"""

import argparse
import sys
import time
import os

import RNS

# Global state
link_established = False
link_instance = None
resource_done = False
resource_success = False

def link_established_callback(link):
    """Called when link is established."""
    global link_established, link_instance
    link_established = True
    link_instance = link
    print(f"LINK_ACTIVATED={link.link_id.hex()}", flush=True)

def link_closed_callback(link):
    """Called when link is closed."""
    print(f"LINK_CLOSED={link.link_id.hex()}", flush=True)

def resource_progress(resource):
    """Called during resource transfer."""
    progress_pct = int(resource.get_progress() * 100)
    print(f"RESOURCE_PROGRESS={resource.hash.hex()}:{progress_pct}", flush=True)

def resource_concluded(resource):
    """Called when resource transfer completes."""
    global resource_done, resource_success

    if resource.status == RNS.Resource.COMPLETE:
        print(f"RESOURCE_COMPLETE={resource.hash.hex()}", flush=True)
        resource_success = True
    else:
        print(f"RESOURCE_FAILED={resource.hash.hex()}:{resource.status}", flush=True)
        resource_success = False

    resource_done = True

def main():
    import tempfile

    parser = argparse.ArgumentParser(description="Python resource client for testing")
    parser.add_argument("-d", "--destination", required=True, help="Destination hash (hex)")
    parser.add_argument("-a", "--app-name", default="test_app", help="Application name")
    parser.add_argument("-A", "--aspect", default="resourceserver", help="Aspect name")
    parser.add_argument("-s", "--send-data", help="Data to send as resource (hex string)")
    parser.add_argument("-f", "--send-file", help="File path to send as resource")
    parser.add_argument("-m", "--metadata", help="Metadata filename")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Timeout in seconds")
    parser.add_argument("-c", "--configdir", help="Config directory (default: ~/.reticulum)")
    parser.add_argument("--tcp-client", help="TCP client target host:port (e.g., 127.0.0.1:4242)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if not args.send_data and not args.send_file:
        print("ERROR: Must specify either --send-data or --send-file", file=sys.stderr)
        sys.exit(1)

    # Configure logging
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_ERROR

    # If TCP client is specified, create a temporary config directory for standalone operation
    temp_configdir = None
    if args.tcp_client and not args.configdir:
        temp_configdir = tempfile.mkdtemp(prefix="rns_resclient_")
        RNS.log(f"Using temporary config directory: {temp_configdir}", RNS.LOG_INFO)

        # Create minimal config with TCP client interface
        host, port = args.tcp_client.rsplit(':', 1)
        config_content = f"""
[reticulum]
enable_transport = No
share_instance = No

[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    interface_enabled = True
    target_host = {host}
    target_port = {port}
"""
        config_path = os.path.join(temp_configdir, "config")
        with open(config_path, "w") as f:
            f.write(config_content)

        # Initialize Reticulum with the temporary config
        reticulum = RNS.Reticulum(configdir=temp_configdir)
    elif args.configdir:
        reticulum = RNS.Reticulum(configdir=args.configdir)
    else:
        reticulum = RNS.Reticulum()

    # Wait for interfaces to initialize
    time.sleep(2)

    # Parse destination hash
    try:
        dest_hash = bytes.fromhex(args.destination)
    except ValueError:
        print(f"ERROR: Invalid destination hash: {args.destination}", file=sys.stderr)
        sys.exit(1)

    print(f"TARGET_DESTINATION={args.destination}", flush=True)

    # Request path to destination
    print("STATUS=REQUESTING_PATH", flush=True)
    RNS.Transport.request_path(dest_hash)

    # Wait for path
    start_time = time.time()
    while not RNS.Transport.has_path(dest_hash):
        if time.time() - start_time > args.timeout / 2:
            print("STATUS=PATH_TIMEOUT", flush=True)
            sys.exit(1)
        time.sleep(0.1)

    print("STATUS=PATH_FOUND", flush=True)

    # Create identity for our side
    identity = RNS.Identity()

    # Recall the remote identity for this destination
    remote_identity = RNS.Identity.recall(dest_hash)
    if remote_identity is None:
        print("STATUS=IDENTITY_NOT_FOUND", flush=True)
        sys.exit(1)

    # Create output destination
    destination = RNS.Destination(
        remote_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        args.app_name,
        args.aspect
    )

    # Establish link
    print("STATUS=ESTABLISHING_LINK", flush=True)
    link = RNS.Link(destination)
    link.set_link_established_callback(link_established_callback)
    link.set_link_closed_callback(link_closed_callback)

    # Wait for link
    link_timeout = time.time() + args.timeout / 2
    while not link_established:
        if time.time() > link_timeout:
            print("STATUS=LINK_TIMEOUT", flush=True)
            sys.exit(1)
        if link.status == RNS.Link.CLOSED:
            print("STATUS=LINK_FAILED", flush=True)
            sys.exit(1)
        time.sleep(0.1)

    # Prepare data to send
    if args.send_file:
        with open(args.send_file, 'rb') as f:
            data = f.read()
        filename = os.path.basename(args.send_file)
    else:
        data = bytes.fromhex(args.send_data)
        filename = args.metadata if args.metadata else "data"

    data_len = len(data)
    data_hex = data.hex()
    print(f"SENDING_DATA={data_len}:{data_hex}", flush=True)

    # Create metadata
    metadata = {"name": filename.encode('utf-8')} if filename else None

    # Send resource - RNS.Resource can accept raw bytes or a file-like object
    # For BytesIO, we need to read the data first
    resource = RNS.Resource(
        data,  # Pass raw bytes directly
        link_instance,
        metadata=metadata,
        callback=resource_concluded,
        progress_callback=resource_progress
    )

    print(f"RESOURCE_STARTED={resource.hash.hex()}:{data_len}", flush=True)
    print(f"DATA_SENT={link_instance.link_id.hex()}:{data_len}", flush=True)

    # Wait for transfer to complete
    transfer_timeout = time.time() + args.timeout
    while not resource_done:
        if time.time() > transfer_timeout:
            print("STATUS=TRANSFER_TIMEOUT", flush=True)
            sys.exit(1)
        time.sleep(0.1)

    # Clean up
    link.teardown()
    time.sleep(0.5)

    if resource_success:
        print("STATUS=SUCCESS", flush=True)
        sys.exit(0)
    else:
        print("STATUS=FAILED", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
