#!/usr/bin/env python3
"""
Python link client helper for integration testing.

Waits for an announce, then establishes a link to the destination.
Outputs link events to stdout for test verification.
"""

import argparse
import sys
import time
import RNS

# Global state
target_destination = None
target_app = None
target_aspect = None
link_established = False
link_instance = None

def announce_received(destination_hash, announced_identity, app_data):
    """Callback when an announce is received."""
    global target_destination, target_app, target_aspect

    # Always log the announce
    dest_hex = destination_hash.hex()
    RNS.log(f"Received announce from {dest_hex}", RNS.LOG_DEBUG)

    if target_destination is None:
        print(f"ANNOUNCE_RECEIVED={dest_hex}", flush=True)
        RNS.log(f"Accepting announce from {dest_hex}", RNS.LOG_INFO)
        target_destination = destination_hash

def link_established_callback(link):
    """Callback when link is established."""
    global link_established, link_instance
    link_established = True
    link_instance = link
    link_id = link.link_id.hex() if hasattr(link, 'link_id') else 'unknown'
    print(f"LINK_ACTIVATED={link_id}", flush=True)
    RNS.log(f"Link {link_id} established", RNS.LOG_INFO)

def link_closed_callback(link):
    """Callback when link is closed."""
    link_id = link.link_id.hex() if hasattr(link, 'link_id') else 'unknown'
    print(f"LINK_CLOSED={link_id}", flush=True)
    RNS.log(f"Link {link_id} closed", RNS.LOG_INFO)

def packet_received(message, packet):
    """Handle incoming data on link."""
    link_id = 'unknown'
    if hasattr(packet, 'link') and packet.link:
        link_id = packet.link.link_id.hex() if hasattr(packet.link, 'link_id') else 'unknown'
    data_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
    print(f"DATA_RECEIVED={link_id}:{len(message)}:{data_hex}", flush=True)
    RNS.log(f"Received {len(message)} bytes", RNS.LOG_DEBUG)

def main():
    global target_destination, link_established, link_instance

    parser = argparse.ArgumentParser(description='Python link client for testing')
    parser.add_argument('-d', '--destination', help='Destination hash to connect to (hex)')
    parser.add_argument('-a', '--app-name', default='test_app', help='Application name to match')
    parser.add_argument('-A', '--aspect', default='linkserver', help='Aspect to match')
    parser.add_argument('-s', '--send-data', help='Data to send after link activation (hex)')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout in seconds')
    parser.add_argument('-c', '--configdir', help='Config directory (default: ~/.reticulum)')
    parser.add_argument('--tcp-client', help='TCP client target host:port (e.g., rust-node:4243)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    # Set log level
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_INFO

    # If TCP client is specified, create a temporary config directory for standalone operation
    # This avoids conflicts with the shared instance
    temp_configdir = None
    if args.tcp_client and not args.configdir:
        import tempfile
        import os
        temp_configdir = tempfile.mkdtemp(prefix="rns_client_")
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

    # Check if we're using a shared instance
    if RNS.Transport.owner and RNS.Transport.owner.is_connected_to_shared_instance:
        RNS.log("Connected to shared Reticulum instance", RNS.LOG_INFO)
    else:
        RNS.log("Running standalone Reticulum instance", RNS.LOG_INFO)

    # Wait for interfaces to initialize
    time.sleep(2)

    # Create identity
    identity = RNS.Identity()
    RNS.log(f"Identity address hash: {identity.hash.hex()}", RNS.LOG_INFO)

    # Set up announce handler
    RNS.Transport.register_announce_handler(announce_received)

    # Parse target destination if provided
    if args.destination:
        target_destination = bytes.fromhex(args.destination)
        print(f"TARGET_DESTINATION={args.destination}", flush=True)

    start_time = time.time()
    deadline = start_time + args.timeout

    # Wait for announce if no destination specified
    if target_destination is None:
        RNS.log(f"Waiting for announce from {args.app_name}.{args.aspect}", RNS.LOG_INFO)
        while target_destination is None:
            if time.time() >= deadline:
                RNS.log("Timeout waiting for announce", RNS.LOG_ERROR)
                print("STATUS=ERROR:announce_timeout", flush=True)
                return 1
            time.sleep(0.1)

    RNS.log(f"Creating link to {target_destination.hex()}", RNS.LOG_INFO)
    print(f"LINK_REQUESTING={target_destination.hex()}", flush=True)

    # Look up destination
    if RNS.Transport.has_path(target_destination):
        RNS.log("Path already known", RNS.LOG_DEBUG)
    else:
        RNS.log("Requesting path", RNS.LOG_DEBUG)
        RNS.Transport.request_path(target_destination)

        # Wait for path
        path_deadline = time.time() + 10
        while not RNS.Transport.has_path(target_destination):
            if time.time() >= path_deadline:
                RNS.log("Timeout waiting for path", RNS.LOG_ERROR)
                print("STATUS=ERROR:path_timeout", flush=True)
                return 1
            time.sleep(0.1)

    # Get destination identity and create output destination
    remote_identity = RNS.Identity.recall(target_destination)
    if remote_identity is None:
        RNS.log("Could not recall identity for destination", RNS.LOG_ERROR)
        print("STATUS=ERROR:no_identity", flush=True)
        return 1

    destination = RNS.Destination(
        remote_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        args.app_name,
        args.aspect
    )

    # Create link
    link = RNS.Link(destination)
    link.set_link_established_callback(link_established_callback)
    link.set_link_closed_callback(link_closed_callback)
    link.set_packet_callback(packet_received)

    # Wait for link activation
    RNS.log("Waiting for link activation", RNS.LOG_INFO)
    while not link_established:
        if time.time() >= deadline:
            RNS.log("Timeout waiting for link activation", RNS.LOG_ERROR)
            print("STATUS=ERROR:link_timeout", flush=True)
            return 1
        if link.status == RNS.Link.CLOSED:
            RNS.log("Link was closed", RNS.LOG_ERROR)
            print("STATUS=ERROR:link_closed", flush=True)
            return 1
        time.sleep(0.1)

    # Send data if configured
    if args.send_data and link_instance:
        data = bytes.fromhex(args.send_data)
        RNS.log(f"Sending {len(data)} bytes on link", RNS.LOG_INFO)
        # Create a Packet with the link as destination and send it
        packet = RNS.Packet(link_instance, data)
        packet.send()
        print(f"DATA_SENT={link_instance.link_id.hex()}:{len(data)}", flush=True)

    # Wait a bit for any response
    time.sleep(2)

    print("STATUS=SUCCESS", flush=True)
    RNS.log("Link client complete", RNS.LOG_INFO)

    # Clean shutdown
    RNS.Transport.detach_interfaces()
    return 0

if __name__ == "__main__":
    sys.exit(main())
