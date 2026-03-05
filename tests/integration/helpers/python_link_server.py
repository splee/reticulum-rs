#!/usr/bin/env python3
"""
Python link server helper for integration testing.

Creates a destination, announces it, and listens for incoming links.
Outputs link events to stdout for test verification.
"""

import argparse
import sys
import time
import threading
import RNS

# Global state
running = True
link_count = 0
message_count = 0

def handle_link_established(link):
    """Callback when a new link is established."""
    global link_count
    link_count += 1
    link_id = link.link_id.hex() if hasattr(link, 'link_id') else 'unknown'
    print(f"LINK_ACTIVATED={link_id}", flush=True)
    RNS.log(f"Link {link_id} established (total: {link_count})", RNS.LOG_INFO)

    # Set up packet callback for this link
    link.set_packet_callback(lambda msg, pkt: handle_link_packet(link, msg, pkt))

def handle_link_packet(link, message, packet):
    """Handle incoming data on a link."""
    global message_count
    message_count += 1
    link_id = link.link_id.hex() if hasattr(link, 'link_id') else 'unknown'
    data_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
    print(f"DATA_RECEIVED={link_id}:{len(message)}:{data_hex}", flush=True)
    RNS.log(f"Received {len(message)} bytes on link {link_id}", RNS.LOG_DEBUG)

def main():
    global running

    parser = argparse.ArgumentParser(description='Python link server for testing')
    parser.add_argument('-a', '--app-name', default='test_app', help='Application name')
    parser.add_argument('-A', '--aspect', default='linkserver', help='Destination aspect')
    parser.add_argument('-i', '--announce-interval', type=int, default=30, help='Announce interval in seconds')
    parser.add_argument('-n', '--link-count', type=int, default=0, help='Exit after N links (0=infinite)')
    parser.add_argument('-t', '--timeout', type=int, default=0, help='Exit after N seconds (0=infinite)')
    parser.add_argument('-c', '--configdir', help='Config directory (default: ~/.reticulum)')
    parser.add_argument('--tcp-client', help='TCP client target host:port (e.g., 127.0.0.1:4242)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    # Set log level
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_INFO

    # If TCP client is specified, create a temporary config directory for standalone operation
    temp_configdir = None
    if args.tcp_client and not args.configdir:
        import tempfile
        import os
        temp_configdir = tempfile.mkdtemp(prefix="rns_server_")
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
        # Log interfaces for debugging
        RNS.log(f"Active interfaces: {len(RNS.Transport.interfaces)}", RNS.LOG_DEBUG)
        for iface in RNS.Transport.interfaces:
            RNS.log(f"  Interface: {iface}", RNS.LOG_DEBUG)

    # Wait for interfaces to initialize
    time.sleep(2)

    # Create identity
    identity = RNS.Identity()
    RNS.log(f"Identity address hash: {identity.hash.hex()}", RNS.LOG_INFO)

    # Create destination
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        args.app_name,
        args.aspect
    )

    # Set link established callback
    destination.set_link_established_callback(handle_link_established)

    dest_hash = destination.hash.hex()
    print(f"DESTINATION_HASH={dest_hash}", flush=True)
    RNS.log(f"Created destination: {args.app_name}.{args.aspect} with hash {dest_hash}", RNS.LOG_INFO)

    # Announce
    destination.announce()
    print("ANNOUNCE_SENT=1", flush=True)
    RNS.log("Sent initial announce", RNS.LOG_INFO)

    # Set up periodic announces
    announce_num = 1
    last_announce = time.time()
    start_time = time.time()

    try:
        while running:
            # Check timeout
            if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                RNS.log("Timeout reached, exiting", RNS.LOG_INFO)
                print("STATUS=TIMEOUT", flush=True)
                break

            # Check link count
            if args.link_count > 0 and link_count >= args.link_count:
                RNS.log(f"Reached link limit ({args.link_count}), exiting", RNS.LOG_INFO)
                print("STATUS=LINK_LIMIT_REACHED", flush=True)
                break

            # Periodic announce
            if (time.time() - last_announce) >= args.announce_interval:
                announce_num += 1
                destination.announce()
                print(f"ANNOUNCE_SENT={announce_num}", flush=True)
                RNS.log(f"Sent announce #{announce_num}", RNS.LOG_INFO)
                last_announce = time.time()

            time.sleep(0.1)

    except KeyboardInterrupt:
        running = False

    print(f"TOTAL_LINKS={link_count}", flush=True)
    print(f"TOTAL_MESSAGES={message_count}", flush=True)
    print("STATUS=SHUTDOWN", flush=True)
    RNS.log(f"Link server complete: {link_count} links, {message_count} messages", RNS.LOG_INFO)

    # Clean shutdown
    RNS.Transport.detach_interfaces()

if __name__ == "__main__":
    main()
