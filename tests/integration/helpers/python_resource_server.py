#!/usr/bin/env python3
"""
Python resource server helper for integration testing.

Accepts incoming links and resources, prints parseable status output.
Used for testing Rust client resource sending to Python server.
"""

import argparse
import sys
import time
import tempfile
import os
import threading

import RNS

# Global state
resource_done = False
received_resource = None
link_established = False

def client_link_established(link):
    """Called when a client establishes a link."""
    global link_established
    link_established = True
    print(f"LINK_ACTIVATED={link.link_id.hex()}", flush=True)

    # Set up resource handling
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_callback(resource_callback)
    link.set_resource_started_callback(resource_started)
    link.set_resource_concluded_callback(resource_concluded)

def resource_callback(resource):
    """Pre-flight check for incoming resource. Return True to accept."""
    print(f"RESOURCE_OFFERED={resource.hash.hex()}:{resource.total_size}", flush=True)
    return True

def resource_started(resource):
    """Called when resource transfer begins."""
    print(f"RESOURCE_STARTED={resource.hash.hex()}:{resource.total_size}", flush=True)
    resource.progress_callback = resource_progress

def resource_progress(resource):
    """Called during resource transfer with progress updates."""
    progress_pct = int(resource.get_progress() * 100)
    print(f"RESOURCE_PROGRESS={resource.hash.hex()}:{progress_pct}", flush=True)

def resource_concluded(resource):
    """Called when resource transfer completes."""
    global resource_done, received_resource

    if resource.status == RNS.Resource.COMPLETE:
        received_resource = resource
        data = resource.data.read() if hasattr(resource.data, 'read') else resource.data
        data_hex = data.hex() if isinstance(data, bytes) else ""
        data_len = len(data) if data else 0
        print(f"RESOURCE_COMPLETE={resource.hash.hex()}:{data_len}:{data_hex}", flush=True)

        # Also output metadata if present
        if resource.metadata:
            if isinstance(resource.metadata, dict) and b'name' in resource.metadata:
                filename = resource.metadata[b'name'].decode('utf-8')
                print(f"RESOURCE_METADATA_NAME={filename}", flush=True)

        resource_done = True
    else:
        print(f"RESOURCE_FAILED={resource.hash.hex()}:{resource.status}", flush=True)
        resource_done = True

def main():
    parser = argparse.ArgumentParser(description="Python resource server for testing")
    parser.add_argument("-a", "--app-name", default="test_app", help="Application name")
    parser.add_argument("-A", "--aspect", default="resourceserver", help="Aspect name")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Timeout in seconds")
    parser.add_argument("-n", "--num-resources", type=int, default=1, help="Expected number of resources (0 for infinite)")
    parser.add_argument("-i", "--announce-interval", type=int, default=10, help="Announce interval in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        RNS.loglevel = RNS.LOG_DEBUG
    else:
        RNS.loglevel = RNS.LOG_ERROR

    # Initialize Reticulum
    reticulum = RNS.Reticulum()

    # Create identity
    identity = RNS.Identity()

    # Create destination
    destination = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        args.app_name,
        args.aspect
    )

    # Output destination hash
    dest_hash = destination.hash.hex()
    print(f"DESTINATION_HASH={dest_hash}", flush=True)

    # Set up link callback
    destination.set_link_established_callback(client_link_established)

    # Announce
    destination.announce()
    announce_count = 1
    print(f"ANNOUNCE_SENT={announce_count}", flush=True)

    # Main loop
    start_time = time.time()
    last_announce = start_time
    resources_received = 0

    while True:
        # Check timeout
        elapsed = time.time() - start_time
        if args.timeout > 0 and elapsed >= args.timeout:
            print("STATUS=TIMEOUT", flush=True)
            break

        # Check resource count
        global resource_done
        if resource_done:
            resources_received += 1
            resource_done = False
            if args.num_resources > 0 and resources_received >= args.num_resources:
                print("STATUS=RESOURCE_LIMIT_REACHED", flush=True)
                break

        # Periodic announce
        if time.time() - last_announce >= args.announce_interval:
            destination.announce()
            announce_count += 1
            last_announce = time.time()
            print(f"ANNOUNCE_SENT={announce_count}", flush=True)

        time.sleep(0.1)

    print(f"TOTAL_RESOURCES={resources_received}", flush=True)
    print("STATUS=SHUTDOWN", flush=True)

if __name__ == "__main__":
    main()
