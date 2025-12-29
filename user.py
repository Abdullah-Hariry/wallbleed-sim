#!/usr/bin/env python3
"""
User Program - DNS Query Tool
Sends DNS queries and receives responses

Usage: python user.py <resolver_host> <resolver_port> <domain>
Example: python user.py localhost 9000 www.example.com
"""

import sys
import socket
from dnsUtils import build_dns_query, send_query, receive_response, format_hex


def main():
    # Parse command line arguments
    if len(sys.argv) != 4:
        print("Usage: python user.py <resolver_host> <resolver_port> <domain>")
        print("Example: python user.py localhost 9000 www.example.com")
        sys.exit(1)

    resolver_host = sys.argv[1]
    resolver_port = int(sys.argv[2])
    domain = sys.argv[3]

    print(f"Querying {domain} via {resolver_host}:{resolver_port}")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Build full DNS query packet
        query_bytes = build_dns_query(domain)
        print(f"\nQuery packet ({len(query_bytes)} bytes):")
        print(format_hex(query_bytes))

        # Send query
        bytes_sent = send_query(sock, query_bytes, resolver_host, resolver_port)
        print(f"\nSent {bytes_sent} bytes")

        # Receive response
        response_bytes, server_addr = receive_response(sock, timeout=5.0)

        if response_bytes is None:
            print("No response received (timeout)")
            sys.exit(1)

        print(f"\nReceived {len(response_bytes)} bytes from {server_addr}")
        print("Response:")
        print(format_hex(response_bytes))

    finally:
        sock.close()


if __name__ == "__main__":
    main()