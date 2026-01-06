#!/usr/bin/env python3
"""
User Program - DNS Query Tool (Raw Hex Mode Only)
Minimal output - just shows query and response

Usage:
  Single query: python user.py <resolver_host> <resolver_port> <hex_query>
  Run tests:    python user.py <resolver_host> <resolver_port> <tests_file.txt>

Example:
  python user.py localhost 9000 0000012000010000000000000866616365626f6f6b03636f6d0000010001
  python user.py localhost 9000 tests.txt
"""

import sys
import socket
import os
from dnsUtils import send_query, receive_response


def parse_hex_input(hex_string):
    """Parse hex string input, removing spaces"""
    cleaned = hex_string.replace(' ', '').replace('\n', '')
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        print(f"ERROR: Invalid hex string: {e}")
        return None


def format_hex_display(data, bytes_per_line=16, bytes_per_group=2):
    """Format bytes for display in readable hex format"""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]

        # Group bytes
        hex_groups = []
        for j in range(0, len(chunk), bytes_per_group):
            group = chunk[j:j + bytes_per_group]
            hex_groups.append(group.hex())

        lines.append(' '.join(hex_groups))

    return '\n'.join(lines)


def run_single_query(sock, query_bytes, resolver_host, resolver_port):
    """Run a single DNS query and display results"""
    # Display query
    print(f"Query ({len(query_bytes)} bytes):")
    print(format_hex_display(query_bytes))
    print()

    # Send query
    send_query(sock, query_bytes, resolver_host, resolver_port)

    # Receive response
    response_bytes, server_addr = receive_response(sock, timeout=5.0)

    if response_bytes is None:
        print("No response (timeout)")
        return False
    else:
        # Display response
        print(f"Response ({len(response_bytes)} bytes):")
        print(format_hex_display(response_bytes))
        return True


def read_tests_file(filename):
    """
    Read tests from file. Format:
    - Lines starting with # are comments
    - Empty lines are ignored
    - Other lines are hex queries
    """
    tests = []

    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Try to parse as hex
                query_bytes = parse_hex_input(line)
                if query_bytes:
                    tests.append({
                        'line': line_num,
                        'hex': line,
                        'bytes': query_bytes
                    })
                else:
                    print(f"WARNING: Skipping invalid hex on line {line_num}")

        return tests
    except FileNotFoundError:
        print(f"ERROR: File '{filename}' not found")
        return None
    except Exception as e:
        print(f"ERROR reading file: {e}")
        return None


def run_tests_from_file(resolver_host, resolver_port, tests_file):
    """Run all tests from a file"""
    tests = read_tests_file(tests_file)

    if tests is None:
        return

    print(f"{'=' * 60}")
    print(f"Running {len(tests)} tests from {tests_file}")
    print(f"{'=' * 60}")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    passed = 0
    failed = 0

    try:
        for i, test in enumerate(tests):
            print(f"{'=' * 60}")
            print(f"Test {i} (line {test['line']})")
            print(f"{'=' * 60}")

            success = run_single_query(sock, test['bytes'], resolver_host, resolver_port)

            if success:
                passed += 1
            else:
                failed += 1

            print()

    finally:
        sock.close()

    # Summary
    print(f"{'=' * 60}")
    print(f"Test Summary: {passed} passed, {failed} failed (total: {len(tests)})")
    print(f"{'=' * 60}")


def main():
    # Parse command line arguments
    if len(sys.argv) != 4:
        print("Usage:")
        print("  Single query: python user.py <resolver_host> <resolver_port> <hex_query>")
        print("  Run tests:    python user.py <resolver_host> <resolver_port> <tests_file.txt>")
        print("\nExamples:")
        print("  python user.py localhost 9000 0000012000010000000000000866616365626f6f6b03636f6d0000010001")
        print("  python user.py localhost 9000 tests.txt")
        sys.exit(1)

    resolver_host = sys.argv[1]
    resolver_port = int(sys.argv[2])
    third_arg = sys.argv[3]

    # Check if third argument is a file
    if os.path.isfile(third_arg):
        # Run tests from file
        run_tests_from_file(resolver_host, resolver_port, third_arg)
    else:
        # Treat as hex query (original behavior)
        query_bytes = parse_hex_input(third_arg)

        if query_bytes is None:
            sys.exit(1)

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            run_single_query(sock, query_bytes, resolver_host, resolver_port)
        except Exception as e:
            print(f"ERROR: {e}")
        finally:
            sock.close()


if __name__ == "__main__":
    main()