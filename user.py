#!/usr/bin/env python3
"""
DNS Query Tool - sends queries from file or command line
"""

import sys
import socket
from dnsUtils import send_query, receive_response


def read_tests_file(filename):
    """
    Read test queries from file.
    Accumulates hex across multiple lines until blank line or EOF.
    """
    tests = []
    current_hex = []

    with open(filename, 'r') as f:
        for line in f:
            stripped = line.strip()

            # Blank line = end of current query
            if not stripped:
                if current_hex:
                    # Join all accumulated hex
                    full_hex = ''.join(current_hex)
                    tests.append(full_hex)
                    current_hex = []
                continue

            # Skip comment lines
            if stripped.startswith('#'):
                continue

            # Accumulate hex (strip all whitespace)
            hex_part = ''.join(stripped.split())
            current_hex.append(hex_part)

        # Don't forget last query if file doesn't end with blank line
        if current_hex:
            full_hex = ''.join(current_hex)
            tests.append(full_hex)

    return tests


def parse_hex_input(hex_string):
    """Convert hex string to bytes, handling various formats"""
    # Remove all whitespace
    cleaned = ''.join(hex_string.split())

    # Remove common prefixes/formatting
    cleaned = cleaned.replace('0x', '')
    cleaned = cleaned.replace('\\x', '')

    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        print(f"ERROR: Invalid hex string: {e}")
        return None


def run_single_query(host, port, query_bytes):
    """Send a single query and display results"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print(f"\nSending query: {query_bytes.hex()}")
        send_query(sock, query_bytes, host, port)

        response_bytes, addr = receive_response(sock, timeout=0.5)

        if response_bytes:
            print(f"Response from {addr}: {len(response_bytes)} bytes")
            print(f"Hex: {response_bytes.hex()}")
        else:
            print("No response (timeout)")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        sock.close()


def run_test_file(host, port, filename):
    """Run all tests from file"""
    tests = read_tests_file(filename)

    if not tests:
        print("No tests found in file")
        return

    print("=" * 60)
    print(f"Running {len(tests)} tests from {filename}")
    print("=" * 60)
    print()

    passed = 0
    failed = 0

    for i, hex_string in enumerate(tests):
        query_bytes = parse_hex_input(hex_string)

        if query_bytes is None:
            print(f"Test {i}: SKIP - Invalid hex")
            print(f"  Query: {hex_string}")
            failed += 1
            continue

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            send_query(sock, query_bytes, host, port)
            response_bytes, _ = receive_response(sock, timeout=0.5)

            if response_bytes:
                # Decode response to show D and X bytes
                response_display = response_bytes.hex()

                # Try to identify D and X bytes in readable format
                readable = []
                for byte in response_bytes:
                    if byte == ord('D'):
                        readable.append('D')
                    elif byte == ord('X'):
                        readable.append('X')
                    elif byte == ord('T'):
                        readable.append('T')
                    elif byte == ord('4'):
                        readable.append('4')
                    elif byte == ord('6'):
                        readable.append('6')
                    else:
                        readable.append(f'{byte:02x}')

                print(f"Test {i}: Response ({len(response_bytes)} bytes)")
                print(f"  Query:    {query_bytes.hex()}")
                print(f"  Response: {response_display}")
                print(f"  Decoded:  {' '.join(readable)}")
                passed += 1
            else:
                print(f"Test {i}: No response")
                print(f"  Query:    {query_bytes.hex()}")
                passed += 1

        except Exception as e:
            print(f"Test {i}: ERROR - {e}")
            print(f"  Query: {query_bytes.hex()}")
            failed += 1

        finally:
            sock.close()

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python user.py <host> <port> <hex_query>")
        print("  python user.py <host> <port> <test_file.txt>")
        print()
        print("Examples:")
        print("  python user.py localhost 9000 000001200001...")
        print("  python user.py localhost 9000 tests.txt")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    input_arg = sys.argv[3]

    # Check if input is a file
    try:
        with open(input_arg, 'r'):
            # It's a file
            run_test_file(host, port, input_arg)
    except FileNotFoundError:
        # It's a hex string
        query_bytes = parse_hex_input(input_arg)
        if query_bytes:
            run_single_query(host, port, query_bytes)
        else:
            print("ERROR: Not a valid file or hex string")
            sys.exit(1)


if __name__ == "__main__":
    main()