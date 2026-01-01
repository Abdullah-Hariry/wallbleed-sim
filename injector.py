#!/usr/bin/env python3
"""
DNS Injector with Wallbleed Vulnerability

Simulates GFW DNS injection with the Wallbleed buffer overread bug.
No bounds checking - reads past packet boundary and leaks memory.

Usage: python injector.py <listen_port>
Example: python injector.py 9000
"""

import sys
import socket
import threading

# Blocklist from Wallbleed paper
BLOCKLIST = {
    'facebook.com',
    'www.facebook.com',
    'rsf.org',
    'www.rsf.org',
    '3.tt',
    '4.tt',
    'google.com',
    'www.google.com',
    '69.mu',
    'shadowvpn.com',
}


def parse_dns_query(data, udp_len):
    """
    VULNERABLE DNS parser - mimics GFW bug

    No bounds checking - reads past packet boundary
    """
    if udp_len < 12:
        return None, None, None, None, None, 0

    # Transaction ID
    txid = int.from_bytes(data[0:2], 'big')

    # Parse QNAME - VULNERABLE VERSION
    labels = []
    pos = 12
    qname_bytes = bytearray()
    overread_count = 0

    while True:
        # BUG: No bounds checking
        if pos >= len(data):
            break

        length = data[pos]
        qname_bytes.append(length)
        pos += 1

        # Track if we've gone past UDP packet length
        if pos > udp_len:
            overread_count = pos - udp_len

        if length == 0:
            break

        # BUG: Read label bytes without bounds checking
        label_bytes = bytearray()
        for i in range(length):
            if pos + i >= len(data):
                break

            byte_val = data[pos + i]
            label_bytes.append(byte_val)
            qname_bytes.append(byte_val)

            if pos + i >= udp_len:
                overread_count += 1

        if label_bytes:
            label_str = label_bytes.decode('ascii', errors='replace')

            # Flatten the label (GFW blocklist matching)
            # Both dots and nulls are treated as separators
            if b'\x00' in label_bytes or b'.' in label_bytes:
                # Split on both null and dot
                parts = label_str.replace('\x00', '.').split('.')
                # Filter out empty parts
                parts = [p for p in parts if p]
                labels.extend(parts)
                # If we found a null, stop parsing
                if b'\x00' in label_bytes:
                    break
            else:
                labels.append(label_str)

        pos += length

        if pos > udp_len + 200:
            break

    domain = '.'.join(labels) if labels else ""

    # Get QTYPE and QCLASS
    if pos + 4 <= len(data):
        qtype = int.from_bytes(data[pos:pos + 2], 'big')
        qclass = int.from_bytes(data[pos + 2:pos + 4], 'big')
        qname_bytes.extend(data[pos:pos + 4])
    else:
        qtype = 1
        qclass = 1

    return txid, domain, qtype, qclass, bytes(qname_bytes), overread_count


def is_blocked(domain):
    """Check if domain is on blocklist"""
    domain_lower = domain.lower().rstrip('.')

    if domain_lower in BLOCKLIST:
        return True

    for blocked in BLOCKLIST:
        if domain_lower.endswith('.' + blocked):
            return True

    return False


def build_fake_response(txid, question_bytes, overread_bytes, fake_ip='127.0.0.1'):
    """Build fake DNS response with leaked memory"""
    response = bytearray()

    # Header
    response.extend(txid.to_bytes(2, 'big'))
    response.extend(b'\x81\x80')
    response.extend(b'\x00\x01')
    response.extend(b'\x00\x01')
    response.extend(b'\x00\x00')
    response.extend(b'\x00\x00')

    # Question section - includes overread bytes
    response.extend(question_bytes)

    # Answer section
    response.extend(b'\xc0\x0c')
    response.extend(b'\x00\x01')
    response.extend(b'\x00\x01')
    response.extend(b'\x00\x00\x00\x3c')
    response.extend(b'\x00\x04')

    # Fake IP
    ip_bytes = bytes([int(x) for x in fake_ip.split('.')])
    response.extend(ip_bytes)

    # Add leaked memory (simulated as 'X' bytes)
    if overread_bytes > 0:
        leaked_memory = b'X' * min(overread_bytes, 124)
        response.extend(leaked_memory)

    return bytes(response)


def injector_thread(listen_port):
    """Injector that listens and responds to queries"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', listen_port))

    print(f"[INJECTOR] Listening on port {listen_port}")
    print()

    # Simulate memory buffer with leaked data
    memory_buffer = bytearray(4096)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            udp_len = len(data)

            # Copy packet to simulated memory buffer with "leaked" data after it
            memory_buffer[:udp_len] = data
            memory_buffer[udp_len:udp_len + 200] = b'X' * 200

            # Parse query using vulnerable parser
            txid, domain, qtype, qclass, question_bytes, overread = parse_dns_query(memory_buffer, udp_len)

            if domain is None:
                continue

            print(f"[QUERY] {domain} from {addr}")

            # Check blocklist
            if is_blocked(domain):
                print(f"[BLOCKED] {domain}")

                # Build and send fake response with leaked memory
                fake_response = build_fake_response(txid, question_bytes, overread, '127.0.0.1')
                sock.sendto(fake_response, addr)

                if overread > 0:
                    print(f"[INJECTED] {len(fake_response)} bytes (leaked: {overread} bytes)")
                else:
                    print(f"[INJECTED] {len(fake_response)} bytes")
            else:
                print(f"[ALLOWED] {domain}")

            print()

        except Exception as e:
            print(f"[ERROR] {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python injector.py <listen_port>")
        print("Example: python injector.py 9000")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    print("=" * 60)
    print("DNS Injector (Vulnerable)")
    print("=" * 60)
    print(f"Port: {listen_port}")
    print(f"Blocklist: {len(BLOCKLIST)} domains")
    print("=" * 60)
    print()

    try:
        injector_thread(listen_port)
    except KeyboardInterrupt:
        print("\n\nStopping injector...")


if __name__ == "__main__":
    main()