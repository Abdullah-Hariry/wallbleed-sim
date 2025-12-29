#!/usr/bin/env python3
"""
Simple DNS Injector (without scapy)

Listens on the same port as queries are sent to and races to respond first.
This is a simpler approach that doesn't require packet sniffing.

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

def parse_dns_query(data):
    """Parse DNS query to extract domain"""
    if len(data) < 12:
        return None, None, None, None

    # Transaction ID
    txid = int.from_bytes(data[0:2], 'big')

    # Parse QNAME
    labels = []
    pos = 12

    while pos < len(data):
        length = data[pos]
        pos += 1

        if length == 0:
            break

        if pos + length > len(data):
            break

        label = data[pos:pos + length].decode('ascii', errors='ignore')
        labels.append(label)
        pos += length

    domain = '.'.join(labels)

    # Get QTYPE and QCLASS
    if pos + 4 <= len(data):
        qtype = int.from_bytes(data[pos:pos + 2], 'big')
        qclass = int.from_bytes(data[pos + 2:pos + 4], 'big')
        question_bytes = data[12:pos + 4]
    else:
        qtype = 1
        qclass = 1
        question_bytes = data[12:]

    return txid, domain, qtype, question_bytes


def is_blocked(domain):
    """Check if domain is on blocklist"""
    domain_lower = domain.lower().rstrip('.')

    if domain_lower in BLOCKLIST:
        return True

    for blocked in BLOCKLIST:
        if domain_lower.endswith('.' + blocked):
            return True

    return False


def build_fake_response(txid, question_bytes, fake_ip='127.0.0.1'):
    """Build fake DNS response"""
    response = bytearray()

    # Header
    response.extend(txid.to_bytes(2, 'big'))
    response.extend(b'\x81\x80')  # Flags
    response.extend(b'\x00\x01')  # QDCOUNT = 1
    response.extend(b'\x00\x01')  # ANCOUNT = 1
    response.extend(b'\x00\x00')  # NSCOUNT = 0
    response.extend(b'\x00\x00')  # ARCOUNT = 0

    # Question section
    response.extend(question_bytes)

    # Answer section
    response.extend(b'\xc0\x0c')  # Compression pointer
    response.extend(b'\x00\x01')  # TYPE = A
    response.extend(b'\x00\x01')  # CLASS = IN
    response.extend(b'\x00\x00\x00\x3c')  # TTL = 60
    response.extend(b'\x00\x04')  # RDLENGTH = 4

    # Fake IP
    ip_bytes = bytes([int(x) for x in fake_ip.split('.')])
    response.extend(ip_bytes)

    return bytes(response)


def injector_thread(listen_port):
    """Injector that listens and responds to queries"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', listen_port))

    print(f"[INJECTOR] Listening on port {listen_port}")
    print()

    while True:
        try:
            data, addr = sock.recvfrom(4096)

            # Parse query
            txid, domain, qtype, question_bytes = parse_dns_query(data)

            if domain is None:
                continue

            print(f"[QUERY] {domain} from {addr}")

            # Check blocklist
            if is_blocked(domain):
                print(f"[BLOCKED] {domain} is on blocklist!")

                # Build and send fake response IMMEDIATELY
                fake_response = build_fake_response(txid, question_bytes, '127.0.0.1')
                sock.sendto(fake_response, addr)

                print(f"[INJECTED] Sent fake response: {domain} -> 127.0.0.1")
                print()
            else:
                print(f"[ALLOWED] {domain} not on blocklist")
                print()

        except Exception as e:
            print(f"[ERROR] {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python injector_simple.py <listen_port>")
        print("Example: python injector_simple.py 9000")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    print("=" * 60)
    print("Simple DNS Injector - Wallbleed Simulation")
    print("=" * 60)
    print(f"Port: {listen_port}")
    print(f"Blocklist: {len(BLOCKLIST)} domains")
    print()
    print("Blocklisted domains:")
    for domain in sorted(BLOCKLIST):
        print(f"  - {domain}")
    print("=" * 60)
    print()

    try:
        injector_thread(listen_port)
    except KeyboardInterrupt:
        print("\n\nStopping injector...")


if __name__ == "__main__":
    main()