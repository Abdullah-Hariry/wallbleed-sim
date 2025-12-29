#!/usr/bin/env python3
import sys
import socket

def parse_dns_query(data: bytes):
    txid = int.from_bytes(data[0:2], 'big')

    # Parse QNAME starting at byte 12
    labels = []
    pos = 12

    while pos < len(data):
        length = data[pos]
        pos += 1

        if length == 0:
            break

        label = data[pos:pos + length].decode('ascii')
        labels.append(label)
        pos += length

    domain = '.'.join(labels)

    # Extract QTYPE and QCLASS (4 bytes after QNAME terminator)
    qtype = int.from_bytes(data[pos:pos + 2], 'big')
    qclass = int.from_bytes(data[pos + 2:pos + 4], 'big')

    # Question bytes = QNAME + QTYPE + QCLASS (from byte 12 to pos+4)
    question_bytes = data[12:pos + 4]

    return txid, domain, qtype, qclass, question_bytes


def build_dns_response(txid: int, question_bytes: bytes, ip: str) -> bytes:
    response = bytearray()

    # Header (12 bytes)
    response.extend(txid.to_bytes(2, 'big'))  # Transaction ID
    response.extend(b'\x81\x80')  # Flags: response, recursion available
    response.extend(b'\x00\x01')  # QDCOUNT = 1
    response.extend(b'\x00\x01')  # ANCOUNT = 1
    response.extend(b'\x00\x00')  # NSCOUNT = 0
    response.extend(b'\x00\x00')  # ARCOUNT = 0

    # Question section (same as query)
    response.extend(question_bytes)

    # Answer section
    response.extend(b'\xc0\x0c')  # Compression pointer to byte 12 (QNAME)
    response.extend(b'\x00\x01')  # TYPE = A
    response.extend(b'\x00\x01')  # CLASS = IN
    response.extend(b'\x00\x00\x00\x3c')  # TTL = 60 seconds
    response.extend(b'\x00\x04')  # RDLENGTH = 4

    # RDATA (IP address)
    ip_bytes = bytes([int(x) for x in ip.split('.')])
    response.extend(ip_bytes)

    return bytes(response)


def main():
    if len(sys.argv) != 2:
        print("Usage: python resolver.py <listen_port>")
        print("Example: python resolver.py 9000")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    # DNS cache - domain to IP mapping
    dns_cache = {
        'facebook.com': '127.0.0.1',
        'www.example.com': '93.184.216.34',
        'google.com': '142.250.185.78',
        'rsf.org': '127.0.0.1',
        '3.tt': '127.0.0.1',
        '4.tt': '127.0.0.1',
    }

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', listen_port))

    print(f"DNS Resolver listening on port {listen_port}")
    print(f"Cached domains: {list(dns_cache.keys())}")
    print()

    try:
        while True:
            # Receive query
            data, client_addr = sock.recvfrom(4096)

            print(f"Received {len(data)} bytes from {client_addr}")
            print(f"Query: {data.hex()}")

            # Parse query
            txid, domain, qtype, qclass, question_bytes = parse_dns_query(data)
            print(f"Domain: {domain}")

            # Look up in cache
            ip = dns_cache.get(domain.lower(), '127.0.0.1')
            print(f"IP: {ip}")

            # Build response
            response = build_dns_response(txid, question_bytes, ip)
            print(f"Response ({len(response)} bytes): {response.hex()}")

            # Send response
            sock.sendto(response, client_addr)
            print(f"Sent response to {client_addr}")
            print()

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()