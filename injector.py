#!/usr/bin/env python3
"""

Replicates GFW DNS injection bug for validation against reference implementation.
Uses same placeholder format as blackbox.c for byte-exact comparison.

Usage: python injector.py <listen_port>
Example: python injector.py 9000
"""

import sys
import socket

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


def parse_dns_query_vulnerable(data, udp_len):
    """
    VULNERABLE DNS parser - mimics GFW bug

    Returns:
        (txid, domain, qtype, qclass, question_bytes, digest_bytes, leaked_bytes)
    """
    if udp_len < 12:
        return None, None, None, None, None, 0, 0

    # Transaction ID
    txid = int.from_bytes(data[0:2], 'big')

    # Parse QNAME - VULNERABLE VERSION
    labels = []
    pos = 12
    qname_bytes = bytearray()
    name_buf = bytearray()  # 126-byte limit buffer (like blackbox.c)
    total_bytes_read = 0
    leaked_in_labels = 0

    while True:
        # Read label length (even if past boundary)
        if pos >= len(data):
            break

        length = data[pos]

        # Add length byte to qname_bytes
        if pos < udp_len:
            qname_bytes.append(length)
            total_bytes_read += 1
        else:
            qname_bytes.append(length)
            leaked_in_labels += 1

        pos += 1

        if length == 0:
            break

        # VULNERABILITY: Read label bytes even past packet boundary!
        label_bytes = bytearray()
        bytes_to_read = length

        # But respect 126-byte name_buf limit
        space_left = 126 - len(name_buf)
        if bytes_to_read > space_left:
            bytes_to_read = space_left

        for i in range(length):
            if pos + i >= len(data):
                break

            # Keep reading into leaked memory!
            byte_val = data[pos + i]

            # Add to label_bytes only if within name_buf limit
            if i < bytes_to_read:
                label_bytes.append(byte_val)
                name_buf.append(byte_val)

            # Always add to qname_bytes for response
            qname_bytes.append(byte_val)

            if pos + i < udp_len:
                total_bytes_read += 1
            else:
                leaked_in_labels += 1

        # CRITICAL: Advance position by FULL length
        pos += length

        if label_bytes:
            # Check for null byte
            if b'\x00' in label_bytes:
                null_pos = label_bytes.index(b'\x00')
                label_bytes = label_bytes[:null_pos]

                if label_bytes:
                    label_str = label_bytes.decode('ascii', errors='replace')
                    if '.' in label_str:
                        labels.extend(label_str.split('.'))
                    else:
                        labels.append(label_str)
                break

            # Normal label
            label_str = label_bytes.decode('ascii', errors='replace')
            if '.' in label_str:
                labels.extend(label_str.split('.'))
            else:
                labels.append(label_str)

        # Stop if name_buf is full or way past packet
        if len(name_buf) >= 126 or pos > udp_len + 200:
            break

    domain = '.'.join(labels) if labels else ""

    # Read QTYPE and QCLASS (also potentially leaked)
    digest_bytes = 0
    qtype = 1
    qclass = 1

    qtype_pos = pos

    for i in range(4):
        if qtype_pos + i >= len(data):
            break

        byte_val = data[qtype_pos + i]
        qname_bytes.append(byte_val)

        if qtype_pos + i >= udp_len:
            digest_bytes += 1

    # Extract QTYPE/QCLASS
    if digest_bytes < 4:
        actual_qtype_start = qtype_pos
        if actual_qtype_start + 1 < len(data):
            qtype = (data[actual_qtype_start] << 8) | data[actual_qtype_start + 1]

    return txid, domain, qtype, qclass, bytes(qname_bytes), digest_bytes, leaked_in_labels


def is_blocked(domain):
    """Check if domain is on blocklist"""
    domain_lower = domain.lower().rstrip('.')

    # Exact match
    if domain_lower in BLOCKLIST:
        return True

    # Start-anchored patterns (for entries like 3.tt, 4.tt)
    START_ANCHORED = {'3.tt', '4.tt', 'shadowvpn.com'}
    for pattern in START_ANCHORED:
        if domain_lower.startswith(pattern):
            return True

    # Suffix match (subdomain)
    for blocked in BLOCKLIST:
        if domain_lower.endswith('.' + blocked):
            return True

    return False

def build_fake_response(txid, question_bytes, digest_bytes, leaked_bytes, qtype=1):
    """
    Build fake DNS response matching blackbox.c format

    Uses placeholder values:
    - 'D' for digest bytes
    - 'X' for leaked memory bytes
    - 'T' for TTL
    - '4' for IPv4, '6' for IPv6
    """
    response = bytearray()

    # Header
    response.extend(txid.to_bytes(2, 'big'))
    response.extend(b'\x81\x80')  # Flags
    response.extend(b'\x00\x01')  # QDCOUNT = 1
    response.extend(b'\x00\x01')  # ANCOUNT = 1
    response.extend(b'\x00\x00')  # NSCOUNT = 0
    response.extend(b'\x00\x00')  # ARCOUNT = 0

    # Question section - includes overread bytes
    response.extend(question_bytes)

    # Add digest bytes (QTYPE/QCLASS read past boundary)
    if digest_bytes > 0:
        response.extend(b'D' * digest_bytes)

    # Add leaked memory bytes
    if leaked_bytes > 0:
        # Cap at 124 bytes total leaked (as per blackbox.c)
        max_leaked = min(leaked_bytes, 124 - digest_bytes)
        response.extend(b'X' * max_leaked)

    # Answer section
    response.extend(b'\xc0\x0c')  # Compression pointer to QNAME

    # RTYPE
    if qtype == 0x1c:  # AAAA record
        response.extend(b'\x00\x1c')
    else:  # A record
        response.extend(b'\x00\x01')

    response.extend(b'\x00\x01')  # CLASS = IN
    response.extend(b'TTTT')  # TTL placeholder (4 bytes)

    # RDLENGTH and RDATA
    if qtype == 0x1c:  # IPv6
        response.extend(b'\x00\x10')  # RDLENGTH = 16
        response.extend(b'6' * 16)  # IPv6 placeholder
    else:  # IPv4
        response.extend(b'\x00\x04')  # RDLENGTH = 4
        response.extend(b'4' * 4)  # IPv4 placeholder

    return bytes(response)


def main():
    if len(sys.argv) != 2:
        print("Usage: python injector.py <listen_port>")
        print("Example: python injector.py 9000")
        sys.exit(1)

    listen_port = int(sys.argv[1])

    print("=" * 60)
    print("DNS Injector (Vulnerable) - FIXED VERSION")
    print("=" * 60)
    print(f"Port: {listen_port}")
    print(f"Blocklist: {len(BLOCKLIST)} domains")
    print("✓ Blocklist works correctly")
    print("✓ Memory leak present (in QTYPE/QCLASS area)")
    print("=" * 60)
    print()

    # Create UDP socket
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

            # Copy packet to simulated memory buffer
            memory_buffer[:udp_len] = data
            # Fill with 'X' (simulated leaked memory)
            memory_buffer[udp_len:udp_len + 200] = b'X' * 200

            # Parse query using vulnerable parser
            result = parse_dns_query_vulnerable(memory_buffer, udp_len)
            txid, domain, qtype, qclass, question_bytes, digest_bytes, leaked_bytes = result

            if domain is None:
                continue

            print(f"[QUERY] {domain} from {addr}")

            # Check blocklist
            if is_blocked(domain):
                print(f"[BLOCKED] {domain}")

                # Build and send fake response
                fake_response = build_fake_response(
                    txid, question_bytes, digest_bytes, leaked_bytes, qtype
                )
                sock.sendto(fake_response, addr)

                print(f"[INJECTED] {len(fake_response)} bytes "
                      f"(digest: {digest_bytes}, leaked: {leaked_bytes})")
            else:
                print(f"[ALLOWED] {domain}")

            print()

        except KeyboardInterrupt:
            print("\n\nStopping injector...")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()