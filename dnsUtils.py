import socket
def format_hex(data: bytes, group_size: int = 2, groups_per_line: int = 8) -> str:
    """
    Format bytes as readable hex with spacing

    Args:
        data: Bytes to format
        group_size: Bytes per group (default 2)
        groups_per_line: Groups per line (default 8)

    Returns:
        Formatted hex string
    """
    hex_str = data.hex()
    groups = [hex_str[i:i + group_size * 2] for i in range(0, len(hex_str), group_size * 2)]

    lines = []
    for i in range(0, len(groups), groups_per_line):
        line = ' '.join(groups[i:i + groups_per_line])
        lines.append(line)

    return '\n'.join(lines)


def encode_qname(domain: str) -> bytes:
    """
    Encode a domain name into DNS QNAME format (label-length format)

    Args:
        domain: Domain name as string (e.g., "www.example.com")

    Returns:
        Encoded QNAME as bytes
    """
    result = bytearray()
    labels = domain.split('.')

    for label in labels:
        label_bytes = label.encode('ascii')
        result.append(len(label_bytes))
        result.extend(label_bytes)

    result.append(0)
    return bytes(result)


def build_dns_query(domain: str, txid: int = 0x0000) -> bytes:
    """
    Build a full DNS query packet with header

    Based on blackbox test case format:
    Header (12 bytes):
        - Transaction ID (2 bytes)
        - Flags (2 bytes): 0x0120 for standard query
        - QDCOUNT (2 bytes): 0x0001 (1 question)
        - ANCOUNT (2 bytes): 0x0000 (0 answers)
        - NSCOUNT (2 bytes): 0x0000 (0 authority)
        - ARCOUNT (2 bytes): 0x0000 (0 additional)
    Question section:
        - QNAME (variable)
        - QTYPE (2 bytes): 0x0001 (A record)
        - QCLASS (2 bytes): 0x0001 (IN)

    Args:
        domain: Domain to query
        txid: Transaction ID (default 0x0000)

    Returns:
        Complete DNS query packet as bytes
    """
    query = bytearray()

    # Header (12 bytes)
    query.extend(txid.to_bytes(2, 'big'))  # Transaction ID
    query.extend(b'\x01\x20')  # Flags: standard query
    query.extend(b'\x00\x01')  # QDCOUNT = 1
    query.extend(b'\x00\x00')  # ANCOUNT = 0
    query.extend(b'\x00\x00')  # NSCOUNT = 0
    query.extend(b'\x00\x00')  # ARCOUNT = 0

    # Question section
    query.extend(encode_qname(domain))  # QNAME
    query.extend(b'\x00\x01')  # QTYPE = A (IPv4 address)
    query.extend(b'\x00\x01')  # QCLASS = IN (Internet)

    return bytes(query)


def send_query(sock, query_bytes: bytes, resolver_host: str, resolver_port: int):
    """
    Send a DNS query packet via UDP

    Args:
        sock: UDP socket to send from
        query_bytes: The encoded DNS query (QNAME bytes)
        resolver_host: Target host (IP or hostname)
        resolver_port: Target UDP port

    Returns:
        Number of bytes sent
    """
    return sock.sendto(query_bytes, (resolver_host, resolver_port))


def receive_response(sock, timeout: float = 30.0):
    """
    Receive a DNS response via UDP

    Args:
        sock: UDP socket to receive from
        timeout: How long to wait for response (seconds)

    Returns:
        Tuple of (response_bytes, server_address) or (None, None) on timeout
    """
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(4096)
        return data, addr
    except socket.timeout:
        return None, None