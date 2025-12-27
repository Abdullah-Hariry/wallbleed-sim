import socket
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