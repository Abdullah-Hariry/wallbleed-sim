"""
Parser for blackbox-tests.inc format
"""
import re

# Macro definitions from blackbox.c
TTL = b"TTTT"
A_SUFFIX = b"\xc0\x0c\x00\x01\x00\x01" + TTL + b"\x00\x04" + b"4444"
AAAA_SUFFIX = b"\xc0\x0c\x00\x1c\x00\x01" + TTL + b"\x00\x10" + b"6666666666666666"

def parse_c_string(s):
    """Parse C string literal with \\x escapes to bytes"""
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]

    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i + 1] == 'x' and i + 3 < len(s):
                # Hex escape: \xNN
                hex_str = s[i + 2:i + 4]
                try:
                    result.append(int(hex_str, 16))
                except ValueError:
                    result.append(ord(s[i]))
                i += 4
            else:
                # Other escapes
                result.append(ord(s[i + 1]))
                i += 2
        else:
            result.append(ord(s[i]))
            i += 1

    return bytes(result)


def parse_single_test(content):
    """Parse a single TEST or TEST_UDPLEN from content"""
    # Remove comments
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)

    # Extract function call and determine type from the actual match
    match = re.search(r'(TEST_UDPLEN|TEST)\s*\((.*)\)', content, re.DOTALL)
    if not match:
        return None

    test_type = match.group(1)  # Either 'TEST' or 'TEST_UDPLEN'
    inner = match.group(2)
    is_udplen = (test_type == 'TEST_UDPLEN')  # Check actual function name

    # Split arguments by commas at depth 0
    parts = []
    current = []
    depth = 0
    in_string = False

    for char in inner:
        if char == '"' and (not current or current[-1] != '\\'):
            in_string = not in_string
        elif not in_string:
            if char in '([{':
                depth += 1
            elif char in ')]}':
                depth -= 1
            elif char == ',' and depth == 0:
                parts.append(''.join(current).strip())
                current = []
                continue
        current.append(char)

    if current:
        parts.append(''.join(current).strip())

    if len(parts) < 3:
        return None

    # Parse based on TEST vs TEST_UDPLEN
    if is_udplen:
        query_str = parts[0]
        udp_increment = int(parts[1].strip())
        uses_digest = 'true' in parts[2].lower()
        expected_str = parts[3] if len(parts) > 3 else '""'
    else:
        query_str = parts[0]
        udp_increment = 0
        uses_digest = 'true' in parts[1].lower()
        expected_str = parts[2] if len(parts) > 2 else '""'

    # Parse query bytes from concatenated strings
    query_bytes = bytearray()
    for string_match in re.findall(r'"[^"]*"', query_str):
        query_bytes.extend(parse_c_string(string_match))

    # Parse expected response
    expected_bytes = bytearray()
    expected_str = expected_str.replace('A_SUFFIX', '__A_SUFFIX__')
    expected_str = expected_str.replace('AAAA_SUFFIX', '__AAAA_SUFFIX__')

    for part in re.findall(r'"[^"]*"|__[A-Z_]+__', expected_str):
        if part == '__A_SUFFIX__':
            expected_bytes.extend(A_SUFFIX)
        elif part == '__AAAA_SUFFIX__':
            expected_bytes.extend(AAAA_SUFFIX)
        elif part.startswith('"'):
            expected_bytes.extend(parse_c_string(part))

    return {
        'query': bytes(query_bytes),
        'query_len': len(query_bytes),
        'udp_len': len(query_bytes) + udp_increment,
        'uses_digest': uses_digest,
        'expected': bytes(expected_bytes) if expected_bytes else None
    }


def parse_blackbox_tests(filename):
    """Read and parse all tests from blackbox-tests.inc"""
    with open(filename, 'r') as f:
        content = f.read()

    tests = []
    lines = content.split('\n')
    current_test = []
    in_test = False
    paren_count = 0

    for line in lines:
        # Skip comment-only lines
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue

        # Look for start of TEST
        if 'TEST' in line and '(' in line and not in_test:
            in_test = True
            current_test = [line]
            paren_count = line.count('(') - line.count(')')
        elif in_test:
            current_test.append(line)
            paren_count += line.count('(') - line.count(')')

            # Check if test is complete
            if paren_count <= 0:
                test_content = '\n'.join(current_test)
                test = parse_single_test(test_content)
                if test:
                    tests.append(test)
                in_test = False
                current_test = []
                paren_count = 0

    return tests