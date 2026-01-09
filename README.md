# Wallbleed Vulnerability Replication

A high-fidelity Python implementation of the Wallbleed vulnerability discovered in China's Great Firewall DNS injection infrastructure. This project replicates the memory disclosure flaw documented in the 2025 NDSS paper for educational and research purposes.

## What is Wallbleed?

Wallbleed is a memory disclosure vulnerability in the Great Firewall's DNS injection middleboxes. When parsing malformed DNS queries, the injector reads beyond packet boundaries due to insufficient bounds checking, leaking up to 124 bytes of process memory per response. This can expose fragments of other users' DNS queries, HTTP headers, and protocol signatures.

## Project Overview

This implementation provides:
- **Vulnerable DNS injector** that replicates the GFW's flawed parser behavior
- **Test harness** for systematic validation against the reference implementation
- **62 comprehensive test cases** covering normal queries, malformed probes, and edge cases
- **Safe simulation** using placeholder bytes instead of real memory leaks

## What We Built

### Core Components

```
wallbleed/
├── injector.py       # Vulnerable DNS injector (main implementation)
├── user.py           # Query generator and test harness
├── dnsUtils.py       # DNS packet utilities
├── tests.txt         # 62 test cases from blackbox.c
└── README.md         # This file
```

### Implementation Highlights

- **Vulnerable Parser**: Deliberately omits bounds checking when reading QNAME label lengths
- **Memory Buffer Simulation**: Safe replication using placeholder bytes (D, X, T, 4, 6)
- **Label Flattening**: Replicates GFW's behavior of treating dots and nulls as separators
- **Blocklist Matching**: 10 domains from the original Wallbleed study
- **Response Generation**: Byte-exact format matching the blackbox.c reference

## Quick Start

### Requirements

- Python 3.7 or higher
- No external dependencies (standard library only)
- Any OS (Linux, macOS, Windows, WSL)

### Running the Injector

**Terminal 1** - Start the injector:
```bash
python injector.py 9000
```

You'll see:
```
============================================================
DNS Injector (Vulnerable) - FIXED VERSION
============================================================
Port: 9000
Blocklist: 10 domains
✓ Blocklist works correctly
✓ Memory leak present (in QTYPE/QCLASS area)
============================================================

[INJECTOR] Listening on port 9000
```

**Terminal 2** - Send a test query:
```bash
python user.py localhost 9000 "000001200001000000000000023639026d75000001000001"
```

## Example Test Cases

### Example 1: Basic Blocked Domain

Query for `69.mu` (a blocked domain):

```bash
python user.py localhost 9000 "000001200001000000000000023639026d75000001000001"
```

**Expected:**
- Domain extracted: `69.mu`
- Blocklist match: YES
- Injection occurs
- No memory leaked (complete packet)

**Output:**
```
[QUERY] 69.mu from ('127.0.0.1', xxxxx)
[BLOCKED] 69.mu
[INJECTED] 55 bytes (digest: 0, leaked: 0)
```

---

### Example 2: Truncated Packet

Query for `69.mu` with missing QTYPE/QCLASS:

```bash
python user.py localhost 9000 "000001200001000000000000023639026d750000"
```

**Expected:**
-  Parser tries to read QTYPE/QCLASS beyond packet end
- 4 digest bytes leaked

**Output:**
```
[QUERY] 69.mu from ('127.0.0.1', xxxxx)
[BLOCKED] 69.mu
[INJECTED] 59 bytes (digest: 4, leaked: 0)
```

---

### Example 3: Maximum Memory Disclosure (Test 52)

Long domain with 0xFF overread trigger:

```bash
python user.py localhost 9000 "00000100000100000000000002616101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610161016101610134ff747400"
```

**Expected:**
-  0xFF byte triggers 255-byte overread
- 124 bytes total leaked (4 digest + 120 leaked)
- Matches `4.tt` on blocklist

**Output:**
```
[QUERY] aa.a.a...a.4.tt from ('127.0.0.1', xxxxx)
[BLOCKED] aa.a.a...a.4.tt
[INJECTED] 205 bytes (digest: 4, leaked: 120)
```

**Actual Test Output:**
```
Test 52: Response (205 bytes)
  Query:    00000100000100000000000002616101...
  Response: 0000818000010001000000000261610...
  Decoded:  00 00 81 80 ... 01 34 ff 74 74 00 D D D D c0 0c ... T T T T 00 04 4 4 4 4
```

---

### Example 4: Run All Tests

Run the complete test suite from `tests.txt`:

```bash
python user.py localhost 9000 tests.txt
```

**Expected:**
```
============================================================
Running 62 tests from tests.txt
============================================================

Test 0: Response (55 bytes)
  Query:    000001200001000000000000023639026d75000001000001
  Response: 00008180000100010000000002363902...

Test 1: Response (65 bytes)
  Query:    0000012000010000000000000866616365626f6f6b03636f6d0000010001
  Response: 0000818000010001000000000866616365...

... (60 more tests) ...

============================================================
Results: XX passed, XX failed
============================================================
```

## Understanding the Output

### Placeholder Bytes

The injector uses ASCII placeholders to safely represent leaked data:

| Byte | Meaning | Description |
|------|---------|-------------|
| `D` | **Digest bytes** | From QTYPE/QCLASS read past packet boundary |
| `X` | **Leaked bytes** | From label overreads into adjacent memory |
| `T` | **TTL** | Placeholder for Time-To-Live field |
| `4` | **IPv4** | Fake IPv4 address (4 bytes of 0x34) |
| `6` | **IPv6** | Fake IPv6 address (16 bytes of 0x36) |

**Example:**
```
Response: ...DDDDXXXXXXXXXXX...TTTT...4444
           ↑   ↑            ↑   ↑    ↑
           │   └─ 11 leaked │   │    └─ Fake IPv4
           │      bytes      │   └─ TTL placeholder
           └─ 4 digest       └─ Answer section starts
              bytes
```

Total memory disclosed: 4 + 11 = 15 bytes

### Injector Log Format

```
[QUERY] domain from (ip, port)
[BLOCKED/ALLOWED] domain
[INJECTED] size bytes (digest: X, leaked: Y)
```

- **QUERY**: Shows parsed domain name
- **BLOCKED**: Domain matched blocklist → injection occurs
- **ALLOWED**: Domain not blocked → no response
- **INJECTED**: Response sent with memory disclosure counts

## How It Works

### The Vulnerability

The GFW's DNS parser has a critical flaw in how it reads QNAME labels:

```python
# VULNERABLE CODE (simplified)
length = data[pos]          # Read label length byte
pos += 1

# Read 'length' bytes
for i in range(length):
    byte_val = data[pos + i]
    label_bytes.append(byte_val)

# BUG: Advance by full length even if packet ended
pos += length  # ← This causes overread!
```

If `length = 0xFF` (255) but only 10 bytes remain in the packet, the position still advances by 255, causing subsequent reads to access memory beyond the packet boundary.

### Label Flattening

The GFW treats dots (`.`) and null bytes (`\x00`) within labels as separators:

```
Query: \x08facebook\xffcom
       └─ 8 bytes  └─ 255 bytes (overread!)

Parser reads "facebook", then 255 bytes including "com" and leaked memory.
Encounters null byte → truncates → extracts "facebook.com"
Matches blocklist entry → injection occurs
```

### Memory Disclosure

Two types of leaked bytes:

1. **Digest bytes**: From QTYPE/QCLASS (4 bytes) read beyond packet end
2. **Leaked bytes**: From label overreads into adjacent memory

Total capped at 124 bytes (matching documented GFW behavior).

## Blocklist

The injector blocks these domains (from the Wallbleed paper):

- `69.mu`
- `3.tt`, `4.tt`
- `facebook.com`, `www.facebook.com`
- `google.com`, `www.google.com`
- `rsf.org`, `www.rsf.org`
- `shadowvpn.com`

## Validation Results

Our implementation was validated against `blackbox.c`, the reference implementation from the Wallbleed researchers.

### Test Coverage

- **62 test cases** covering 8 categories:
  - Basic functionality (8 tests)
  - Label overread (3 tests)
  - Label flattening (3 tests)
  - Truncated packets (15 tests)
  - Long domain names (14 tests)
  - Maximum overread (13 tests)
  - Edge cases (6 tests)

## File Descriptions

### injector.py

The vulnerable DNS injector that replicates the Wallbleed flaw.

**Key functions:**
- `parse_dns_query_vulnerable()` - Deliberately flawed parser with no bounds checking
- `build_fake_response()` - Generates forged DNS responses with placeholder leaked bytes
- `is_blocked()` - Checks domain against blocklist

**How to use:**
```bash
python injector.py <port>
```

Runs indefinitely until stopped with Ctrl+C.

---

### user.py

Query generator and test harness.

**Two modes:**

**Single query:**
```bash
python user.py <host> <port> <hex_query>
```

**Batch testing:**
```bash
python user.py <host> <port> <test_file.txt>
```

**Features:**
- Parses hex queries from command line or file
- Sends queries via UDP
- Displays responses with decoded placeholder bytes
- Tracks pass/fail statistics

---

### dnsUtils.py

Shared utilities for DNS packet manipulation.

**Key functions:**
- `encode_qname(domain)` - Converts domain to DNS label format
- `build_dns_query(domain, txid)` - Constructs complete DNS query
- `send_query()` - Sends UDP packets
- `receive_response()` - Receives responses with timeout
- `format_hex()` - Formats bytes for display

---

### tests.txt

62 test cases from the `blackbox.c` reference implementation.

**Format:**
```
# Comment lines start with #
000001200001000000000000023639026d75000001000001

# Blank lines separate test cases
0000012000010000000000000866616365626f6f6b03636f6d0000010001
```

Each line is a DNS query in hexadecimal format.

## Creating Custom Queries

### Basic DNS Query Structure

```
Header (12 bytes):
  00 00       - Transaction ID
  01 20       - Flags (standard query)
  00 01       - 1 question
  00 00       - 0 answers
  00 00       - 0 authority
  00 00       - 0 additional

Question:
  QNAME (variable):
    Length byte + label bytes + ... + 00 (terminator)
  
  00 01       - QTYPE (A record)
  00 01       - QCLASS (IN)
```

### Example: Query for "test.com"

```
Header:
  0000 0120 0001 0000 0000 0000

QNAME:
  04           - Length of "test" (4)
  74657374     - "test" in ASCII
  03           - Length of "com" (3)
  636f6d       - "com" in ASCII
  00           - Terminator

QTYPE/QCLASS:
  0001 0001

Full query:
00000120000100000000000004746573740303636f6d000001000001
```

### Triggering Overread

Replace terminator with large length value:

```
Malformed:
00000120000100000000000004746573740303636f6dff

The 'ff' tells parser to read 255 bytes, causing overread!
```

## Troubleshooting

### No response received

**Check:**
1. Is injector running? Look for "Listening on port" message
2. Do ports match? User and injector must use same port
3. Is domain blocked? Only blocked domains trigger injection
4. Firewall blocking UDP? Try `sudo` or check firewall rules

### "Address already in use"

Another process is using the port. Either:
- Stop the other process
- Use a different port: `python injector.py 9002`

### Invalid hex string

**Common issues:**
- Odd number of hex digits (must be even)
- Contains `0x` prefix (remove it)
- Invalid characters (only 0-9, a-f, A-F allowed)

## Educational Value

This implementation demonstrates:
- How memory disclosure vulnerabilities work
- The importance of bounds checking in parsers
- DNS injection techniques used in censorship
- Cross-user data leakage in shared infrastructure
- Validation methodologies for security research

**Safe for learning:** Uses placeholder bytes, not real memory access.

## Project Contributions

### Implementation
**Abdullah Hariry** - Complete implementation of all system components
- Vulnerable DNS parser with intentional buffer overread
- DNS injection system and response generation
- Test framework and validation harness
- All Python code (injector.py, user.py, dnsUtils.py)
- Test case development and validation

### Documentation
**Avishi Srivastava** - Project documentation and reporting
- README documentation
- Report structure and coordination

**Non-contributing members:** Yashaswini Balasubramaniam, Dawoud Aboalsaud, Aaser Alsulimani

## References

- **Wallbleed Paper**: Fan et al., "Wallbleed: Memory Disclosure in the Great Firewall's DNS Injection Infrastructure," NDSS 2025
- **Reference Implementation**: blackbox.c from the Wallbleed study

## License

This implementation is provided for educational and research purposes only. The code demonstrates a vulnerability for learning purposes and should not be used maliciously.

## Acknowledgments

This project was completed as part of COMP3207: Web and Cloud-Based Security at the University of Southampton.

---

**For the full technical report, see:** `wallbleed_report.pdf`

**For questions or issues:** Refer to the project documentation or contact the development team.
