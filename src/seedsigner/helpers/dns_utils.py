"""
DNS packet signing utilities for BEP44.

Supports DNS packet format (Pkarr encoding) for publishing DNS records to the
Mainline DHT using Ed25519 public keys as domain identifiers.

BEP44 Value Format (DNS Packet / SignedPacket):
    Bytes 0-63:   Ed25519 signature over DNS packet (64 bytes)
    Bytes 64-71:  Timestamp in microseconds, big-endian (8 bytes)
    Bytes 72+:    DNS packet in wire format (up to 1000 bytes)

Total max size: 1072 bytes (64 + 8 + 1000)

References:
    - RFC 1035: DNS wire format
    - BEP44: Storing arbitrary data in DHT
"""

import struct
from datetime import datetime
from typing import Optional, Dict, List, Tuple


# DNS Record Type constants (subset commonly used in Pkarr)
DNS_TYPES = {
    1: 'A',         # IPv4 address
    2: 'NS',        # Name server
    5: 'CNAME',     # Canonical name
    6: 'SOA',       # Start of authority
    12: 'PTR',      # Pointer
    15: 'MX',       # Mail exchange
    16: 'TXT',      # Text
    28: 'AAAA',     # IPv6 address
    33: 'SRV',      # Service
    65: 'HTTPS',    # HTTPS service binding
}


def is_dns_packet_payload(value: bytes) -> bool:
    """
    Check if a BEP44 value appears to be a DNS packet payload.

    A valid DNS packet payload must be at least 72 bytes (signature + timestamp + minimal DNS).
    We perform a heuristic check to detect if this is likely DNS packet format.

    Args:
        value: The BEP44 value field bytes

    Returns:
        True if the value appears to be DNS packet format, False otherwise
    """
    # Minimum size: 64 (sig) + 8 (timestamp) + minimal DNS packet
    # DNS packet minimum is ~12 bytes for header
    if len(value) < 84:  # 72 + 12
        return False

    # Maximum size: 64 + 8 + 1000 = 1072
    if len(value) > 1072:
        return False

    # Check if timestamp looks reasonable (microseconds since epoch)
    # Should be between year 2000 and year 2100 approximately
    try:
        timestamp_bytes = value[64:72]
        timestamp_us = struct.unpack('>Q', timestamp_bytes)[0]

        # Convert to seconds
        timestamp_s = timestamp_us / 1_000_000

        # Year 2000: ~946684800 seconds
        # Year 2100: ~4102444800 seconds
        if timestamp_s < 946684800 or timestamp_s > 4102444800:
            return False

    except (struct.error, ValueError):
        return False

    # Check if bytes 72+ look like DNS header (very basic heuristic)
    # DNS header starts with 2-byte ID, then flags
    if len(value) < 84:
        return False

    # This is a heuristic - if all checks pass, likely DNS packet format
    return True


def parse_dns_packet_payload(value: bytes) -> Optional[Dict]:
    """
    Parse a DNS packet BEP44 value into its components.

    Args:
        value: The BEP44 value field bytes (should be DNS packet format)

    Returns:
        Dictionary with:
            - signature: 64-byte Ed25519 signature
            - timestamp_us: Timestamp in microseconds
            - timestamp_dt: Python datetime object
            - dns_packet: Raw DNS packet bytes
            - dns_records: Parsed DNS records (if dnslib available)
            - dns_parse_error: Error message if DNS parsing failed

        Returns None if the value is not valid DNS packet format
    """
    if not is_dns_packet_payload(value):
        return None

    try:
        # Extract signature (bytes 0-63)
        signature = value[0:64]

        # Extract timestamp (bytes 64-71, big-endian microseconds)
        timestamp_bytes = value[64:72]
        timestamp_us = struct.unpack('>Q', timestamp_bytes)[0]

        # Convert to datetime
        timestamp_s = timestamp_us / 1_000_000
        timestamp_dt = datetime.utcfromtimestamp(timestamp_s)

        # Extract DNS packet (bytes 72+)
        dns_packet = value[72:]

        result = {
            'signature': signature,
            'timestamp_us': timestamp_us,
            'timestamp_dt': timestamp_dt,
            'dns_packet': dns_packet,
            'dns_records': None,
            'dns_parse_error': None,
        }

        # Try to parse DNS packet if dnslib is available
        try:
            from dnslib import DNSRecord

            dns_record = DNSRecord.parse(dns_packet)
            result['dns_records'] = extract_dns_records(dns_record)

        except ImportError:
            # dnslib not available - fallback to basic parsing
            result['dns_parse_error'] = "dnslib not installed (optional)"
            result['dns_records'] = parse_dns_basic(dns_packet)

        except Exception as e:
            # DNS parsing failed
            result['dns_parse_error'] = str(e)
            result['dns_records'] = parse_dns_basic(dns_packet)

        return result

    except Exception as e:
        return None


def extract_dns_records(dns_record) -> List[Dict]:
    """
    Extract DNS records from a parsed DNSRecord object (requires dnslib).

    Args:
        dns_record: Parsed DNSRecord object from dnslib

    Returns:
        List of dictionaries, each containing:
            - name: Domain name
            - type: Record type number
            - type_name: Record type name (A, AAAA, TXT, etc.)
            - ttl: Time to live in seconds
            - data: Record data as string
    """
    from dnslib import QTYPE

    records = []

    # Extract from answer section
    for rr in dns_record.rr:
        record = {
            'name': str(rr.rname),
            'type': rr.rtype,
            'type_name': QTYPE.get(rr.rtype, f'TYPE{rr.rtype}'),
            'ttl': rr.ttl,
            'data': str(rr.rdata),
        }
        records.append(record)

    return records


def parse_dns_basic(dns_packet: bytes) -> List[Dict]:
    """
    Basic DNS packet parser (fallback when dnslib is not available).

    This provides minimal parsing of the DNS header to extract basic info.
    It won't parse all records correctly, but gives some useful data.

    Args:
        dns_packet: Raw DNS packet bytes

    Returns:
        List with basic info about the DNS packet
    """
    if len(dns_packet) < 12:
        return [{'error': 'DNS packet too short'}]

    try:
        # Parse DNS header (12 bytes)
        # Format: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
        header = struct.unpack('>HHHHHH', dns_packet[0:12])

        packet_id = header[0]
        flags = header[1]
        qd_count = header[2]  # Questions
        an_count = header[3]  # Answers
        ns_count = header[4]  # Authority
        ar_count = header[5]  # Additional

        # Extract flags
        qr = (flags >> 15) & 0x1  # Query (0) or Response (1)
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1  # Authoritative
        tc = (flags >> 9) & 0x1   # Truncated
        rd = (flags >> 8) & 0x1   # Recursion desired
        ra = (flags >> 7) & 0x1   # Recursion available
        rcode = flags & 0xF       # Response code

        return [{
            'type_name': 'DNS_HEADER',
            'name': 'Basic DNS Info',
            'data': f'{an_count} answer(s), {qd_count} question(s)',
            'ttl': None,
            'details': {
                'packet_id': packet_id,
                'is_response': qr == 1,
                'answer_count': an_count,
                'question_count': qd_count,
                'authority_count': ns_count,
                'additional_count': ar_count,
                'authoritative': aa == 1,
                'truncated': tc == 1,
            }
        }]

    except Exception as e:
        return [{'error': f'Failed to parse DNS header: {str(e)}'}]


def format_dns_records_for_display(records: List[Dict], max_records: int = 10) -> List[str]:
    """
    Format parsed DNS records for display on SeedSigner screen.

    Args:
        records: List of parsed DNS record dictionaries
        max_records: Maximum number of records to format

    Returns:
        List of formatted strings suitable for screen display
    """
    lines = []

    if not records:
        return ["No DNS records found"]

    for i, record in enumerate(records[:max_records]):
        if 'error' in record:
            lines.append(f"⚠ {record['error']}")
            continue

        type_name = record.get('type_name', 'UNKNOWN')
        name = record.get('name', '')
        data = record.get('data', '')
        ttl = record.get('ttl')

        # Truncate long names/data for display
        if len(name) > 30:
            name = name[:27] + '...'
        if len(data) > 40:
            data = data[:37] + '...'

        # Format based on record type
        if type_name == 'A' or type_name == 'AAAA':
            # IP addresses
            lines.append(f"{type_name}: {data}")
            if name and name != '@':
                lines.append(f"  → {name}")

        elif type_name == 'TXT':
            # Text records
            lines.append(f"TXT: {data}")
            if name and name != '@':
                lines.append(f"  @ {name}")

        elif type_name == 'CNAME':
            # Canonical name
            lines.append(f"CNAME: {name}")
            lines.append(f"  → {data}")

        elif type_name == 'MX':
            # Mail exchange
            lines.append(f"MX: {data}")
            if name and name != '@':
                lines.append(f"  @ {name}")

        elif type_name == 'DNS_HEADER':
            # Basic info from fallback parser
            lines.append(f"📋 {data}")

        else:
            # Generic format
            lines.append(f"{type_name}: {data}")

        # Add TTL if available and not the last item
        if ttl is not None and i < len(records) - 1:
            lines.append(f"  TTL: {ttl}s")

    if len(records) > max_records:
        lines.append(f"... and {len(records) - max_records} more")

    return lines


def format_dns_packet_summary(parsed: Dict) -> Dict[str, str]:
    """
    Format DNS packet payload data into human-readable summary.

    Args:
        parsed: Dictionary from parse_dns_packet_payload()

    Returns:
        Dictionary with formatted fields suitable for display
    """
    if not parsed:
        return {'error': 'Invalid DNS packet payload'}

    # Format timestamp
    timestamp_dt = parsed.get('timestamp_dt')
    if timestamp_dt:
        timestamp_str = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    else:
        timestamp_str = 'Unknown'

    # Count DNS records
    dns_records = parsed.get('dns_records', [])
    record_count = len(dns_records) if dns_records else 0

    # DNS packet size
    dns_packet = parsed.get('dns_packet', b'')
    dns_size = len(dns_packet)

    # Total payload size
    total_size = 64 + 8 + dns_size  # signature + timestamp + DNS

    summary = {
        'timestamp': timestamp_str,
        'record_count': str(record_count),
        'dns_size': f"{dns_size} bytes",
        'total_size': f"{total_size} bytes",
    }

    # Add parse error if present
    parse_error = parsed.get('dns_parse_error')
    if parse_error:
        summary['parse_warning'] = parse_error

    return summary


def verify_dns_packet_signature(public_key: bytes, signature: bytes, dns_packet: bytes) -> bool:
    """
    Verify the internal DNS packet signature (signature over DNS packet).

    Note: This is separate from the BEP44 signature. DNS packet format has two signatures:
    1. Internal signature (first 64 bytes of value) - signs only the DNS packet
    2. BEP44 signature - signs the entire bencode structure

    Args:
        public_key: 32-byte Ed25519 public key
        signature: 64-byte Ed25519 signature (from bytes 0-63 of DNS packet value)
        dns_packet: DNS packet bytes (from bytes 72+ of DNS packet value)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        # Create public key object
        public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)

        # Verify signature
        public_key_obj.verify(signature, dns_packet)
        return True

    except Exception:
        return False


def z32_encode(data: bytes) -> str:
    """
    Encode bytes to z-base-32 (used for DNS domain identifiers).

    Z-base-32 is a human-oriented encoding that avoids confusing characters.
    Character set: ybndrfg8ejkmcpqxot1uwisza345h769

    Args:
        data: Bytes to encode

    Returns:
        Z-base-32 encoded string
    """
    # Z-base-32 alphabet (no padding)
    alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'

    # Convert bytes to bits
    bits = ''.join(format(byte, '08b') for byte in data)

    # Pad to multiple of 5 bits
    padding = (5 - len(bits) % 5) % 5
    bits += '0' * padding

    # Convert 5-bit groups to z-base-32 characters
    result = ''
    for i in range(0, len(bits), 5):
        chunk = bits[i:i+5]
        index = int(chunk, 2)
        result += alphabet[index]

    return result


def z32_decode(encoded: str) -> Optional[bytes]:
    """
    Decode z-base-32 string to bytes.

    Args:
        encoded: Z-base-32 encoded string

    Returns:
        Decoded bytes, or None if invalid
    """
    alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'

    try:
        # Convert characters to 5-bit groups
        bits = ''
        for char in encoded.lower():
            if char not in alphabet:
                return None
            index = alphabet.index(char)
            bits += format(index, '05b')

        # Convert bits to bytes (ignore padding)
        byte_count = len(bits) // 8
        result = bytearray()
        for i in range(byte_count):
            byte_bits = bits[i*8:(i+1)*8]
            result.append(int(byte_bits, 2))

        return bytes(result)

    except Exception:
        return None
