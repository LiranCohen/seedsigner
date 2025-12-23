"""
Tests for DNS packet signing utilities.

Tests DNS packet payload parsing (Pkarr format), DNS record extraction,
and z-base-32 encoding for domain identifiers.
"""

import struct
from datetime import datetime
import pytest


class TestDnsPacketDetection:
    """Test DNS packet payload detection heuristics."""

    def test_is_dns_packet_valid_payload(self):
        """Test that valid DNS packet payloads are correctly identified."""
        from seedsigner.helpers.dns_utils import is_dns_packet_payload
        from dnslib import DNSRecord, RR, QTYPE, A

        # Create a minimal DNS packet
        dns_query = DNSRecord.question("example.com")
        dns_response = dns_query.reply()
        dns_response.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
        dns_packet = bytes(dns_response.pack())

        # Create DNS packet payload: signature (64) + timestamp (8) + DNS packet
        signature = b'\x00' * 64  # Dummy signature
        timestamp = struct.pack('>Q', int(datetime.utcnow().timestamp() * 1_000_000))
        payload = signature + timestamp + dns_packet

        assert is_dns_packet_payload(payload) == True

    def test_is_dns_packet_too_short(self):
        """Test that payloads shorter than minimum are rejected."""
        from seedsigner.helpers.dns_utils import is_dns_packet_payload

        # Less than 72 bytes minimum
        short_payload = b'\x00' * 70
        assert is_dns_packet_payload(short_payload) == False

    def test_is_dns_packet_too_long(self):
        """Test that payloads exceeding maximum size are rejected."""
        from seedsigner.helpers.dns_utils import is_dns_packet_payload

        # More than 1072 bytes maximum (64 + 8 + 1000)
        long_payload = b'\x00' * 1073
        assert is_dns_packet_payload(long_payload) == False

    def test_is_dns_packet_invalid_timestamp(self):
        """Test that payloads with unrealistic timestamps are rejected."""
        from seedsigner.helpers.dns_utils import is_dns_packet_payload

        signature = b'\x00' * 64
        # Timestamp way in the future (year 2200)
        bad_timestamp = struct.pack('>Q', 7_000_000_000 * 1_000_000)
        dns_minimal = b'\x00' * 20
        payload = signature + bad_timestamp + dns_minimal

        assert is_dns_packet_payload(payload) == False

    def test_is_dns_packet_generic_bep44(self):
        """Test that generic BEP44 payloads are not detected as Pkarr."""
        from seedsigner.helpers.dns_utils import is_dns_packet_payload

        # Generic BEP44 value (not Pkarr format)
        generic_value = b"Hello, this is a regular BEP44 message!"
        assert is_dns_packet_payload(generic_value) == False


class TestDnsPacketParsing:
    """Test DNS packet payload parsing."""

    def test_parse_dns_packet_with_dns_records(self):
        """Test parsing DNS packet payload with DNS records."""
        from seedsigner.helpers.dns_utils import parse_dns_packet_payload
        from dnslib import DNSRecord, RR, QTYPE, A, AAAA

        # Create DNS packet with multiple records
        dns_query = DNSRecord.question("test.example")
        dns_response = dns_query.reply()
        dns_response.add_answer(RR("test.example", QTYPE.A, rdata=A("192.168.1.1"), ttl=300))
        dns_response.add_answer(RR("test.example", QTYPE.AAAA, rdata=AAAA("2001:db8::1"), ttl=300))
        dns_packet = bytes(dns_response.pack())

        # Create DNS packet payload
        signature = b'\xAB' * 64
        timestamp_us = int(datetime.utcnow().timestamp() * 1_000_000)
        timestamp_bytes = struct.pack('>Q', timestamp_us)
        payload = signature + timestamp_bytes + dns_packet

        # Parse
        result = parse_dns_packet_payload(payload)

        assert result is not None
        assert result['signature'] == signature
        assert result['timestamp_us'] == timestamp_us
        assert result['dns_packet'] == dns_packet
        assert result['dns_records'] is not None
        assert len(result['dns_records']) == 2

        # Check record details
        records = result['dns_records']
        assert records[0]['type_name'] == 'A'
        assert records[0]['data'] == '192.168.1.1'
        assert records[1]['type_name'] == 'AAAA'
        assert records[1]['data'] == '2001:db8::1'

    def test_parse_dns_packet_timestamp_conversion(self):
        """Test that timestamp is correctly converted to datetime."""
        from seedsigner.helpers.dns_utils import parse_dns_packet_payload
        from dnslib import DNSRecord

        # Create minimal DNS packet
        dns_packet = bytes(DNSRecord.question("test.com").pack())

        # Known timestamp: 2024-01-15 12:00:00 UTC
        expected_dt = datetime(2024, 1, 15, 12, 0, 0)
        timestamp_s = expected_dt.timestamp()
        timestamp_us = int(timestamp_s * 1_000_000)

        # Create payload
        signature = b'\x00' * 64
        timestamp_bytes = struct.pack('>Q', timestamp_us)
        payload = signature + timestamp_bytes + dns_packet

        # Parse
        result = parse_dns_packet_payload(payload)

        assert result is not None
        assert abs((result['timestamp_dt'] - expected_dt).total_seconds()) < 1  # Within 1 second

    def test_parse_dns_packet_invalid_payload(self):
        """Test that invalid payloads return None."""
        from seedsigner.helpers.dns_utils import parse_dns_packet_payload

        # Too short
        assert parse_dns_packet_payload(b"short") is None

        # Wrong timestamp format
        bad_payload = b'\x00' * 64 + b'\xFF' * 8 + b'\x00' * 20
        # This should still parse but may have errors


class TestDNSRecordFormatting:
    """Test DNS record formatting for display."""

    def test_format_dns_records_for_display(self):
        """Test formatting DNS records for screen display."""
        from seedsigner.helpers.dns_utils import format_dns_records_for_display

        records = [
            {'type_name': 'A', 'name': 'example.com', 'data': '192.168.1.1', 'ttl': 300},
            {'type_name': 'TXT', 'name': 'example.com', 'data': 'v=spf1 -all', 'ttl': 600},
            {'type_name': 'CNAME', 'name': 'www', 'data': 'example.com', 'ttl': 300},
        ]

        lines = format_dns_records_for_display(records, max_records=10)

        assert len(lines) > 0
        assert any('A:' in line for line in lines)
        assert any('192.168.1.1' in line for line in lines)
        assert any('TXT:' in line for line in lines)

    def test_format_dns_records_truncation(self):
        """Test that long record data is truncated."""
        from seedsigner.helpers.dns_utils import format_dns_records_for_display

        records = [
            {
                'type_name': 'TXT',
                'name': 'verylongdomainname.example.com.that.goes.on.forever',
                'data': 'very_long_text_value_that_exceeds_forty_characters_for_sure_yes',
                'ttl': 300
            },
        ]

        lines = format_dns_records_for_display(records)

        # Check that truncation indicators are present
        assert any('...' in line for line in lines)

    def test_format_dns_records_max_limit(self):
        """Test that max_records limit is respected."""
        from seedsigner.helpers.dns_utils import format_dns_records_for_display

        # Create 10 records
        records = [
            {'type_name': 'A', 'name': f'host{i}.example', 'data': f'192.168.1.{i}', 'ttl': 300}
            for i in range(10)
        ]

        # Limit to 3
        lines = format_dns_records_for_display(records, max_records=3)

        # Should indicate more records exist
        assert any('and' in line and 'more' in line for line in lines)


class TestDnsPacketSummary:
    """Test DNS packet payload summary formatting."""

    def test_format_dns_packet_summary(self):
        """Test formatting Pkarr summary for display."""
        from seedsigner.helpers.dns_utils import format_dns_packet_summary

        timestamp_dt = datetime(2024, 1, 15, 12, 30, 0)
        parsed_data = {
            'timestamp_dt': timestamp_dt,
            'dns_records': [
                {'type_name': 'A', 'data': '1.2.3.4'},
                {'type_name': 'TXT', 'data': 'test'},
            ],
            'dns_packet': b'\x00' * 100,
            'dns_parse_error': None,
        }

        summary = format_dns_packet_summary(parsed_data)

        assert 'timestamp' in summary
        assert '2024-01-15' in summary['timestamp']
        assert summary['record_count'] == '2'
        assert '100 bytes' in summary['dns_size']
        assert '172 bytes' in summary['total_size']  # 64 + 8 + 100


class TestZBase32Encoding:
    """Test z-base-32 encoding/decoding."""

    def test_z32_encode_decode_roundtrip(self):
        """Test that encoding and decoding are inverse operations."""
        from seedsigner.helpers.dns_utils import z32_encode, z32_decode

        # Test various byte sequences
        test_data = [
            b'\x00' * 32,  # All zeros
            b'\xFF' * 32,  # All ones
            b'Hello, World! This is a test..',  # ASCII (32 bytes)
            bytes(range(32)),  # Sequential bytes
        ]

        for data in test_data:
            encoded = z32_encode(data)
            decoded = z32_decode(encoded)
            assert decoded == data, f"Round-trip failed for {data.hex()}"

    def test_z32_encode_empty(self):
        """Test z-base-32 encoding of empty bytes."""
        from seedsigner.helpers.dns_utils import z32_encode

        result = z32_encode(b'')
        assert result == ''

    def test_z32_encode_single_byte(self):
        """Test z-base-32 encoding of a single byte."""
        from seedsigner.helpers.dns_utils import z32_encode

        # Single byte 0x00
        result = z32_encode(b'\x00')
        assert len(result) == 2  # 8 bits -> 2 chars (5 bits each)

    def test_z32_encode_ed25519_pubkey(self):
        """Test z-base-32 encoding of a typical ed25519 public key."""
        from seedsigner.helpers.dns_utils import z32_encode

        # Typical 32-byte ed25519 public key
        pubkey = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155')
        encoded = z32_encode(pubkey)

        # Should be 52 characters for 32 bytes (32 * 8 / 5 = 51.2, rounded up)
        assert len(encoded) == 52
        # All characters should be in z-base-32 alphabet
        alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
        assert all(c in alphabet for c in encoded.lower())

    def test_z32_decode_invalid(self):
        """Test that invalid z-base-32 strings return None."""
        from seedsigner.helpers.dns_utils import z32_decode

        # Invalid character
        assert z32_decode('invalid@character') is None

        # Non-z-base-32 alphabet ('L' and 'V' not in z-base-32)
        assert z32_decode('LLLLLLLL') is None  # 'L' not in z-base-32
        assert z32_decode('VVVVVVVV') is None  # 'V' not in z-base-32


class TestDnsPacketSignatureVerification:
    """Test internal DNS packet signature verification."""

    def test_verify_dns_packet_signature_valid(self):
        """Test verification of valid DNS packet signature."""
        from seedsigner.helpers.dns_utils import verify_dns_packet_signature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate test keypair
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()

        # DNS packet to sign
        dns_packet = b"This is a test DNS packet"

        # Sign
        signature = private_key.sign(dns_packet)

        # Verify
        is_valid = verify_dns_packet_signature(public_key_bytes, signature, dns_packet)
        assert is_valid == True

    def test_verify_dns_packet_signature_invalid(self):
        """Test that invalid signatures are rejected."""
        from seedsigner.helpers.dns_utils import verify_dns_packet_signature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate test keypair
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes_raw()

        # DNS packet to sign
        dns_packet = b"This is a test DNS packet"

        # Sign
        signature = private_key.sign(dns_packet)

        # Modify DNS packet (should invalidate signature)
        modified_packet = dns_packet + b"MODIFIED"

        # Verify should fail
        is_valid = verify_dns_packet_signature(public_key_bytes, signature, modified_packet)
        assert is_valid == False

    def test_verify_dns_packet_signature_wrong_key(self):
        """Test that signature fails with wrong public key."""
        from seedsigner.helpers.dns_utils import verify_dns_packet_signature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate two keypairs
        private_key1 = Ed25519PrivateKey.generate()
        private_key2 = Ed25519PrivateKey.generate()
        public_key2_bytes = private_key2.public_key().public_bytes_raw()

        # DNS packet
        dns_packet = b"Test DNS packet"

        # Sign with key1
        signature = private_key1.sign(dns_packet)

        # Verify with key2 (should fail)
        is_valid = verify_dns_packet_signature(public_key2_bytes, signature, dns_packet)
        assert is_valid == False


class TestDnsPacketIntegration:
    """Integration tests for complete Pkarr workflow."""

    def test_create_and_parse_dns_packet_payload(self):
        """Test creating a DNS packet payload and parsing it back."""
        from seedsigner.helpers.dns_utils import parse_dns_packet_payload, is_dns_packet_payload
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from dnslib import DNSRecord, RR, QTYPE, A, TXT
        import struct

        # Create DNS packet
        dns_query = DNSRecord.question("myapp.example")
        dns_response = dns_query.reply()
        dns_response.add_answer(RR("myapp.example", QTYPE.A, rdata=A("10.0.0.1"), ttl=60))
        dns_response.add_answer(RR("_config.myapp.example", QTYPE.TXT, rdata=TXT("v=1"), ttl=60))
        dns_packet = bytes(dns_response.pack())  # Convert bytearray to bytes

        # Create DNS packet signature
        private_key = Ed25519PrivateKey.generate()
        signature = private_key.sign(dns_packet)

        # Build DNS packet payload
        timestamp_us = int(datetime.utcnow().timestamp() * 1_000_000)
        timestamp_bytes = struct.pack('>Q', timestamp_us)
        pkarr_payload = signature + timestamp_bytes + dns_packet

        # Verify detection
        assert is_dns_packet_payload(pkarr_payload) == True

        # Parse
        parsed = parse_dns_packet_payload(pkarr_payload)
        assert parsed is not None
        assert parsed['signature'] == signature
        assert parsed['dns_packet'] == dns_packet

        # Check DNS records
        records = parsed['dns_records']
        assert len(records) == 2
        assert records[0]['type_name'] == 'A'
        assert records[0]['data'] == '10.0.0.1'
        assert records[1]['type_name'] == 'TXT'
        assert '"v=1"' in records[1]['data']  # TXT records are quoted
