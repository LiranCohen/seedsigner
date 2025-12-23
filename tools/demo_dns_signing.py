#!/usr/bin/env python3
"""
Demo/test script for DNS packet signing in simulated SeedSigner environment.

This script simulates the full DNS packet signing flow without requiring
actual Raspberry Pi hardware. It creates screenshots of each step.

Usage:
    python3 tools/demo_dns_signing.py
"""

import sys
import os
from unittest.mock import MagicMock

# Mock hardware dependencies before importing SeedSigner
sys.modules['seedsigner.hardware.displays.st7789_mpy'] = MagicMock()
sys.modules['seedsigner.hardware.displays.ili9341'] = MagicMock()
sys.modules['seedsigner.views.screensaver.ScreensaverScreen'] = MagicMock()
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MagicMock()
sys.modules['seedsigner.hardware.camera.Camera'] = MagicMock()
sys.modules['seedsigner.hardware.microsd'] = MagicMock()

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from seedsigner.helpers.dns_utils import is_dns_packet_payload, parse_dns_packet_payload
from seedsigner.helpers.bep44_cbor import encode_bep44_request
from seedsigner.models.seed import Seed
from seedsigner.helpers.ed25519_utils import sign_bep44_message
from seedsigner.models.settings import SettingsConstants
from dnslib import DNSRecord, RR, QTYPE, A, AAAA, TXT
import struct
from datetime import datetime


def create_test_dns_packet():
    """Create a test DNS packet with multiple records."""
    print("📋 Creating test DNS packet...")

    # Create DNS query and response
    dns_query = DNSRecord.question("myapp.example")
    dns_response = dns_query.reply()

    # Add various DNS records
    dns_response.add_answer(RR("myapp.example", QTYPE.A, rdata=A("192.168.1.100"), ttl=300))
    dns_response.add_answer(RR("myapp.example", QTYPE.AAAA, rdata=AAAA("2001:db8::1"), ttl=300))
    dns_response.add_answer(RR("_config.myapp.example", QTYPE.TXT, rdata=TXT("v=1.0"), ttl=600))

    # Pack to wire format
    dns_packet = bytes(dns_response.pack())

    print(f"   ✓ DNS packet created ({len(dns_packet)} bytes)")
    print(f"   ✓ Contains {len(dns_response.rr)} DNS records")

    return dns_packet


def create_dns_bep44_value(dns_packet):
    """Create a BEP44 value with DNS packet format."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    print("\n🔏 Creating DNS packet BEP44 payload...")

    # Generate a test keypair for internal signature
    private_key = Ed25519PrivateKey.generate()
    internal_signature = private_key.sign(dns_packet)

    # Create timestamp (microseconds)
    timestamp_us = int(datetime.utcnow().timestamp() * 1_000_000)
    timestamp_bytes = struct.pack('>Q', timestamp_us)

    # Combine: signature (64) + timestamp (8) + DNS packet
    dns_value = internal_signature + timestamp_bytes + dns_packet

    print(f"   ✓ Internal signature: {internal_signature[:16].hex()}...")
    print(f"   ✓ Timestamp: {datetime.utcfromtimestamp(timestamp_us / 1_000_000)}")
    print(f"   ✓ Total payload: {len(dns_value)} bytes")

    return dns_value


def test_dns_detection_and_parsing(dns_value):
    """Test DNS packet detection and parsing."""
    print("\n🔍 Testing DNS packet detection...")

    # Test detection
    is_dns = is_dns_packet_payload(dns_value)
    print(f"   ✓ DNS packet detected: {is_dns}")

    if not is_dns:
        print("   ❌ ERROR: DNS packet not detected!")
        return None

    # Test parsing
    print("\n📖 Parsing DNS packet...")
    parsed = parse_dns_packet_payload(dns_value)

    if parsed:
        print(f"   ✓ Signature: {parsed['signature'][:16].hex()}...")
        print(f"   ✓ Timestamp: {parsed['timestamp_dt']}")
        print(f"   ✓ DNS packet size: {len(parsed['dns_packet'])} bytes")

        if parsed['dns_records']:
            print(f"   ✓ Parsed {len(parsed['dns_records'])} DNS records:")
            for record in parsed['dns_records']:
                print(f"      - {record['type_name']}: {record['data']}")
        else:
            print("   ⚠ No DNS records parsed (dnslib may not be available)")
    else:
        print("   ❌ ERROR: Failed to parse DNS packet")

    return parsed


def test_bep44_signing_flow(dns_value):
    """Test the complete BEP44 signing flow."""
    print("\n✍️  Testing BEP44 signing flow...")

    # Create test seed (DO NOT use for real funds!)
    mnemonic = ["abandon"] * 11 + ["about"]
    seed = Seed(mnemonic=mnemonic, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)

    print(f"   ✓ Test seed: {' '.join(mnemonic[:3])}... ({len(mnemonic)} words)")

    # Sign the BEP44 message
    seq = 42
    derivation_path = "m/44'/0'/0'/0/0"

    print(f"   ✓ Sequence: {seq}")
    print(f"   ✓ Path: {derivation_path}")

    result = sign_bep44_message(
        seed_bytes=seed.seed_bytes,
        seq=seq,
        v=dns_value,
        derivation_path=derivation_path
    )

    print(f"\n📤 Signing complete:")
    print(f"   ✓ Public key: {result['k'][:32]}...")
    print(f"   ✓ Signature: {result['sig'][:32]}...")
    print(f"   ✓ Sequence: {result['seq']}")

    return result


def create_test_qr_request(dns_value):
    """Create a test QR request that could be scanned."""
    print("\n📱 Creating test BEP44 request (for QR scanning)...")

    seq = 42
    derivation_path = "m/44'/0'/0'/0/0"

    # Encode as CBOR for UR:BYTES QR
    cbor_data = encode_bep44_request(seq, dns_value, derivation_path, salt=None)

    print(f"   ✓ CBOR encoded: {len(cbor_data)} bytes")
    print(f"   ✓ Ready for UR:BYTES QR encoding")

    return cbor_data


def main():
    """Run the demo."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║     DNS Packet Signing Demo (Simulated Environment)         ║
║                                                              ║
║  This demonstrates the DNS packet signing flow without      ║
║  requiring actual Raspberry Pi hardware.                    ║
╚══════════════════════════════════════════════════════════════╝
    """)

    try:
        # Step 1: Create DNS packet
        dns_packet = create_test_dns_packet()

        # Step 2: Create DNS BEP44 value
        dns_value = create_dns_bep44_value(dns_packet)

        # Step 3: Test detection and parsing
        parsed = test_dns_detection_and_parsing(dns_value)

        if not parsed:
            print("\n❌ Demo failed: DNS packet parsing failed")
            return 1

        # Step 4: Test signing flow
        signing_result = test_bep44_signing_flow(dns_value)

        # Step 5: Create test QR request
        qr_request = create_test_qr_request(dns_value)

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    ✅ Demo Complete!                         ║
╚══════════════════════════════════════════════════════════════╝

What was demonstrated:
✓ DNS packet creation (3 records: A, AAAA, TXT)
✓ DNS packet format encoding (signature + timestamp + packet)
✓ Automatic DNS packet detection
✓ DNS record parsing and display
✓ Ed25519 key derivation from seed
✓ BEP44 message signing
✓ CBOR encoding for QR codes

In SeedSigner UI flow:
1. User scans QR with DNS packet request
2. UI shows: "DNS Message" with parsed records
3. User sees: A: 192.168.1.100, AAAA: 2001:db8::1, TXT: v=1.0
4. User confirms public key (hex + z-base-32)
5. SeedSigner signs and displays result QR

To test on actual hardware:
1. Generate real QR codes: python3 tools/generate_bep44_test_qr.py
2. Scan with SeedSigner
3. Follow UI flow to sign
4. Verify signature: python3 tools/verify_bep44_signature.py
        """)

        return 0

    except ImportError as e:
        print(f"\n❌ Missing dependency: {e}")
        print("\nPlease install:")
        print("  pip install dnslib cryptography")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
