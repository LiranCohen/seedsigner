#!/usr/bin/env python3
"""
Generate test BEP44 signing request QR codes for SeedSigner testing.

This tool creates UR:BYTES QR codes containing BEP44 signing requests that can be
scanned by SeedSigner. After SeedSigner signs the message, it will display a
result QR code that can be scanned back.

Usage:
    python3 tools/generate_bep44_test_qr.py

This will generate an animated QR code in the terminal that you can scan with SeedSigner.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from seedsigner.helpers.bep44_cbor import encode_bep44_request
from seedsigner.models.encode_qr import Bep44RequestQrEncoder
import qrcode


def generate_simple_test():
    """Generate a simple BEP44 test request."""
    print("\n" + "="*60)
    print("TEST 1: Simple BEP44 Signing Request (No Salt)")
    print("="*60)

    seq = 1
    value = b"Hello from SeedSigner! This is a BEP44 test message."
    path = "m/44'/0'/0'/0/0"
    salt = None

    print(f"\nSequence: {seq}")
    print(f"Value: {value.decode('utf-8')}")
    print(f"Path: {path}")
    print(f"Salt: None")
    print(f"Value size: {len(value)} bytes")

    # Create encoder
    encoder = Bep44RequestQrEncoder(
        seq=seq,
        value=value,
        derivation_path=path,
        salt=salt,
        qr_density="M"
    )

    # Generate QR code(s)
    print("\n--- QR Code Data (UR format) ---")
    qr_data = encoder.next_part()
    print(f"UR: {qr_data}")
    print(f"\nQR Data Length: {len(qr_data)} characters")

    # Display QR in terminal
    print("\n--- Scan this QR code with SeedSigner ---\n")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)

    print("\n" + "-"*60)
    print("After scanning, SeedSigner will:")
    print("1. Show message details (seq, value, path)")
    print("2. Show derived ed25519 public key")
    print("3. Display signed result as QR code")
    print("-"*60 + "\n")


def generate_test_with_salt():
    """Generate a BEP44 test request with salt."""
    print("\n" + "="*60)
    print("TEST 2: BEP44 Signing Request (With Salt)")
    print("="*60)

    seq = 42
    value = b"DHT mutable item with salt for unique storage location"
    path = "m/44'/0'/0'/0/0"
    salt = b"my_app_v1"

    print(f"\nSequence: {seq}")
    print(f"Value: {value.decode('utf-8')}")
    print(f"Path: {path}")
    print(f"Salt: {salt.decode('utf-8')}")
    print(f"Value size: {len(value)} bytes")
    print(f"Salt size: {len(salt)} bytes")

    # Create encoder
    encoder = Bep44RequestQrEncoder(
        seq=seq,
        value=value,
        derivation_path=path,
        salt=salt,
        qr_density="M"
    )

    # Generate QR code(s)
    print("\n--- QR Code Data (UR format) ---")
    qr_data = encoder.next_part()
    print(f"UR: {qr_data}")
    print(f"\nQR Data Length: {len(qr_data)} characters")

    # Display QR in terminal
    print("\n--- Scan this QR code with SeedSigner ---\n")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)

    print("\n" + "-"*60)
    print("Note: Salt changes the DHT storage location")
    print("Target = SHA1(public_key || salt)")
    print("-"*60 + "\n")


def generate_large_value_test():
    """Generate a BEP44 test with large value (tests fountain encoding)."""
    print("\n" + "="*60)
    print("TEST 3: Large BEP44 Request (Animated QR)")
    print("="*60)

    seq = 100
    # Create a 500-byte value (should require animated QR)
    value = b"Large DHT value test. " * 22 + b"End of message."
    path = "m/44'/0'/0'/0/0"
    salt = None

    print(f"\nSequence: {seq}")
    print(f"Value: {value[:50].decode('utf-8')}... (truncated)")
    print(f"Path: {path}")
    print(f"Salt: None")
    print(f"Value size: {len(value)} bytes")

    # Create encoder
    encoder = Bep44RequestQrEncoder(
        seq=seq,
        value=value,
        derivation_path=path,
        salt=salt,
        qr_density="M"
    )

    print("\n--- QR Code Animation Required ---")
    print("This message is large enough to require animated QR codes.")
    print("The QR scanner will need to capture multiple frames.")
    print("\nGenerating first 3 frames...\n")

    for i in range(3):
        qr_data = encoder.next_part()
        print(f"\nFrame {i+1}:")
        print(f"UR: {qr_data[:80]}...")

        # Only show QR for first frame
        if i == 0:
            print("\n--- Scan this animated QR (frame 1 of N) ---\n")
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=1,
                border=2,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            qr.print_ascii(invert=True)

    print("\n" + "-"*60)
    print("Note: This requires scanning multiple QR frames")
    print("SeedSigner's scanner will collect all frames automatically")
    print("-"*60 + "\n")


def generate_custom_path_test():
    """Generate a BEP44 test with custom derivation path."""
    print("\n" + "="*60)
    print("TEST 4: Custom Derivation Path")
    print("="*60)

    seq = 5
    value = b"Testing custom ed25519 derivation path"
    path = "m/44'/0'/1'/0/5"  # Different account and index
    salt = None

    print(f"\nSequence: {seq}")
    print(f"Value: {value.decode('utf-8')}")
    print(f"Path: {path} (custom path)")
    print(f"Salt: None")
    print(f"Value size: {len(value)} bytes")

    # Create encoder
    encoder = Bep44RequestQrEncoder(
        seq=seq,
        value=value,
        derivation_path=path,
        salt=salt,
        qr_density="M"
    )

    # Generate QR code(s)
    print("\n--- QR Code Data (UR format) ---")
    qr_data = encoder.next_part()
    print(f"UR: {qr_data}")

    # Display QR in terminal
    print("\n--- Scan this QR code with SeedSigner ---\n")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)

    print("\n" + "-"*60)
    print("Different paths generate different ed25519 keys")
    print("Useful for key separation and privacy")
    print("-"*60 + "\n")


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║         BEP44 Test QR Code Generator for SeedSigner         ║
║                                                              ║
║  This tool generates test BEP44 signing requests that can   ║
║  be scanned by SeedSigner to test ed25519 signing.          ║
╚══════════════════════════════════════════════════════════════╝
    """)

    try:
        # Generate all test cases
        generate_simple_test()
        input("\nPress Enter to continue to next test...")

        generate_test_with_salt()
        input("\nPress Enter to continue to next test...")

        generate_large_value_test()
        input("\nPress Enter to continue to next test...")

        generate_custom_path_test()

        print("\n" + "="*60)
        print("All test QR codes generated!")
        print("="*60)
        print("\nNext steps:")
        print("1. Scan any of the QR codes above with SeedSigner")
        print("2. Confirm the message details on screen")
        print("3. Confirm the public key")
        print("4. SeedSigner will display the signed result QR")
        print("5. Scan the result QR to verify signature")
        print("\nFor automated verification, use:")
        print("  python3 tools/verify_bep44_signature.py")
        print("="*60 + "\n")

    except ImportError as e:
        print(f"\n❌ Error: Missing dependency - {e}")
        print("\nPlease install required packages:")
        print("  pip install qrcode[pil]")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error generating QR codes: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
