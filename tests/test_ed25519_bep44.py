"""
Unit tests for ed25519 key derivation and BEP44 message signing.

Tests:
- SLIP-0010 ed25519 key derivation
- BEP44 signing buffer creation
- BEP44 message signing and verification
- CBOR encoding/decoding
"""

import pytest
from seedsigner.helpers.ed25519_utils import (
    derive_ed25519_keypair_from_seed,
    create_bep44_signing_buffer,
    sign_bep44_message,
    verify_bep44_signature,
    get_bep44_storage_target,
    InvalidDerivationPath
)
from seedsigner.helpers.bep44_cbor import (
    encode_bep44_request,
    decode_bep44_request,
    encode_bep44_result,
    decode_bep44_result
)


class TestEd25519KeyDerivation:
    """Test SLIP-0010 ed25519 key derivation"""

    def test_key_derivation_basic(self):
        """Test basic key derivation from seed"""
        # Test seed (64 bytes)
        test_seed = b'\x00' * 64

        # Derive keypair
        private_key, public_key = derive_ed25519_keypair_from_seed(test_seed)

        # Verify lengths
        assert len(private_key) == 32, "Private key should be 32 bytes"
        assert len(public_key) == 32, "Public key should be 32 bytes"

    def test_key_derivation_deterministic(self):
        """Test that derivation is deterministic"""
        test_seed = b'\x01' * 64
        path = "m/44'/0'/0'/0/0"

        # Derive twice
        priv1, pub1 = derive_ed25519_keypair_from_seed(test_seed, path)
        priv2, pub2 = derive_ed25519_keypair_from_seed(test_seed, path)

        # Should be identical
        assert priv1 == priv2, "Private keys should match"
        assert pub1 == pub2, "Public keys should match"

    def test_key_derivation_different_paths(self):
        """Test that different paths produce different keys"""
        test_seed = b'\x02' * 64
        path1 = "m/44'/0'/0'/0/0"
        path2 = "m/44'/0'/0'/0/1"

        priv1, pub1 = derive_ed25519_keypair_from_seed(test_seed, path1)
        priv2, pub2 = derive_ed25519_keypair_from_seed(test_seed, path2)

        # Should be different
        assert priv1 != priv2, "Private keys should differ"
        assert pub1 != pub2, "Public keys should differ"

    def test_invalid_derivation_path(self):
        """Test that invalid paths raise exception"""
        test_seed = b'\x03' * 64

        with pytest.raises(InvalidDerivationPath):
            derive_ed25519_keypair_from_seed(test_seed, "invalid/path")


class TestBep44SigningBuffer:
    """Test BEP44 signing buffer creation (bencode format)"""

    def test_signing_buffer_no_salt(self):
        """Test signing buffer without salt"""
        seq = 1
        value = b"Hello World!"

        buffer = create_bep44_signing_buffer(seq, value)

        # Should be: "3:seqi1e1:v12:Hello World!"
        expected = b"3:seqi1e1:v12:Hello World!"
        assert buffer == expected, f"Buffer mismatch: {buffer}"

    def test_signing_buffer_with_salt(self):
        """Test signing buffer with salt"""
        seq = 1
        value = b"Hello World!"
        salt = b"foobar"

        buffer = create_bep44_signing_buffer(seq, value, salt)

        # Should be: "4:salt6:foobar3:seqi1e1:v12:Hello World!"
        expected = b"4:salt6:foobar3:seqi1e1:v12:Hello World!"
        assert buffer == expected, f"Buffer mismatch: {buffer}"

    def test_signing_buffer_value_size_limit(self):
        """Test that value > 1000 bytes raises error"""
        seq = 1
        value = b"x" * 1001  # Too large

        with pytest.raises(ValueError):
            create_bep44_signing_buffer(seq, value)

    def test_signing_buffer_salt_size_limit(self):
        """Test that salt > 64 bytes raises error"""
        seq = 1
        value = b"test"
        salt = b"x" * 65  # Too large

        with pytest.raises(ValueError):
            create_bep44_signing_buffer(seq, value, salt)


class TestBep44Signing:
    """Test BEP44 message signing and verification"""

    def test_sign_and_verify_no_salt(self):
        """Test signing and verifying without salt"""
        test_seed = b'\x04' * 64
        seq = 1
        value = b"Test message"
        path = "m/44'/0'/0'/0/0"

        # Sign message
        result = sign_bep44_message(test_seed, seq, value, derivation_path=path)

        # Verify result structure
        assert "k" in result, "Result should contain public key"
        assert "sig" in result, "Result should contain signature"
        assert "seq" in result, "Result should contain sequence"
        assert "v" in result, "Result should contain value"
        assert result["seq"] == seq, "Sequence should match"

        # Verify signature
        public_key = bytes.fromhex(result["k"])
        signature = bytes.fromhex(result["sig"])
        verified = verify_bep44_signature(public_key, seq, value, signature)
        assert verified, "Signature should verify"

    def test_sign_and_verify_with_salt(self):
        """Test signing and verifying with salt"""
        test_seed = b'\x05' * 64
        seq = 42
        value = b"Another test"
        salt = b"test_salt"
        path = "m/44'/0'/0'/0/0"

        # Sign message
        result = sign_bep44_message(test_seed, seq, value, salt=salt, derivation_path=path)

        # Verify result has salt
        assert "salt" in result, "Result should contain salt"

        # Verify signature
        public_key = bytes.fromhex(result["k"])
        signature = bytes.fromhex(result["sig"])
        verified = verify_bep44_signature(public_key, seq, value, signature, salt=salt)
        assert verified, "Signature with salt should verify"

    def test_verify_wrong_signature_fails(self):
        """Test that wrong signature fails verification"""
        test_seed = b'\x06' * 64
        seq = 1
        value = b"Message"

        # Sign message
        result = sign_bep44_message(test_seed, seq, value)

        # Try to verify with wrong signature
        public_key = bytes.fromhex(result["k"])
        wrong_signature = b'\x00' * 64  # Wrong signature
        verified = verify_bep44_signature(public_key, seq, value, wrong_signature)
        assert not verified, "Wrong signature should not verify"

    def test_sign_large_value(self):
        """Test signing with maximum allowed value size"""
        test_seed = b'\x07' * 64
        seq = 1
        value = b"x" * 1000  # Maximum size

        # Should succeed
        result = sign_bep44_message(test_seed, seq, value)
        assert "sig" in result

        # Verify
        public_key = bytes.fromhex(result["k"])
        signature = bytes.fromhex(result["sig"])
        verified = verify_bep44_signature(public_key, seq, value, signature)
        assert verified


class TestBep44StorageTarget:
    """Test BEP44 storage target hash calculation"""

    def test_storage_target_no_salt(self):
        """Test storage target without salt"""
        public_key = b'\x08' * 32

        target = get_bep44_storage_target(public_key)

        # Should be 20-byte SHA-1 hash
        assert len(target) == 20, "Target should be 20 bytes"

    def test_storage_target_with_salt(self):
        """Test storage target with salt"""
        public_key = b'\x09' * 32
        salt = b"salt"

        target = get_bep44_storage_target(public_key, salt)

        # Should be 20-byte SHA-1 hash
        assert len(target) == 20, "Target should be 20 bytes"

    def test_storage_target_different_with_salt(self):
        """Test that salt changes storage target"""
        public_key = b'\x0a' * 32

        target1 = get_bep44_storage_target(public_key)
        target2 = get_bep44_storage_target(public_key, b"salt")

        assert target1 != target2, "Salt should change target"


class TestBep44CBOR:
    """Test CBOR encoding/decoding for BEP44 messages"""

    def test_encode_decode_request_no_salt(self):
        """Test encoding and decoding request without salt"""
        seq = 1
        value = b"Test value"
        path = "m/44'/0'/0'/0/0"

        # Encode
        cbor_data = encode_bep44_request(seq, value, path)
        assert len(cbor_data) > 0, "CBOR data should not be empty"

        # Decode
        decoded = decode_bep44_request(cbor_data)
        assert decoded["seq"] == seq, "Sequence should match"
        assert decoded["value"] == value, "Value should match"
        assert decoded["derivation_path"] == path, "Path should match"
        assert "salt" not in decoded, "Salt should not be present"

    def test_encode_decode_request_with_salt(self):
        """Test encoding and decoding request with salt"""
        seq = 42
        value = b"Test value with salt"
        path = "m/44'/0'/0'/0/1"
        salt = b"test_salt"

        # Encode
        cbor_data = encode_bep44_request(seq, value, path, salt)

        # Decode
        decoded = decode_bep44_request(cbor_data)
        assert decoded["seq"] == seq
        assert decoded["value"] == value
        assert decoded["derivation_path"] == path
        assert decoded["salt"] == salt, "Salt should be present"

    def test_encode_decode_result_minimal(self):
        """Test encoding and decoding result (minimal)"""
        public_key = b'\x0b' * 32
        signature = b'\x0c' * 64
        seq = 123

        # Encode
        cbor_data = encode_bep44_result(public_key, signature, seq, include_value=False)

        # Decode
        decoded = decode_bep44_result(cbor_data)
        assert decoded["public_key"] == public_key
        assert decoded["signature"] == signature
        assert decoded["seq"] == seq
        assert "value" not in decoded, "Value should not be included"
        assert "salt" not in decoded, "Salt should not be included"

    def test_encode_decode_result_full(self):
        """Test encoding and decoding result (with value and salt)"""
        public_key = b'\x0d' * 32
        signature = b'\x0e' * 64
        seq = 456
        value = b"Full value"
        salt = b"salt"

        # Encode
        cbor_data = encode_bep44_result(
            public_key, signature, seq,
            include_value=True, v=value, salt=salt
        )

        # Decode
        decoded = decode_bep44_result(cbor_data)
        assert decoded["public_key"] == public_key
        assert decoded["signature"] == signature
        assert decoded["seq"] == seq
        assert decoded["value"] == value
        assert decoded["salt"] == salt
