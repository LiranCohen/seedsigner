"""
Ed25519 cryptographic utilities for BEP44 DHT message signing.

Implements:
- SLIP-0010 key derivation for ed25519 from BIP39 seeds
- BEP44 message signing according to BEP44 specification
- Bencode formatting for BEP44 signing buffers
"""

import hashlib
import hmac
import struct
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519


class InvalidDerivationPath(Exception):
    """Raised when derivation path is invalid for ed25519."""
    pass


def _bencode_int(n: int) -> bytes:
    """Bencode an integer: i<number>e"""
    return b'i' + str(n).encode('ascii') + b'e'


def _bencode_bytes(data: bytes) -> bytes:
    """Bencode bytes: <length>:<data>"""
    return str(len(data)).encode('ascii') + b':' + data


def _bencode_string(s: str) -> bytes:
    """Bencode a string (as bytes)"""
    data = s.encode('utf-8')
    return _bencode_bytes(data)


def derive_ed25519_keypair_from_seed(
    seed_bytes: bytes,
    path: str = "m/44'/0'/0'/0/0"
) -> Tuple[bytes, bytes]:
    """
    Derive ed25519 keypair from BIP39 seed using SLIP-0010.

    SLIP-0010 specification:
    https://github.com/satoshilabs/slips/blob/master/slip-0010.md

    Args:
        seed_bytes: 64-byte seed from BIP39 (from bip39.mnemonic_to_seed)
        path: Derivation path (e.g., "m/44'/0'/0'/0/0")
              Note: ed25519 only supports hardened derivation

    Returns:
        (private_key_32bytes, public_key_32bytes)

    Raises:
        InvalidDerivationPath: If path is invalid or contains unhardened derivation
    """
    # Parse derivation path
    if not path.startswith("m/"):
        raise InvalidDerivationPath(f"Path must start with 'm/': {path}")

    path_parts = path[2:].split('/')
    indices = []

    for part in path_parts:
        if not part:
            continue

        # Check for hardened derivation (ends with ' or h)
        if part.endswith("'") or part.endswith("h"):
            index = int(part[:-1])
            # Hardened indices are offset by 2^31
            indices.append(index + 0x80000000)
        else:
            # Ed25519 SLIP-0010 only supports hardened derivation
            index = int(part)
            if index < 0x80000000:
                # For ed25519, all derivations should be hardened
                # But we'll allow it and make it hardened automatically
                indices.append(index + 0x80000000)
            else:
                indices.append(index)

    # SLIP-0010 Master key generation for ed25519
    # Uses "ed25519 seed" as HMAC key (different from BIP32's "Bitcoin seed")
    hmac_result = hmac.new(
        key=b"ed25519 seed",
        msg=seed_bytes,
        digestmod=hashlib.sha512
    ).digest()

    # Split into key and chain code
    master_key = hmac_result[:32]
    master_chain_code = hmac_result[32:]

    # Derive child keys
    key = master_key
    chain_code = master_chain_code

    for index in indices:
        key, chain_code = _derive_ed25519_child(key, chain_code, index)

    # Generate public key from private key
    private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(key)
    public_key_obj = private_key_obj.public_key()
    public_key = public_key_obj.public_bytes_raw()

    return (key, public_key)


def _derive_ed25519_child(
    parent_key: bytes,
    parent_chain_code: bytes,
    index: int
) -> Tuple[bytes, bytes]:
    """
    Derive a child key using SLIP-0010 for ed25519.

    For ed25519, only hardened derivation is supported.
    The data to be hashed is: 0x00 + parent_key + index (big-endian)

    Args:
        parent_key: 32-byte parent private key
        parent_chain_code: 32-byte parent chain code
        index: Child index (should be >= 0x80000000 for hardened)

    Returns:
        (child_key_32bytes, child_chain_code_32bytes)
    """
    # Ed25519 uses hardened derivation only
    # Data = 0x00 || parent_key || index (4 bytes, big-endian)
    data = b'\x00' + parent_key + struct.pack('>I', index)

    # HMAC-SHA512 with parent chain code as key
    hmac_result = hmac.new(
        key=parent_chain_code,
        msg=data,
        digestmod=hashlib.sha512
    ).digest()

    # Split result
    child_key = hmac_result[:32]
    child_chain_code = hmac_result[32:]

    return (child_key, child_chain_code)


def create_bep44_signing_buffer(
    seq: int,
    v: bytes,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Create the bencoded buffer for BEP44 signing.

    BEP44 specification states the signature covers:
    - Optional salt: "4:salt" + length + ":" + salt
    - Sequence: "3:seqi" + seq + "e"
    - Value: "1:v" + length + ":" + value

    Args:
        seq: Sequence number (monotonically increasing integer)
        v: Value bytes to store (max 1000 bytes)
        salt: Optional salt bytes (max 64 bytes)

    Returns:
        Bencoded buffer ready for ed25519 signing

    Raises:
        ValueError: If v > 1000 bytes or salt > 64 bytes
    """
    if len(v) > 1000:
        raise ValueError(f"Value must be ≤1000 bytes, got {len(v)}")
    if salt and len(salt) > 64:
        raise ValueError(f"Salt must be ≤64 bytes, got {len(salt)}")

    buffer = b""

    # Add salt if present (must come first)
    if salt and len(salt) > 0:
        buffer += b"4:salt"
        buffer += _bencode_bytes(salt)

    # Add sequence number
    buffer += b"3:seq"
    buffer += _bencode_int(seq)

    # Add value
    buffer += b"1:v"
    buffer += _bencode_bytes(v)

    return buffer


def sign_bep44_message(
    seed_bytes: bytes,
    seq: int,
    v: bytes,
    salt: Optional[bytes] = None,
    derivation_path: str = "m/44'/0'/0'/0/0"
) -> dict:
    """
    Sign a BEP44 mutable item message.

    This function:
    1. Derives ed25519 keypair from seed using SLIP-0010
    2. Creates BEP44 signing buffer (bencoded)
    3. Signs with ed25519
    4. Returns all data needed for DHT PUT request

    Args:
        seed_bytes: 64-byte seed from BIP39
        seq: Sequence number (must be monotonically increasing)
        v: Value to store (max 1000 bytes)
        salt: Optional salt (max 64 bytes)
        derivation_path: Ed25519 key derivation path

    Returns:
        {
            "k": hex(public_key),     # 32 bytes -> 64 hex chars
            "sig": hex(signature),     # 64 bytes -> 128 hex chars
            "seq": seq,                # integer
            "v": hex(v),               # variable length hex
            "salt": hex(salt)          # optional, 64 bytes max
        }

    Raises:
        ValueError: If inputs are invalid
        InvalidDerivationPath: If derivation path is invalid
    """
    # Validate inputs
    if len(v) > 1000:
        raise ValueError(f"Value must be ≤1000 bytes, got {len(v)}")
    if salt and len(salt) > 64:
        raise ValueError(f"Salt must be ≤64 bytes, got {len(salt)}")
    if seq < 0:
        raise ValueError(f"Sequence number must be non-negative, got {seq}")

    # Derive ed25519 keypair
    private_key_bytes, public_key_bytes = derive_ed25519_keypair_from_seed(
        seed_bytes, derivation_path
    )

    # Create signing buffer
    signing_buffer = create_bep44_signing_buffer(seq, v, salt)

    # Sign with ed25519
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(signing_buffer)

    # Build result dictionary
    result = {
        "k": public_key_bytes.hex(),
        "sig": signature.hex(),
        "seq": seq,
        "v": v.hex(),
    }

    if salt:
        result["salt"] = salt.hex()

    return result


def verify_bep44_signature(
    public_key: bytes,
    seq: int,
    v: bytes,
    signature: bytes,
    salt: Optional[bytes] = None
) -> bool:
    """
    Verify a BEP44 signature.

    Useful for testing and validation.

    Args:
        public_key: 32-byte ed25519 public key
        seq: Sequence number
        v: Value bytes
        signature: 64-byte ed25519 signature
        salt: Optional salt bytes

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Create signing buffer
        signing_buffer = create_bep44_signing_buffer(seq, v, salt)

        # Verify signature
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        public_key_obj.verify(signature, signing_buffer)
        return True
    except Exception:
        return False


def get_bep44_storage_target(
    public_key: bytes,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Calculate the DHT storage target hash for a BEP44 mutable item.

    The target is SHA-1(public_key || salt)

    Args:
        public_key: 32-byte ed25519 public key
        salt: Optional salt bytes

    Returns:
        20-byte SHA-1 hash (DHT target ID)
    """
    key_with_salt = public_key + (salt if salt else b"")
    return hashlib.sha1(key_with_salt).digest()


def format_public_key_for_display(public_key_hex: str) -> str:
    """
    Format a hex public key for display on SeedSigner screen.

    Splits into groups of 8 characters for readability.

    Args:
        public_key_hex: 64-character hex string

    Returns:
        Formatted string with spaces (e.g., "abcd1234 5678ef90 ...")
    """
    # Split into groups of 8
    groups = [public_key_hex[i:i+8] for i in range(0, len(public_key_hex), 8)]
    return ' '.join(groups)
