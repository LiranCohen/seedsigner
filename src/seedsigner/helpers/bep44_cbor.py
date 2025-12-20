"""
CBOR encoding/decoding for BEP44 messages to work with UR2 QR codes.

This module handles the serialization of BEP44 signing requests and results
for transmission via UR2 (Uniform Resources) animated QR codes.
"""

from typing import Optional, Dict, Any
from seedsigner.helpers.ur2.cbor_lite import CBOREncoder, CBORDecoder


# CBOR map keys for BEP44 request (input QR)
KEY_SEQ = 1          # Sequence number (integer)
KEY_VALUE = 2        # Value to sign (bytes)
KEY_SALT = 3         # Optional salt (bytes)
KEY_PATH = 4         # Derivation path (string)

# CBOR map keys for BEP44 result (output QR)
KEY_PUBLIC_KEY = 10  # Public key (bytes)
KEY_SIGNATURE = 11   # Signature (bytes)
# seq, value, salt reuse keys 1, 2, 3


def encode_bep44_request(
    seq: int,
    v: bytes,
    derivation_path: str,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Encode a BEP44 signing request as CBOR.

    This is used for the INPUT QR code (UR:BYTES/... format).
    The SeedSigner scans this to get the signing request.

    Args:
        seq: Sequence number
        v: Value to sign (max 1000 bytes)
        derivation_path: Ed25519 key derivation path
        salt: Optional salt (max 64 bytes)

    Returns:
        CBOR-encoded bytes
    """
    encoder = CBOREncoder()

    # Encode as CBOR map
    map_size = 3  # seq, value, path
    if salt:
        map_size += 1

    encoder.encodeMapSize(map_size)

    # Add sequence number
    encoder.encodeInteger(KEY_SEQ)
    encoder.encodeInteger(seq)

    # Add value
    encoder.encodeInteger(KEY_VALUE)
    encoder.encodeBytes(v)

    # Add derivation path
    encoder.encodeInteger(KEY_PATH)
    encoder.encodeText(derivation_path)

    # Add salt if present
    if salt:
        encoder.encodeInteger(KEY_SALT)
        encoder.encodeBytes(salt)

    return bytes(encoder.get_bytes())


def decode_bep44_request(cbor_data: bytes) -> Dict[str, Any]:
    """
    Decode a BEP44 signing request from CBOR.

    Args:
        cbor_data: CBOR-encoded bytes

    Returns:
        {
            "seq": int,
            "value": bytes,
            "derivation_path": str,
            "salt": bytes (optional)
        }

    Raises:
        Exception: If CBOR decoding fails or required fields missing
    """
    decoder = CBORDecoder(cbor_data)

    # Decode map
    map_size, _ = decoder.decodeMapSize()  # Returns (value, length) tuple

    result = {}

    for _ in range(map_size):
        key, _ = decoder.decodeInteger()  # Returns (value, length) tuple

        if key == KEY_SEQ:
            result["seq"], _ = decoder.decodeInteger()
        elif key == KEY_VALUE:
            result["value"], _ = decoder.decodeBytes()
        elif key == KEY_PATH:
            path_bytes, _ = decoder.decodeText()
            result["derivation_path"] = path_bytes.decode('utf-8')
        elif key == KEY_SALT:
            result["salt"], _ = decoder.decodeBytes()
        else:
            # Unknown key, skip value
            decoder.skip()

    # Validate required fields
    if "seq" not in result:
        raise ValueError("Missing required field: seq")
    if "value" not in result:
        raise ValueError("Missing required field: value")
    if "derivation_path" not in result:
        raise ValueError("Missing required field: derivation_path")

    return result


def encode_bep44_result(
    public_key: bytes,
    signature: bytes,
    seq: int,
    include_value: bool = False,
    v: Optional[bytes] = None,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Encode a BEP44 signing result as CBOR.

    This is used for the OUTPUT QR code (UR:BYTES/... format).
    The DHT client scans this to get the signature.

    Args:
        public_key: 32-byte ed25519 public key
        signature: 64-byte ed25519 signature
        seq: Sequence number (echoed back)
        include_value: Whether to include value in result (usually False)
        v: Value bytes (only if include_value=True)
        salt: Optional salt bytes (only if include_value=True)

    Returns:
        CBOR-encoded bytes
    """
    encoder = CBOREncoder()

    # Calculate map size
    map_size = 3  # public_key, signature, seq
    if include_value and v is not None:
        map_size += 1
    if include_value and salt is not None:
        map_size += 1

    encoder.encodeMapSize(map_size)

    # Add public key
    encoder.encodeInteger(KEY_PUBLIC_KEY)
    encoder.encodeBytes(public_key)

    # Add signature
    encoder.encodeInteger(KEY_SIGNATURE)
    encoder.encodeBytes(signature)

    # Add sequence number
    encoder.encodeInteger(KEY_SEQ)
    encoder.encodeInteger(seq)

    # Optionally add value and salt
    if include_value and v is not None:
        encoder.encodeInteger(KEY_VALUE)
        encoder.encodeBytes(v)

    if include_value and salt is not None:
        encoder.encodeInteger(KEY_SALT)
        encoder.encodeBytes(salt)

    return bytes(encoder.get_bytes())


def decode_bep44_result(cbor_data: bytes) -> Dict[str, Any]:
    """
    Decode a BEP44 signing result from CBOR.

    Useful for testing.

    Args:
        cbor_data: CBOR-encoded bytes

    Returns:
        {
            "public_key": bytes,
            "signature": bytes,
            "seq": int,
            "value": bytes (optional),
            "salt": bytes (optional)
        }

    Raises:
        Exception: If CBOR decoding fails or required fields missing
    """
    decoder = CBORDecoder(cbor_data)

    # Decode map
    map_size, _ = decoder.decodeMapSize()  # Returns (value, length) tuple

    result = {}

    for _ in range(map_size):
        key, _ = decoder.decodeInteger()  # Returns (value, length) tuple

        if key == KEY_PUBLIC_KEY:
            result["public_key"], _ = decoder.decodeBytes()
        elif key == KEY_SIGNATURE:
            result["signature"], _ = decoder.decodeBytes()
        elif key == KEY_SEQ:
            result["seq"], _ = decoder.decodeInteger()
        elif key == KEY_VALUE:
            result["value"], _ = decoder.decodeBytes()
        elif key == KEY_SALT:
            result["salt"], _ = decoder.decodeBytes()
        else:
            # Unknown key, skip value
            decoder.skip()

    # Validate required fields
    if "public_key" not in result:
        raise ValueError("Missing required field: public_key")
    if "signature" not in result:
        raise ValueError("Missing required field: signature")
    if "seq" not in result:
        raise ValueError("Missing required field: seq")

    return result


def format_bep44_result_for_dht(result_dict: Dict[str, Any]) -> Dict[str, str]:
    """
    Format BEP44 result for DHT PUT request (hex encoding).

    Converts bytes to hex strings for JSON serialization.

    Args:
        result_dict: Result from decode_bep44_result or similar

    Returns:
        {
            "k": hex_string,
            "sig": hex_string,
            "seq": int,
            "v": hex_string (optional),
            "salt": hex_string (optional)
        }
    """
    formatted = {
        "k": result_dict["public_key"].hex(),
        "sig": result_dict["signature"].hex(),
        "seq": result_dict["seq"]
    }

    if "value" in result_dict:
        formatted["v"] = result_dict["value"].hex()

    if "salt" in result_dict:
        formatted["salt"] = result_dict["salt"].hex()

    return formatted
