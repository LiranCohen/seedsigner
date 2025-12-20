# BEP44 Ed25519 Signing Support for SeedSigner

## Overview

This implementation adds support for signing BEP44 DHT mutable item messages using ed25519 keys derived from BIP39 seeds. This enables SeedSigner to be used as an air-gapped signing device for BitTorrent DHT operations.

## Features

- ✅ **Ed25519 key derivation** from BIP39 seeds using SLIP-0010 standard
- ✅ **BEP44 message signing** with proper bencode format
- ✅ **UR2 (Uniform Resources) QR codes** for large message support (up to 1000 bytes)
- ✅ **Animated QR codes** using fountain encoding (handles multi-frame scanning)
- ✅ **Air-gapped operation** - all signing happens offline on SeedSigner
- ✅ **Full UI integration** - menu entry, confirmation screens, QR display

## Technical Specifications

### BEP44 Message Format

**Signing Buffer (bencoded):**
```
Without salt: "3:seqi{seq}e1:v{len}:{value}"
With salt:    "4:salt{len}:{salt}3:seqi{seq}e1:v{len}:{value}"
```

**Output Format:**
```json
{
  "k": "hex_public_key_32bytes",
  "sig": "hex_signature_64bytes",
  "seq": sequence_number
}
```

### Key Derivation

Uses **SLIP-0010** for deterministic ed25519 key derivation:
- Default path: `m/44'/0'/0'/0/0`
- Custom paths supported (all hardened derivation)
- Master key: `HMAC-SHA512("ed25519 seed", seed_bytes)`

### QR Code Format

**Input (Signing Request):**
```
UR:BYTES/{cbor_encoded_request}
```

CBOR structure:
- Key 1: `seq` (integer) - sequence number
- Key 2: `value` (bytes) - data to sign (max 1000 bytes)
- Key 3: `salt` (bytes, optional) - salt (max 64 bytes)
- Key 4: `derivation_path` (string) - ed25519 key path

**Output (Signed Result):**
```
UR:BYTES/{cbor_encoded_result}
```

CBOR structure:
- Key 10: `public_key` (bytes) - 32-byte ed25519 public key
- Key 11: `signature` (bytes) - 64-byte ed25519 signature
- Key 1: `seq` (integer) - sequence number (echoed back)

Note: Value and salt are NOT included in output to keep QR size minimal.

## File Structure

### New Files Created

```
src/seedsigner/
├── helpers/
│   ├── ed25519_utils.py          # Ed25519 crypto & BEP44 signing
│   └── bep44_cbor.py              # CBOR encoding/decoding
├── views/
│   └── bep44_views.py             # BEP44 signing flow views
└── tests/
    └── test_ed25519_bep44.py      # Unit tests

docs/
└── BEP44_IMPLEMENTATION.md        # This file
```

### Modified Files

```
requirements.txt                   # Added cryptography>=41.0.0
src/seedsigner/models/
├── qr_type.py                     # Added SIGN_MESSAGE_BEP44 type
├── decode_qr.py                   # Added BEP44 decoder support
└── encode_qr.py                   # Added Bep44QrEncoder classes
src/seedsigner/views/
└── seed_views.py                  # Added menu entry for BEP44
src/seedsigner/gui/screens/
└── seed_screens.py                # Added BEP44 confirmation screens
```

## Usage Flow

### On SeedSigner:

1. **Navigate to Seed** → Select your seed → **"Sign BEP44 message"**
2. **Scan Request QR** - UR:BYTES/... containing signing request
3. **Review Message** - Confirm seq, value size, salt, path
4. **Confirm Public Key** - Verify ed25519 public key
5. **Sign** - Device signs the message
6. **Scan Output QR** - Animated UR:BYTES/... with signature

### Creating a Signing Request (Example):

```python
from seedsigner.helpers.bep44_cbor import encode_bep44_request
from seedsigner.models.encode_qr import Bep44RequestQrEncoder
from urtypes.bytes import Bytes

# Create request
seq = 1
value = b"Hello DHT!"
path = "m/44'/0'/0'/0/0"
salt = b"optional_salt"  # or None

# Encode as CBOR
cbor_data = encode_bep44_request(seq, value, path, salt)

# Create UR QR encoder
encoder = Bep44RequestQrEncoder(
    seq=seq,
    value=value,
    derivation_path=path,
    salt=salt,
    qr_density="M"
)

# Generate QR frames (fountain encoding for large messages)
while True:
    qr_frame = encoder.next_part()
    # Display qr_frame as QR code
    # Animate through frames
```

### Processing Signed Result:

```python
from seedsigner.helpers.bep44_cbor import decode_bep44_result
from urtypes.bytes import Bytes

# After scanning SeedSigner's output QR
# and assembling with URDecoder:

cbor_data = ur_decoder.result_message().cbor
raw_bytes = Bytes.from_cbor(cbor_data).data

# Decode result
result = decode_bep44_result(raw_bytes)

# Extract signature components
public_key = result["public_key"]  # 32 bytes
signature = result["signature"]    # 64 bytes
seq = result["seq"]                # integer

# Now construct DHT PUT message
dht_put_message = {
    "k": public_key,
    "sig": signature,
    "seq": seq,
    "v": original_value,      # From your request
    "salt": original_salt     # If used
}
```

## Testing

### Run Unit Tests:

```bash
cd /home/user/seedsigner
pytest tests/test_ed25519_bep44.py -v
```

### Test Coverage:

- ✅ Ed25519 key derivation (SLIP-0010)
- ✅ Deterministic key generation
- ✅ BEP44 signing buffer creation
- ✅ Bencode formatting
- ✅ Signature creation and verification
- ✅ CBOR encoding/decoding
- ✅ Large value handling (up to 1000 bytes)
- ✅ Salt handling

## Security Considerations

### Key Derivation

- Uses industry-standard SLIP-0010 for ed25519
- Fully deterministic from BIP39 seed
- Same seed+path always produces same keys
- Compatible with other SLIP-0010 implementations

### Air-Gapped Operation

- All cryptographic operations happen on-device
- No network connectivity required
- Keys never leave the device
- Signature displayed via QR code only

### Input Validation

- Value limited to 1000 bytes (BEP44 spec)
- Salt limited to 64 bytes (BEP44 spec)
- Sequence number validated (non-negative)
- Derivation path validated (hardened only)

## Limitations & Future Enhancements

### Current Limitations:

1. **No BIP32 public derivation** - Ed25519 uses hardened derivation only
2. **Output doesn't include value/salt** - Keeps QR small, but DHT client must track
3. **No custom UR type** - Uses generic `UR:BYTES` instead of `UR:CRYPTO-BEP44`

### Future Enhancements:

1. **Add settings toggle** - Enable/disable BEP44 signing
2. **Custom UR registry** - Register `UR:CRYPTO-BEP44` type
3. **Multi-key support** - Sign with multiple keys in one session
4. **Verify mode** - Verify BEP44 signatures without signing

## Dependencies

### New Dependency:

- **cryptography >= 41.0.0** - For ed25519 operations

### Existing Dependencies Used:

- **urtypes** - For UR:BYTES CBOR encoding
- **seedsigner.helpers.ur2** - For fountain encoding/decoding

## Compatibility

- **Python**: 3.7+
- **SeedSigner**: Compatible with existing seed management
- **Hardware**: Works on all SeedSigner-supported hardware
- **BIP39 Seeds**: Works with 12-word and 24-word seeds

## References

- [BEP44: Storing arbitrary data in the DHT](https://bittorrent.org/beps/bep_0044.html)
- [SLIP-0010: Universal private key derivation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [UR (Uniform Resources) Specification](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
- [Ed25519: RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

## Contributing

For bugs, feature requests, or questions:
- Open an issue on GitHub
- Include logs and test vectors if applicable
- Specify SeedSigner version and hardware

## License

This implementation follows the same license as SeedSigner.
