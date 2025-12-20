# BEP44 Testing Tools for SeedSigner

This directory contains testing utilities for the BEP44 ed25519 signing implementation.

## Tools Overview

### 1. `generate_bep44_test_qr.py`
Generates test BEP44 signing request QR codes that can be scanned by SeedSigner.

**Features:**
- Creates UR:BYTES formatted QR codes
- Multiple test scenarios (simple, with salt, large values, custom paths)
- Displays QR codes directly in terminal
- Tests fountain encoding for large messages

**Usage:**
```bash
cd /home/user/seedsigner
python3 tools/generate_bep44_test_qr.py
```

### 2. `verify_bep44_signature.py`
Verifies ed25519 signatures produced by SeedSigner.

**Features:**
- Validates signature cryptographically
- Calculates DHT storage target
- Displays DHT PUT message format
- Interactive verification workflow

**Usage:**
```bash
cd /home/user/seedsigner
python3 tools/verify_bep44_signature.py
```

## End-to-End Testing Workflow

### Prerequisites

1. **Install dependencies:**
   ```bash
   pip install qrcode[pil]
   pip install -r requirements.txt
   ```

2. **Ensure SeedSigner is set up:**
   - Have a test seed loaded (DO NOT use real funds seed for testing!)
   - SeedSigner device is powered on and ready

### Step-by-Step Testing

#### Test 1: Simple BEP44 Signing (No Salt)

1. **Generate test QR code:**
   ```bash
   python3 tools/generate_bep44_test_qr.py
   ```
   This will display a QR code in your terminal.

2. **On SeedSigner:**
   - Navigate to: Seeds → [Your Test Seed] → **Sign BEP44 message**
   - Scan the QR code displayed in your terminal
   - Review message details screen:
     - Sequence number: 1
     - Value size: ~54 bytes
     - Value preview: "Hello from SeedSigner!..."
     - Path: m/44'/0'/0'/0/0
     - Salt: None
   - Press "Continue"

3. **Confirm public key:**
   - SeedSigner displays derived ed25519 public key
   - Record this for verification (optional)
   - Press "Continue"

4. **Scan result QR:**
   - SeedSigner displays animated QR with signature
   - Use phone or QR scanner to capture the result
   - The result QR contains: public_key, signature, seq

5. **Verify signature:**
   ```bash
   python3 tools/verify_bep44_signature.py
   ```
   - Choose option 1 (Verify from hex input)
   - Enter the values from SeedSigner's output:
     - Public key (64 hex chars)
     - Signature (128 hex chars)
     - Sequence: 1
     - Value: "Hello from SeedSigner!..." (in hex)
     - Salt: (leave empty)

6. **Expected result:**
   ```
   ✅ Signature is VALID!

   DHT Storage Target: <20-byte hex>

   --- DHT PUT Message Format ---
   {
     "k": "...",
     "sig": "...",
     "seq": 1,
     "v": "..."
   }
   ```

#### Test 2: BEP44 with Salt

Follow the same workflow, but when prompted in `generate_bep44_test_qr.py`, continue to test 2.

**Expected differences:**
- Salt will be displayed on confirmation screen
- Storage target will be different (SHA1(pubkey + salt))
- DHT PUT message will include "salt" field

#### Test 3: Large Message (Animated QR)

This test uses a 500-byte value requiring fountain encoding.

**Expected behavior:**
- Scanner on SeedSigner will need to capture multiple frames
- Progress indicator shows frame collection (e.g., "Collecting: 3/10 frames")
- Once complete, same workflow as Test 1
- Result QR may also be animated (depending on qr_density setting)

#### Test 4: Custom Derivation Path

Tests ed25519 key derivation with non-standard path.

**Expected:**
- Different public key than Test 1 (same seed, different path)
- Signature validates correctly with the different key

## Troubleshooting

### QR Code Won't Scan
- **Issue:** Terminal QR is too small or unclear
- **Solution:**
  - Increase terminal font size
  - Use `qr_density="L"` for larger QR codes (lower error correction)
  - Generate QR image file instead of terminal display

### "Invalid BEP44 Request" Error on SeedSigner
- **Issue:** QR data not recognized
- **Solution:**
  - Verify UR:BYTES format is correct
  - Check CBOR encoding with unit tests
  - Ensure all dependencies are installed

### Signature Verification Fails
- **Issue:** Signature doesn't match
- **Causes:**
  1. Wrong value entered (ensure exact hex match)
  2. Wrong salt (must match signing request exactly)
  3. Sequence number mismatch
  4. Bug in signing implementation
- **Solution:**
  - Re-run unit tests: `pytest tests/test_ed25519_bep44.py -v`
  - Check logs for errors
  - Verify seed is consistent

### Animated QR Not Completing
- **Issue:** Scanner gets stuck collecting frames
- **Solution:**
  - Hold steady and scan all frames sequentially
  - Each frame only needs to be captured once
  - Reset scanner and try again
  - Check fountain encoder settings

## Test Vectors

### Known Test Vector (for automated testing)

**Seed (DO NOT use for real funds):**
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

**BIP39 Seed (first 32 bytes hex):**
```
5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
```

**Expected Results (path m/44'/0'/0'/0/0):**

| Field | Value |
|-------|-------|
| Ed25519 Public Key | TBD - run derive_ed25519_keypair_from_seed() |
| Signature for "test" | TBD - run sign_bep44_message() |

To generate test vectors:
```python
from mnemonic import Mnemonic
from seedsigner.helpers.ed25519_utils import derive_ed25519_keypair_from_seed, sign_bep44_message

# Generate seed
mnemo = Mnemonic("english")
seed_bytes = mnemo.to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

# Derive key
private_key, public_key = derive_ed25519_keypair_from_seed(seed_bytes, "m/44'/0'/0'/0/0")
print(f"Public Key: {public_key.hex()}")

# Sign test message
result = sign_bep44_message(seed_bytes, seq=1, v=b"test", derivation_path="m/44'/0'/0'/0/0")
print(f"Signature: {result['sig']}")
```

## Integration with DHT Clients

After SeedSigner signs a BEP44 message, use the signature in a DHT PUT request:

```python
import bencodepy
import hashlib
from libtorrent import dht_mutable_put

# From SeedSigner result
public_key = bytes.fromhex("...")  # 32 bytes
signature = bytes.fromhex("...")   # 64 bytes
seq = 1
value = b"Your DHT value"
salt = b"optional_salt"  # or None

# Create DHT PUT message
message = {
    b"k": public_key,
    b"sig": signature,
    b"seq": seq,
    b"v": value,
}

if salt:
    message[b"salt"] = salt
    target = hashlib.sha1(public_key + salt).digest()
else:
    target = hashlib.sha1(public_key).digest()

# Send to DHT
# (implementation depends on your DHT client library)
# libtorrent example:
# dht_mutable_put(target, message)
```

## Advanced Testing

### Performance Testing
```bash
# Test with maximum size value (1000 bytes)
# Measure QR generation time
# Measure signing time on device
```

### Compatibility Testing
```bash
# Verify signatures with external tools:
# - python-libtorrent
# - openssl (ed25519)
# - trezor-crypto
```

### Stress Testing
```bash
# Sign 100 messages in sequence
# Verify memory doesn't leak
# Verify QR animation doesn't stutter
```

## Reporting Issues

If you encounter problems:

1. **Collect logs:**
   - SeedSigner console output (if accessible)
   - Error messages from tools
   - Screenshots of failures

2. **Provide context:**
   - Hardware: Raspberry Pi model
   - SeedSigner version: Git commit hash
   - Test case that failed

3. **Create minimal reproduction:**
   - Exact steps to reproduce
   - Expected vs actual behavior

4. **Submit:**
   - GitHub issue with logs and context
   - Include test vectors if applicable

## References

- [BEP44 Specification](https://bittorrent.org/beps/bep_0044.html)
- [SLIP-0010: Ed25519 Derivation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [UR Specification](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
- [Ed25519: RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)
- [Main Implementation Docs](../docs/BEP44_IMPLEMENTATION.md)
