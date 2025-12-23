# Deploying DNS Packet Signing to SeedSigner Hardware

This guide explains how to get the DNS packet signing feature onto your actual SeedSigner device.

## Quick Answer

Copy these files from your `claude/add-ed25519-support-DgnCJ` branch to your SeedSigner's SD card:

```
src/seedsigner/helpers/
├── bep44_cbor.py          (modified)
├── dns_utils.py           (new)
├── ed25519_utils.py       (modified)
└── ur2/cbor_lite.py       (modified - bug fixes)

src/seedsigner/models/
├── decode_qr.py           (modified)
├── encode_qr.py           (modified)
└── qr_type.py             (modified)

src/seedsigner/views/
├── bep44_views.py         (new)
└── seed_views.py          (modified)

src/seedsigner/gui/screens/
└── seed_screens.py        (modified)

requirements.txt           (modified - added dnslib)
```

## Deployment Methods

### Method 1: Full Repository Update (Recommended)

If you're running SeedSigner from a Git repository on the SD card:

```bash
# On your computer (where you have this branch)
cd /home/user/seedsigner

# Create a tarball of the branch
git archive --format=tar.gz --output=seedsigner-dns.tar.gz claude/add-ed25519-support-DgnCJ

# Copy to SD card (insert SD card, mount it)
cp seedsigner-dns.tar.gz /path/to/sdcard/

# On the Raspberry Pi (or extract on computer and copy)
cd /path/to/seedsigner
tar -xzf seedsigner-dns.tar.gz
```

### Method 2: Manual File Copy (If you have custom modifications)

1. **Mount your SeedSigner SD card** on your computer

2. **Navigate to the SeedSigner directory** on the SD card (usually `/home/seedsigner/seedsigner` or `/opt/seedsigner`)

3. **Copy the modified/new files:**

```bash
# Set SD card path
SDCARD="/path/to/your/sdcard/seedsigner"

# Copy new helper
cp src/seedsigner/helpers/dns_utils.py $SDCARD/src/seedsigner/helpers/

# Copy modified helpers
cp src/seedsigner/helpers/bep44_cbor.py $SDCARD/src/seedsigner/helpers/
cp src/seedsigner/helpers/ed25519_utils.py $SDCARD/src/seedsigner/helpers/
cp src/seedsigner/helpers/ur2/cbor_lite.py $SDCARD/src/seedsigner/helpers/ur2/

# Copy modified models
cp src/seedsigner/models/decode_qr.py $SDCARD/src/seedsigner/models/
cp src/seedsigner/models/encode_qr.py $SDCARD/src/seedsigner/models/
cp src/seedsigner/models/qr_type.py $SDCARD/src/seedsigner/models/

# Copy new views
cp src/seedsigner/views/bep44_views.py $SDCARD/src/seedsigner/views/

# Copy modified views and screens
cp src/seedsigner/views/seed_views.py $SDCARD/src/seedsigner/views/
cp src/seedsigner/gui/screens/seed_screens.py $SDCARD/src/seedsigner/gui/screens/

# Copy updated requirements
cp requirements.txt $SDCARD/
```

### Method 3: Direct Git Clone on SD Card

If you have network access on your Raspberry Pi:

```bash
# SSH into your SeedSigner (if accessible)
ssh pi@seedsigner.local  # or whatever your hostname is

# Navigate to SeedSigner directory
cd /opt/seedsigner  # or wherever it's installed

# Add your fork as a remote
git remote add dns-signing https://github.com/YOUR_USERNAME/seedsigner.git

# Fetch the branch
git fetch dns-signing claude/add-ed25519-support-DgnCJ

# Checkout the branch
git checkout claude/add-ed25519-support-DgnCJ
```

## Installing Dependencies

After copying the files, you need to install the new dependency (`dnslib`):

### Option A: On the Raspberry Pi (if network connected)

```bash
# SSH into the Pi
ssh pi@seedsigner.local

# Activate virtual environment (if SeedSigner uses one)
source /path/to/venv/bin/activate

# Install dependencies
pip3 install dnslib>=0.9.23

# Or install all requirements
pip3 install -r requirements.txt
```

### Option B: Pre-install on SD Card (Offline)

On your computer with internet:

```bash
# Download dnslib wheel
pip3 download dnslib -d ./wheels/

# Copy wheels to SD card
cp -r wheels /path/to/sdcard/

# On the Pi (offline):
pip3 install --no-index --find-links=/path/to/wheels dnslib
```

### Option C: Already Bundled (if using seedsigner-os image)

If you're using the official SeedSigner OS image, you may need to rebuild the image with the updated requirements.txt. See: https://github.com/SeedSigner/seedsigner-os

## Verification

After deployment, verify it works:

1. **Boot your SeedSigner**

2. **Load a test seed** (DO NOT use real funds seed!)
   - Use the test mnemonic: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`

3. **Navigate to BEP44 signing:**
   ```
   Seeds → [Your Test Seed] → Sign BEP44 message
   ```

4. **Generate a test QR code** on your computer:
   ```bash
   python3 tools/generate_bep44_test_qr.py
   ```

5. **Scan the QR** with your SeedSigner

6. **Verify you see:**
   - "DNS Message" screen (not "BEP44 Message")
   - Parsed DNS records (A, AAAA, TXT)
   - Timestamp in human-readable format
   - "Ed25519 Public Key" screen with z-base-32 domain ID

## File Checklist

### New Files (must copy):
- ✅ `src/seedsigner/helpers/dns_utils.py`
- ✅ `src/seedsigner/views/bep44_views.py`

### Modified Files (must update):
- ✅ `src/seedsigner/helpers/bep44_cbor.py`
- ✅ `src/seedsigner/helpers/ed25519_utils.py`
- ✅ `src/seedsigner/helpers/ur2/cbor_lite.py` (bug fixes)
- ✅ `src/seedsigner/models/decode_qr.py`
- ✅ `src/seedsigner/models/encode_qr.py`
- ✅ `src/seedsigner/models/qr_type.py`
- ✅ `src/seedsigner/views/seed_views.py`
- ✅ `src/seedsigner/gui/screens/seed_screens.py`
- ✅ `requirements.txt`

### Optional (for testing):
- `tools/generate_bep44_test_qr.py`
- `tools/verify_bep44_signature.py`
- `tools/demo_dns_signing.py`
- `tests/test_dns_packets.py`
- `docs/DNS_SIGNING.md`

## Troubleshooting

### "ModuleNotFoundError: No module named 'dnslib'"

**Cause:** dnslib not installed

**Solution:**
```bash
pip3 install dnslib
```

**Workaround:** DNS signing still works, but records won't be parsed (will show basic header info only)

### "Menu option 'Sign BEP44 message' not appearing"

**Cause:** `seed_views.py` not updated correctly

**Solution:** Re-copy `src/seedsigner/views/seed_views.py` and restart SeedSigner

### Screen shows generic "BEP44 Message" instead of "DNS Message"

**Cause:** `bep44_views.py` not updated or `dns_utils.py` not copied

**Solution:**
- Verify `src/seedsigner/views/bep44_views.py` exists
- Verify `src/seedsigner/helpers/dns_utils.py` exists
- Restart SeedSigner

### Signature verification fails

**Cause:** Possible version mismatch or incomplete update

**Solution:**
- Ensure ALL files are updated (check modified dates)
- Re-copy `ed25519_utils.py` and `bep44_cbor.py`
- Run unit tests: `PYTHONPATH=src pytest tests/test_ed25519_bep44.py -v`

## SeedSigner OS Build

If you're building a custom SeedSigner OS image:

1. Fork the seedsigner-os repo: https://github.com/SeedSigner/seedsigner-os
2. Update the SeedSigner submodule to point to your branch
3. Rebuild the image with buildroot

See seedsigner-os README for build instructions.

## Security Note

⚠️ **IMPORTANT**: Always test with a test seed first!

Test seed (DO NOT use for real funds):
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Only use with real seeds after thoroughly testing on hardware.

## What Changed Summary

**User-facing changes:**
- New menu option: "Sign BEP44 message"
- DNS messages show parsed records instead of hex
- Z-base-32 domain identifiers displayed
- Human-readable timestamps

**Technical changes:**
- Ed25519 key derivation (SLIP-0010)
- BEP44 signing with bencode
- DNS packet parsing (RFC 1035)
- UR2 QR encoding for large messages
- Automatic DNS packet detection

**Backward compatible:**
- Generic BEP44 messages still work
- All existing functionality unchanged
- Optional dependency (dnslib)

## Need Help?

- Test in simulation first: `python3 tools/demo_dns_signing.py`
- Run unit tests: `PYTHONPATH=src pytest tests/ -v`
- Check logs on device (if accessible)
- Verify file MD5 checksums match

## Summary

**Minimum deployment:**
1. Copy 11 modified/new Python files to SD card
2. Update requirements.txt
3. Install dnslib (or skip for basic functionality)
4. Reboot SeedSigner
5. Test with abandon seed + generated QR code

**That's it!** 🚀
