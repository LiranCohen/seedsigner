# Deploying DNS Packet Signing to SeedSigner

This guide covers deployment of the ed25519/BEP44/DNS packet signing feature to actual SeedSigner hardware.

> **Note:** For general SeedSigner setup and local development, see [raspberry_pi_os_build_instructions.md](raspberry_pi_os_build_instructions.md)

## Quick Deployment Methods

### Method 1: Using the Deployment Package (Fastest)

For quick testing on existing SeedSigner installations:

```bash
# Create deployment package
./tools/package_for_deployment.sh

# This creates: seedsigner-deployment/seedsigner-dns-TIMESTAMP.tar.gz
# Copy to SD card and extract, then:
cd seedsigner-dns-*/
./install.sh /path/to/seedsigner  # e.g., /opt/seedsigner

# Install dnslib dependency
pip3 install dnslib>=0.9.23
```

### Method 2: Building SeedSigner OS Image (Production)

For production deployment, build a complete SeedSigner OS image:

1. **Clone SeedSigner OS repository:**
   ```bash
   git clone https://github.com/SeedSigner/seedsigner-os.git
   cd seedsigner-os
   ```

2. **Point to your DNS-enabled branch:**

   Edit `external_config/package/seedsigner/seedsigner.mk`:
   ```makefile
   SEEDSIGNER_SITE = https://github.com/YOUR_USERNAME/seedsigner.git
   SEEDSIGNER_VERSION = claude/add-ed25519-support-DgnCJ
   ```

3. **Add dnslib dependency:**

   In the same file, add to dependencies or install during build:
   ```makefile
   SEEDSIGNER_DEPENDENCIES += python-dnslib
   ```

4. **Build the image:**
   ```bash
   ./opt/build.sh --pi02w  # or --pi0, --pi4
   # Takes 30-60 minutes
   ```

5. **Flash to SD card:**
   ```bash
   # Use Balena Etcher (recommended): https://www.balena.io/etcher/
   # Or dd:
   sudo dd if=output/images/sdcard.img of=/dev/sdX bs=4M status=progress
   ```

## What's Included

**New files:**
- `src/seedsigner/helpers/dns_utils.py` - DNS packet parsing
- `src/seedsigner/views/bep44_views.py` - BEP44 signing UI flow

**Modified files:**
- `src/seedsigner/helpers/ed25519_utils.py` - Ed25519 key derivation
- `src/seedsigner/helpers/bep44_cbor.py` - CBOR encoding
- `src/seedsigner/helpers/ur2/cbor_lite.py` - Bug fixes
- `src/seedsigner/models/{decode_qr,encode_qr,qr_type}.py` - BEP44 QR support
- `src/seedsigner/views/seed_views.py` - Menu integration
- `src/seedsigner/gui/screens/seed_screens.py` - DNS-specific screens
- `requirements.txt` - Added dnslib dependency

## Testing

After deployment, test with the abandon seed:
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

1. Navigate to: **Seeds → [Test Seed] → Sign BEP44 message**
2. Generate test QR: `python3 tools/generate_bep44_test_qr.py`
3. Scan QR with SeedSigner
4. Verify you see "DNS Message" screen with parsed records

## Troubleshooting

**Missing dnslib:** DNS signing works without it, but records won't be parsed (shows basic header info only)

**Menu option not appearing:** Verify `seed_views.py` was updated and restart SeedSigner

**For more details:**
- Usage guide: [DNS_SIGNING.md](DNS_SIGNING.md)
- Technical details: [BEP44_IMPLEMENTATION.md](BEP44_IMPLEMENTATION.md)
- Simulation testing: `python3 tools/demo_dns_signing.py`
