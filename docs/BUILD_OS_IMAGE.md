# Building SeedSigner OS Image with DNS Packet Signing

The **proper way** to deploy this to hardware is to build a complete SeedSigner OS image that includes all the DNS packet signing features.

## Overview

SeedSigner uses **seedsigner-os** (based on Buildroot) to create bootable Raspberry Pi images. Instead of manually copying files, you build a complete OS image and flash it to your SD card.

## Quick Start

### 1. Clone SeedSigner OS

```bash
git clone https://github.com/SeedSigner/seedsigner-os.git
cd seedsigner-os
```

### 2. Point to Your Branch

Edit `opt/build.sh` or the build configuration to use your SeedSigner branch:

**Option A: Edit the Buildroot config**

```bash
# Edit the external tree configuration
nano external_config/package/seedsigner/seedsigner.mk
```

Change the repository and version:
```makefile
SEEDSIGNER_SITE = https://github.com/YOUR_USERNAME/seedsigner.git
SEEDSIGNER_VERSION = claude/add-ed25519-support-DgnCJ
```

**Option B: Use a local path**

If you have your modified SeedSigner locally:
```makefile
SEEDSIGNER_SITE = /path/to/your/local/seedsigner
SEEDSIGNER_SITE_METHOD = local
```

### 3. Add dnslib Dependency

Edit `external_config/package/seedsigner/seedsigner.mk`:

```makefile
# Add to dependencies
SEEDSIGNER_DEPENDENCIES += python-dnslib

# Or if it's not packaged, add as a Python dependency
define SEEDSIGNER_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 $(@D)/src/main.py $(TARGET_DIR)/opt/src/main.py
    # ... existing commands ...
    $(HOST_DIR)/bin/pip3 install dnslib>=0.9.23 -t $(TARGET_DIR)/opt/lib/python3.11/site-packages
endef
```

### 4. Build the Image

```bash
# Run the build (this takes 30-60 minutes)
./opt/build.sh

# Or for specific hardware:
./opt/build.sh --pi02w      # Pi Zero 2 W
./opt/build.sh --pi0        # Pi Zero
./opt/build.sh --pi4        # Pi 4
```

### 5. Flash to SD Card

```bash
# Find your SD card
lsblk

# Flash the image (replace sdX with your SD card)
sudo dd if=output/images/sdcard.img of=/dev/sdX bs=4M status=progress
sync
```

**Or use Balena Etcher (recommended):**
1. Download Balena Etcher: https://www.balena.io/etcher/
2. Select `output/images/sdcard.img`
3. Select your SD card
4. Flash!

### 6. Boot Your SeedSigner

1. Insert SD card into Raspberry Pi
2. Power on
3. Navigate to: **Seeds → [Test Seed] → Sign BEP44 message**
4. Test with QR code from `tools/generate_bep44_test_qr.py`

## Using Pre-Built SeedSigner OS

If you don't want to build from source, you can modify an existing SeedSigner OS image:

### Method 1: Mount and Modify Image

```bash
# Download official SeedSigner OS image
wget https://github.com/SeedSigner/seedsigner-os/releases/latest/download/seedsigner_os.0.7.0.pi02w.img

# Mount the image
sudo losetup -fP seedsigner_os.0.7.0.pi02w.img
sudo losetup -a  # Find the loop device (e.g., /dev/loop0)

# Mount the root partition
sudo mount /dev/loop0p2 /mnt

# Copy your files
sudo cp -r /path/to/your/seedsigner/src/* /mnt/opt/seedsigner/src/
sudo cp /path/to/your/requirements.txt /mnt/opt/seedsigner/

# Install dnslib
sudo chroot /mnt pip3 install dnslib>=0.9.23

# Unmount
sudo umount /mnt
sudo losetup -d /dev/loop0

# Flash modified image to SD card
sudo dd if=seedsigner_os.0.7.0.pi02w.img of=/dev/sdX bs=4M status=progress
```

### Method 2: Modify Live System

1. Flash official SeedSigner OS to SD card
2. Boot the Pi with a keyboard connected
3. Drop to console (if possible) or SSH if enabled
4. Copy files via USB stick or network
5. Install dnslib: `pip3 install dnslib`
6. Reboot

## Using Our Pre-Packaged Deployment

We've made this easier with the deployment package:

```bash
# Create deployment package
./tools/package_for_deployment.sh

# This creates: seedsigner-deployment/seedsigner-dns-TIMESTAMP.tar.gz

# Copy to USB stick, then on SeedSigner:
# 1. Mount USB stick
# 2. Extract tarball to /tmp
# 3. Run: cd /tmp/seedsigner-dns-* && ./install.sh /opt/seedsigner
# 4. Install dnslib: pip3 install dnslib
# 5. Reboot
```

## Docker Build (Advanced)

For reproducible builds:

```bash
# Clone seedsigner-os
git clone https://github.com/SeedSigner/seedsigner-os.git
cd seedsigner-os

# Modify to use your branch (as above)

# Build in Docker
docker run --rm -it \
  -v $PWD:/seedsigner-os \
  -v $PWD/output:/seedsigner-os/output \
  buildroot/base:latest \
  /bin/bash -c "cd /seedsigner-os && ./opt/build.sh"
```

## GitHub Actions Build

Create a fork of seedsigner-os and set up GitHub Actions to automatically build images:

```yaml
# .github/workflows/build.yml
name: Build SeedSigner OS

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build Image
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential git
          ./opt/build.sh --pi02w
      - name: Upload Artifact
        uses: actions/upload-artifact@v2
        with:
          name: seedsigner-dns-image
          path: output/images/sdcard.img
```

## Verification Checklist

After flashing and booting:

- [ ] SeedSigner boots normally
- [ ] Main menu appears
- [ ] Can load a test seed
- [ ] "Sign BEP44 message" option appears in seed menu
- [ ] Can scan test QR code
- [ ] DNS records are displayed (not just hex)
- [ ] Shows "DNS Message" screen
- [ ] Shows "Ed25519 Public Key" with z-base-32
- [ ] Can complete signing flow
- [ ] Result QR displays correctly

## Troubleshooting

### Build fails with "dnslib not found"

Add dnslib to Buildroot packages or install it during the build:

```makefile
define SEEDSIGNER_INSTALL_EXTRA_CMDS
    $(HOST_DIR)/bin/pip3 install dnslib -t $(TARGET_DIR)/opt/lib/python
endef
```

### Image too large for SD card

Buildroot creates minimal images. If size is an issue:
- Use Pi Zero config (smaller)
- Remove unnecessary packages
- Check output/images/sdcard.img size

### Boot fails after flashing

- Verify SD card is not corrupted
- Try re-flashing with Balena Etcher
- Check Pi hardware (power, connections)
- Verify you used the correct Pi model build

## Recommended Approach

For most users, we recommend:

**Quick Testing:**
```bash
# Use deployment package on existing SeedSigner
./tools/package_for_deployment.sh
# Copy to SD card, run install.sh
```

**Production Deployment:**
```bash
# Build full OS image
git clone https://github.com/SeedSigner/seedsigner-os.git
# Modify to use your branch
./opt/build.sh --pi02w
# Flash output/images/sdcard.img
```

## Official SeedSigner OS Repository

- **Repository**: https://github.com/SeedSigner/seedsigner-os
- **Releases**: https://github.com/SeedSigner/seedsigner-os/releases
- **Documentation**: https://github.com/SeedSigner/seedsigner-os/blob/main/README.md

## Creating a Release

To share your DNS-enabled SeedSigner build:

1. Fork seedsigner-os
2. Update to use your SeedSigner branch
3. Build the image
4. Create a GitHub release with the image
5. Users can download and flash directly

Example release:
```
SeedSigner v0.7.0 + DNS Packet Signing

Features:
- All standard SeedSigner features
- Ed25519 key derivation
- BEP44 DHT message signing
- DNS packet parsing and display
- Z-base-32 domain identifiers

Installation:
1. Download seedsigner-dns-v0.7.0-pi02w.img
2. Flash to SD card with Balena Etcher
3. Boot on Raspberry Pi Zero 2 W
4. Test with abandon seed
```

## Summary

**Option 1: Quick Test (Deployment Package)**
- ✓ Fast (5 minutes)
- ✓ No build required
- ✓ Works on existing SeedSigner
- ✗ Requires manual file copying

**Option 2: Build OS Image (Recommended)**
- ✓ Clean installation
- ✓ Reproducible builds
- ✓ Professional deployment
- ✗ Requires build tools (30-60 min build)

**Option 3: Modify Existing Image**
- ✓ No build from source
- ✓ Uses official base
- ~ Requires image manipulation tools

Choose based on your needs! 🚀
