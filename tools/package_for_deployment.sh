#!/bin/bash
#
# Package SeedSigner DNS signing files for deployment to SD card
#
# Usage: ./tools/package_for_deployment.sh [output_dir]
#

set -e

OUTPUT_DIR="${1:-./seedsigner-deployment}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PACKAGE_NAME="seedsigner-dns-${TIMESTAMP}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   SeedSigner DNS Packet Signing - Deployment Packager       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME"
echo "📦 Creating package: $PACKAGE_NAME"

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/helpers/ur2"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/models"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/views"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/gui/screens"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/tools"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME/docs"

# Copy files
echo "📋 Copying files..."

# Helpers
echo "  ✓ Copying helpers..."
cp src/seedsigner/helpers/dns_utils.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/helpers/"
cp src/seedsigner/helpers/bep44_cbor.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/helpers/"
cp src/seedsigner/helpers/ed25519_utils.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/helpers/"
cp src/seedsigner/helpers/ur2/cbor_lite.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/helpers/ur2/"

# Models
echo "  ✓ Copying models..."
cp src/seedsigner/models/decode_qr.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/models/"
cp src/seedsigner/models/encode_qr.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/models/"
cp src/seedsigner/models/qr_type.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/models/"

# Views
echo "  ✓ Copying views..."
cp src/seedsigner/views/bep44_views.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/views/"
cp src/seedsigner/views/seed_views.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/views/"

# Screens
echo "  ✓ Copying screens..."
cp src/seedsigner/gui/screens/seed_screens.py "$OUTPUT_DIR/$PACKAGE_NAME/src/seedsigner/gui/screens/"

# Root files
echo "  ✓ Copying requirements..."
cp requirements.txt "$OUTPUT_DIR/$PACKAGE_NAME/"

# Tools (optional)
echo "  ✓ Copying tools..."
cp tools/generate_bep44_test_qr.py "$OUTPUT_DIR/$PACKAGE_NAME/tools/" 2>/dev/null || true
cp tools/verify_bep44_signature.py "$OUTPUT_DIR/$PACKAGE_NAME/tools/" 2>/dev/null || true
cp tools/demo_dns_signing.py "$OUTPUT_DIR/$PACKAGE_NAME/tools/" 2>/dev/null || true
cp tools/README_BEP44_TESTING.md "$OUTPUT_DIR/$PACKAGE_NAME/tools/" 2>/dev/null || true

# Docs
echo "  ✓ Copying documentation..."
cp docs/DNS_SIGNING.md "$OUTPUT_DIR/$PACKAGE_NAME/docs/" 2>/dev/null || true
cp docs/BEP44_IMPLEMENTATION.md "$OUTPUT_DIR/$PACKAGE_NAME/docs/" 2>/dev/null || true
cp docs/DEPLOYMENT.md "$OUTPUT_DIR/$PACKAGE_NAME/docs/" 2>/dev/null || true

# Create installation script
echo "  ✓ Creating install script..."
cat > "$OUTPUT_DIR/$PACKAGE_NAME/install.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
#
# Install DNS packet signing to SeedSigner
#
# Usage: ./install.sh /path/to/seedsigner
#

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/seedsigner"
    echo ""
    echo "Example: $0 /opt/seedsigner"
    echo "         $0 /home/seedsigner/seedsigner"
    exit 1
fi

SEEDSIGNER_DIR="$1"

if [ ! -d "$SEEDSIGNER_DIR/src" ]; then
    echo "❌ Error: $SEEDSIGNER_DIR does not appear to be a SeedSigner installation"
    echo "   (missing src/ directory)"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        Installing DNS Packet Signing Support                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $SEEDSIGNER_DIR"
echo ""

# Backup original files
echo "💾 Creating backups..."
BACKUP_DIR="$SEEDSIGNER_DIR/backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

for file in \
    src/seedsigner/views/seed_views.py \
    src/seedsigner/gui/screens/seed_screens.py \
    requirements.txt
do
    if [ -f "$SEEDSIGNER_DIR/$file" ]; then
        cp "$SEEDSIGNER_DIR/$file" "$BACKUP_DIR/"
        echo "  ✓ Backed up: $file"
    fi
done

# Copy files
echo ""
echo "📋 Installing files..."

rsync -av --exclude='*.md' --exclude='*.sh' --exclude='tools' --exclude='docs' \
    ./src/ "$SEEDSIGNER_DIR/src/"

cp requirements.txt "$SEEDSIGNER_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Backups saved to: $BACKUP_DIR"
echo ""
echo "Next steps:"
echo "1. Install dnslib: pip3 install dnslib>=0.9.23"
echo "2. Reboot your SeedSigner"
echo "3. Test with: Seeds → [Test Seed] → Sign BEP44 message"
echo ""
echo "See docs/DEPLOYMENT.md for detailed instructions"
INSTALL_SCRIPT

chmod +x "$OUTPUT_DIR/$PACKAGE_NAME/install.sh"

# Create README
echo "  ✓ Creating README..."
cat > "$OUTPUT_DIR/$PACKAGE_NAME/README.txt" << 'README'
SeedSigner DNS Packet Signing - Deployment Package
===================================================

This package contains all files needed to add DNS packet signing support
to your SeedSigner hardware device.

QUICK START
-----------

1. Copy this entire directory to your SeedSigner's SD card

2. Run the install script:
   ./install.sh /path/to/seedsigner

3. Install dnslib:
   pip3 install dnslib>=0.9.23

4. Reboot your SeedSigner

MANUAL INSTALLATION
-------------------

If you prefer manual installation, copy the files from src/ to your
SeedSigner's src/ directory, preserving the directory structure.

See docs/DEPLOYMENT.md for detailed instructions.

TESTING
-------

Test with the abandon seed:
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

Generate test QR codes:
python3 tools/generate_bep44_test_qr.py

WHAT'S INCLUDED
---------------

Modified Files:
- src/seedsigner/helpers/bep44_cbor.py
- src/seedsigner/helpers/ed25519_utils.py
- src/seedsigner/helpers/ur2/cbor_lite.py
- src/seedsigner/models/decode_qr.py
- src/seedsigner/models/encode_qr.py
- src/seedsigner/models/qr_type.py
- src/seedsigner/views/seed_views.py
- src/seedsigner/gui/screens/seed_screens.py
- requirements.txt

New Files:
- src/seedsigner/helpers/dns_utils.py
- src/seedsigner/views/bep44_views.py

Tools:
- tools/generate_bep44_test_qr.py
- tools/verify_bep44_signature.py
- tools/demo_dns_signing.py

Documentation:
- docs/DEPLOYMENT.md
- docs/DNS_SIGNING.md
- docs/BEP44_IMPLEMENTATION.md

SUPPORT
-------

For issues or questions, see docs/DEPLOYMENT.md
README

# Create file list
echo "  ✓ Creating file list..."
find "$OUTPUT_DIR/$PACKAGE_NAME" -type f | sed "s|$OUTPUT_DIR/$PACKAGE_NAME/||" | sort > "$OUTPUT_DIR/$PACKAGE_NAME/FILES.txt"

# Create tarball
echo ""
echo "🗜️  Creating tarball..."
cd "$OUTPUT_DIR"
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
cd - > /dev/null

# Create checksum
echo "  ✓ Creating checksum..."
cd "$OUTPUT_DIR"
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
cd - > /dev/null

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ Package Complete!                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📦 Package: $OUTPUT_DIR/${PACKAGE_NAME}.tar.gz"
echo "🔒 SHA256:  $OUTPUT_DIR/${PACKAGE_NAME}.tar.gz.sha256"
echo "📁 Files:   $OUTPUT_DIR/$PACKAGE_NAME/"
echo ""
echo "To deploy to SD card:"
echo "1. Extract: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "2. Run: cd ${PACKAGE_NAME} && ./install.sh /path/to/seedsigner"
echo "3. Install dnslib: pip3 install dnslib"
echo "4. Reboot SeedSigner"
echo ""
echo "Or manually copy files from src/ to your SeedSigner's SD card"
echo ""
