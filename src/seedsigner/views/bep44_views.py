"""
Views for BEP44 DHT message signing workflow.

Handles the complete flow for signing BEP44 mutable DHT items:
1. Scan QR with signing request (UR:BYTES/... format)
2. Confirm message details (seq, value, salt, derivation path)
3. Confirm public key that will sign
4. Sign and display result as QR (UR:BYTES/... format)
"""

import logging
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.models.encode_qr import Bep44ResultQrEncoder
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)


class SeedSignBep44StartView(View):
    """
    Entry point for BEP44 signing flow.

    Launches QR scanner to scan a BEP44 signing request (UR:BYTES/... format).
    The request contains: seq, value, derivation_path, salt (optional).
    """
    def __init__(self):
        super().__init__()

        # Initialize BEP44 data storage in controller
        if not hasattr(self.controller, 'bep44_data'):
            self.controller.bep44_data = None

    def run(self):
        from seedsigner.views.scan_views import ScanView

        # Launch scanner for UR:BYTES (SIGN_MESSAGE_BEP44 will be detected)
        ret = ScanView(
            qr_type=QRType.SIGN_MESSAGE_BEP44,
        ).run()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Scanner completed, extract BEP44 data
        decoder = ret
        bep44_data = decoder.get_bep44_data()

        if not bep44_data:
            # Invalid BEP44 data
            from seedsigner.gui.screens import WarningScreen
            self.run_screen(
                WarningScreen,
                title="Invalid BEP44 Request",
                status_headline="Error",
                text="The scanned QR code does not contain a valid BEP44 signing request.",
                show_back_button=True
            )
            return Destination(BackStackView)

        # Store data in controller
        self.controller.bep44_data = bep44_data

        # May be None
        self.seed_num = bep44_data.get("seed_num")

        if self.seed_num is not None:
            # We already know which seed we're signing with
            return Destination(SeedSignBep44ConfirmMessageView, skip_current_view=True)
        else:
            # Need to select a seed
            from seedsigner.controller import Controller
            from seedsigner.views.seed_views import SeedSelectSeedView
            return Destination(
                SeedSelectSeedView,
                view_args=dict(flow=Controller.FLOW__SIGN_MESSAGE),
                skip_current_view=True
            )


class SeedSignBep44ConfirmMessageView(View):
    """
    Display BEP44 message details for user confirmation.

    Shows:
    - Sequence number
    - Value (hex preview, truncated if large)
    - Salt (if present)
    - Derivation path
    """
    def __init__(self):
        super().__init__()

    def run(self):
        from seedsigner.gui.screens import seed_screens

        data = self.controller.bep44_data
        if not data:
            # No data, shouldn't happen
            return Destination(BackStackView)

        seq = data["seq"]
        value = data["value"]
        salt = data.get("salt")
        derivation_path = data["derivation_path"]

        # Prepare value preview (show first 64 hex chars, indicate if truncated)
        value_hex = value.hex()
        value_preview = value_hex if len(value_hex) <= 64 else value_hex[:64] + "..."
        value_size = f"{len(value)} bytes"

        # Prepare salt preview
        salt_preview = None
        if salt:
            salt_hex = salt.hex()
            salt_preview = salt_hex if len(salt_hex) <= 32 else salt_hex[:32] + "..."

        # Display confirmation screen
        selected_menu_num = self.run_screen(
            seed_screens.SeedSignBep44ConfirmMessageScreen,
            seq=seq,
            value_preview=value_preview,
            value_size=value_size,
            salt_preview=salt_preview,
            derivation_path=derivation_path
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User confirmed, move to public key confirmation
        return Destination(SeedSignBep44ConfirmPublicKeyView)


class SeedSignBep44ConfirmPublicKeyView(View):
    """
    Display the ed25519 public key that will sign the message.

    This allows the user to verify they're using the correct key.
    """
    def __init__(self):
        super().__init__()

    def run(self):
        from seedsigner.gui.screens import seed_screens
        from seedsigner.helpers.ed25519_utils import derive_ed25519_keypair_from_seed, format_public_key_for_display

        data = self.controller.bep44_data
        if not data:
            return Destination(BackStackView)

        # Get seed
        seed_num = data.get("seed_num")
        if seed_num is None:
            # Shouldn't happen, but handle gracefully
            return Destination(BackStackView)

        seed = self.controller.get_seed(seed_num)
        derivation_path = data["derivation_path"]

        # Derive ed25519 public key
        try:
            _, public_key = derive_ed25519_keypair_from_seed(
                seed.seed_bytes,
                derivation_path
            )
            public_key_hex = public_key.hex()
            public_key_formatted = format_public_key_for_display(public_key_hex)

        except Exception as e:
            logger.error(f"Error deriving ed25519 key: {e}")
            from seedsigner.gui.screens import WarningScreen
            self.run_screen(
                WarningScreen,
                title="Key Derivation Error",
                status_headline="Error",
                text=f"Failed to derive ed25519 key: {str(e)}",
                show_back_button=True
            )
            return Destination(BackStackView)

        # Display public key
        selected_menu_num = self.run_screen(
            seed_screens.SeedSignBep44ConfirmPublicKeyScreen,
            public_key_hex=public_key_hex,
            public_key_formatted=public_key_formatted,
            derivation_path=derivation_path
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # User confirmed, proceed to signing
        return Destination(SeedSignBep44SignedMessageQRView)


class SeedSignBep44SignedMessageQRView(View):
    """
    Sign the BEP44 message and display the result as an animated QR code.

    The result is encoded as UR:BYTES/... (using fountain encoding for large results).
    Contains: public_key, signature, seq (but NOT value/salt to keep QR small).
    """
    def __init__(self):
        super().__init__()

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.helpers.ed25519_utils import sign_bep44_message

        data = self.controller.bep44_data
        if not data:
            return Destination(BackStackView)

        # Get seed
        seed_num = data.get("seed_num")
        if seed_num is None:
            return Destination(BackStackView)

        seed = self.controller.get_seed(seed_num)

        # Extract signing parameters
        seq = data["seq"]
        value = data["value"]
        salt = data.get("salt")
        derivation_path = data["derivation_path"]

        # Sign the BEP44 message
        try:
            result = sign_bep44_message(
                seed_bytes=seed.seed_bytes,
                seq=seq,
                v=value,
                salt=salt,
                derivation_path=derivation_path
            )

            # Convert hex strings back to bytes for encoder
            public_key_bytes = bytes.fromhex(result["k"])
            signature_bytes = bytes.fromhex(result["sig"])

            # Create QR encoder (minimal output: k, sig, seq only)
            qr_encoder = Bep44ResultQrEncoder(
                public_key=public_key_bytes,
                signature=signature_bytes,
                seq=seq,
                include_value=False,  # Keep QR small
                qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY)
            )

        except Exception as e:
            logger.error(f"Error signing BEP44 message: {e}")
            from seedsigner.gui.screens import WarningScreen
            self.run_screen(
                WarningScreen,
                title="Signing Error",
                status_headline="Error",
                text=f"Failed to sign BEP44 message: {str(e)}",
                show_back_button=True
            )
            return Destination(BackStackView)

        # Display signed result as QR
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )

        # Cleanup
        self.controller.bep44_data = None

        # Exiting/Canceling the QR display screen always returns Home
        return Destination(MainMenuView, skip_current_view=True)
