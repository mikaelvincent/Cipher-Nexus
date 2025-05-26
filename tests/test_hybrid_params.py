"""Tests for envelope encryption/decryption edge cases in src.crypto.hybrid."""

import unittest
import tempfile
import os

from src.crypto.hybrid import envelope_encrypt_params, envelope_decrypt_params
from src.crypto.rsa_manager import RSAManager
from src.crypto.rsa_manager import RSAManagerError
from src.utils.constants import AES_KEY_SIZE, GCM_IV_SIZE


class TestHybridParams(unittest.TestCase):
    """Test envelope_encrypt_params/envelope_decrypt_params edge cases."""

    def setUp(self) -> None:
        """Generate an RSA key pair for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pub_key_path = os.path.join(self.temp_dir.name, "public_key.pem")
        self.priv_key_path = os.path.join(self.temp_dir.name, "private_key.pem")

        rsa_mgr = RSAManager()
        rsa_mgr.generate_key_pair(2048)
        rsa_mgr.save_public_key(self.pub_key_path)
        rsa_mgr.save_private_key(self.priv_key_path)

    def tearDown(self) -> None:
        """Clean up temp directory."""
        self.temp_dir.cleanup()

    def test_tag_mismatch(self) -> None:
        """Test that a GCM tag mismatch raises ValueError and logs an error."""
        params = {"foo": "bar"}
        ephemeral_enc, param_ciphertext, _ = envelope_encrypt_params(
            params, self.pub_key_path
        )
        # Corrupt the tag in ephemeral_decrypt call
        corrupted_tag = b"\x00" * 16

        # Capture logs at ERROR level from the 'src.crypto.hybrid' logger
        with self.assertLogs("src.crypto.hybrid", level="ERROR") as captured:
            with self.assertRaises(ValueError):
                envelope_decrypt_params(
                    ephemeral_enc, param_ciphertext, corrupted_tag, self.priv_key_path
                )

        # Verify the log message
        self.assertTrue(
            any("GCM tag mismatch" in msg for msg in captured.output),
            "Expected GCM tag mismatch message not found in logs.",
        )

    def test_corrupted_ciphertext(self) -> None:
        """Test that a corrupted AES-GCM ciphertext raises ValueError and logs an error."""
        params = {"secret": b"12345"}
        ephemeral_enc, param_ciphertext, param_tag = envelope_encrypt_params(
            params, self.pub_key_path
        )

        # Corrupt the ciphertext
        corrupted_ciphertext = param_ciphertext[:-1] + b"\x99"

        # Capture logs at ERROR level
        with self.assertLogs("src.crypto.hybrid", level="ERROR") as captured:
            with self.assertRaises(ValueError):
                envelope_decrypt_params(
                    ephemeral_enc, corrupted_ciphertext, param_tag, self.priv_key_path
                )

        # Check log content if desired
        self.assertTrue(
            any("AES-GCM decryption failed" in msg for msg in captured.output),
            "Expected AES-GCM decryption failure message not found in logs.",
        )


if __name__ == "__main__":
    unittest.main()
