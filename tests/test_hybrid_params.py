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

    def test_tag_mismatch(self):
        """Test that a GCM tag mismatch raises ValueError."""
        params = {"foo": "bar"}
        ephemeral_enc, param_ciphertext, param_tag = envelope_encrypt_params(
            params, self.pub_key_path
        )
        # Corrupt the tag in ephemeral_enc
        # ephemeral_enc = RSA-encrypted AES key + IV + real_tag
        # We'll pass a different 'param_tag' below.
        corrupted_tag = b"\x00" * 16
        with self.assertRaises(ValueError):
            envelope_decrypt_params(
                ephemeral_enc, param_ciphertext, corrupted_tag, self.priv_key_path
            )

    def test_corrupted_ciphertext(self):
        """Test that a corrupted ciphertext raises ValueError."""
        params = {"secret": b"12345"}
        ephemeral_enc, param_ciphertext, param_tag = envelope_encrypt_params(
            params, self.pub_key_path
        )
        # Corrupt param_ciphertext
        corrupted_ciphertext = param_ciphertext[:-1] + b"\x99"
        with self.assertRaises(ValueError):
            envelope_decrypt_params(
                ephemeral_enc, corrupted_ciphertext, param_tag, self.priv_key_path
            )


if __name__ == "__main__":
    unittest.main()
