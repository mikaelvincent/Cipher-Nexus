"""Unit tests for the Monoalphabetic cipher implementation."""

import unittest
import secrets

from src.ciphers.monoalphabetic import MonoalphabeticCipher


class TestMonoalphabeticCipher(unittest.TestCase):
    """Test the MonoalphabeticCipher for correct encryption and decryption."""

    def test_random_data_encryption_decryption(self) -> None:
        """Encrypt and decrypt random data, asserting it remains unchanged."""
        # Generate random data
        data = secrets.token_bytes(512)  # 512 bytes of random data

        # Create cipher with a random key
        cipher = MonoalphabeticCipher()

        # Encrypt and then decrypt
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)

        self.assertEqual(data, decrypted)
        self.assertNotEqual(data, encrypted)

    def test_provided_key(self) -> None:
        """Use a known (fixed) key for the cipher, ensuring correct round-trip."""
        # Create a simple permutation for demonstration
        # (just reversing 0..255 for clarity; 0->255, 1->254, etc.)
        key = bytes(range(255, -1, -1))
        cipher = MonoalphabeticCipher(key=key)

        data = b"Test with known key 1234"
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)

        self.assertEqual(data, decrypted)
        self.assertNotEqual(data, encrypted)

    def test_invalid_key_length(self) -> None:
        """Ensure a ValueError is raised if key length is not exactly 256 bytes."""
        with self.assertRaises(ValueError):
            MonoalphabeticCipher(key=b"short_key")


if __name__ == "__main__":
    unittest.main()
