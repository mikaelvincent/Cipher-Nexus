"""Unit tests for the Transposition cipher implementation."""

import unittest
import secrets

from src.ciphers.transposition import TranspositionCipher


class TestTranspositionCipher(unittest.TestCase):
    """Test the TranspositionCipher for correct encryption and decryption."""

    def test_random_data_encryption_decryption(self) -> None:
        """Encrypt and decrypt random data, ensuring correctness."""
        data = secrets.token_bytes(512)
        cipher = TranspositionCipher(columns=8)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)
        self.assertNotEqual(data, encrypted)

    def test_minimum_columns(self) -> None:
        """Verify that attempting to set columns <= 1 raises a ValueError."""
        with self.assertRaises(ValueError):
            TranspositionCipher(columns=1)

    def test_random_columns(self) -> None:
        """Check that omitting 'columns' yields a valid random value and correct round-trip."""
        cipher = TranspositionCipher(columns=None)
        self.assertTrue(
            4 <= cipher.columns <= 16, "Columns not in expected random range."
        )
        data = b"Testing random columns"
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)


if __name__ == "__main__":
    unittest.main()
