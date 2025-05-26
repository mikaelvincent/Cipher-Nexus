"""Unit tests for the Vernam cipher (XOR-based) implementation."""

import unittest
import secrets

from src.ciphers.vernam import VernamCipher


class TestVernamCipher(unittest.TestCase):
    """Test the VernamCipher for correct encryption and decryption."""

    def test_random_data_round_trip(self) -> None:
        """Encrypt and decrypt random data with a random key."""
        data = secrets.token_bytes(1024)
        cipher = VernamCipher()
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_custom_key(self) -> None:
        """Use a small custom key and verify round-trip."""
        key = b"\x01\x02\x03\x04"
        cipher = VernamCipher(key=key)
        data = b"Example Data for Vernam"
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_empty_key_raises_error(self) -> None:
        """Ensure an empty key raises ValueError."""
        with self.assertRaises(ValueError):
            VernamCipher(key=b"")


if __name__ == "__main__":
    unittest.main()
