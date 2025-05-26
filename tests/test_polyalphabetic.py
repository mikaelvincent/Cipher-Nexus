"""Unit tests for the Polyalphabetic cipher implementation."""

import unittest
import secrets

from src.ciphers.polyalphabetic import PolyalphabeticCipher


class TestPolyalphabeticCipher(unittest.TestCase):
    """Test the PolyalphabeticCipher for correct encryption and decryption."""

    def test_round_trip_encryption_decryption(self) -> None:
        """Encrypt and decrypt random data, asserting equality with original."""
        data = secrets.token_bytes(512)
        cipher = PolyalphabeticCipher()
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_custom_key(self) -> None:
        """Use a known custom key to verify repeated shifts."""
        key = b"\x05\xaa\x10"  # Some arbitrary bytes
        cipher = PolyalphabeticCipher(key=key)
        data = b"Hello Polyalphabetic!"
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_empty_key_raises_error(self) -> None:
        """Ensure an empty key raises a ValueError."""
        with self.assertRaises(ValueError):
            PolyalphabeticCipher(key=b"")


if __name__ == "__main__":
    unittest.main()
