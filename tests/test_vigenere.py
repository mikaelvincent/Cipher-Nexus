"""Unit tests for the Vigenere cipher implementation."""

import unittest
import string

from src.ciphers.vigenere import VigenereCipher


class TestVigenereCipher(unittest.TestCase):
    """Test the VigenereCipher for correct encryption and decryption of alphabetic characters."""

    def test_round_trip_encryption_decryption(self) -> None:
        """Encrypt and decrypt a sample text, ensuring the result matches."""
        passphrase = "SecretPass"
        cipher = VigenereCipher(passphrase=passphrase)
        plaintext = b"Hello, Vigenere123!"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)
        self.assertNotEqual(plaintext, encrypted)

    def test_only_alphabetic_transformed(self) -> None:
        """Verify that non-alphabetic characters remain unchanged."""
        cipher = VigenereCipher(passphrase="test")
        data = b"1234!@#$%^&*()_+"
        encrypted = cipher.encrypt(data)
        # For these chars, encryption == decryption == original
        self.assertEqual(data, encrypted)
        self.assertEqual(data, cipher.decrypt(encrypted))

    def test_empty_passphrase_raises_error(self) -> None:
        """Ensure a passphrase that is empty or whitespace triggers ValueError."""
        with self.assertRaises(ValueError):
            VigenereCipher(passphrase="   ")


if __name__ == "__main__":
    unittest.main()
