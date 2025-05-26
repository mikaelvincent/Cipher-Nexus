"""Unit tests for the RSAManager class, ensuring correct key generation, encryption, decryption, and file operations."""

import os
import unittest
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.rsa_manager import RSAManager


class TestRSAManager(unittest.TestCase):
    """Test RSAManager functionalities: key generation, encryption/decryption, and PEM I/O."""

    def test_generate_key_pair(self) -> None:
        """Generate an RSA key pair and ensure public and private keys are accessible."""
        manager = RSAManager()
        manager.generate_key_pair(key_size=2048)
        self.assertIsInstance(manager.private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(manager.public_key, rsa.RSAPublicKey)

    def test_encrypt_decrypt_in_memory(self) -> None:
        """Encrypt and decrypt data entirely in memory with the generated key pair."""
        manager = RSAManager()
        manager.generate_key_pair(key_size=2048)

        plaintext = b"Sample data for encryption."
        ciphertext = manager.encrypt(plaintext)
        self.assertNotEqual(plaintext, ciphertext)

        recovered = manager.decrypt(ciphertext)
        self.assertEqual(plaintext, recovered)

    def test_save_and_load_private_key(self) -> None:
        """Save a private key to file and then load it, verifying it decrypts data properly."""
        manager = RSAManager()
        manager.generate_key_pair(key_size=2048)
        plaintext = b"Test saving private key."

        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = os.path.join(temp_dir, "private_key.pem")
            manager.save_private_key(key_path)

            # Create a new manager to load the saved key
            loader = RSAManager()
            loader.load_private_key(key_path)

            # Ensure it can decrypt something encrypted by itself
            ciphertext = loader.encrypt(plaintext)
            recovered = loader.decrypt(ciphertext)
            self.assertEqual(plaintext, recovered)

    def test_save_and_load_public_key(self) -> None:
        """Save a public key to file and then load it, verifying encryption."""
        manager = RSAManager()
        manager.generate_key_pair(key_size=2048)
        plaintext = b"Test saving public key."

        with tempfile.TemporaryDirectory() as temp_dir:
            pub_key_path = os.path.join(temp_dir, "public_key.pem")
            manager.save_public_key(pub_key_path)

            # Create a new manager to load the saved key
            loader = RSAManager()
            loader.load_public_key(pub_key_path)

            # Ensure it can encrypt data; will need manager's private key to decrypt
            ciphertext = loader.encrypt(plaintext)
            recovered = manager.decrypt(ciphertext)
            self.assertEqual(plaintext, recovered)

    def test_password_encrypted_private_key(self) -> None:
        """Save a password-protected private key and load it, verifying correctness."""
        manager = RSAManager()
        manager.generate_key_pair(key_size=2048)
        plaintext = b"Password-protected key test."
        password = b"secret_pass"

        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = os.path.join(temp_dir, "private_key.pem")
            manager.save_private_key(key_path, password=password)

            # Load the encrypted private key
            loader = RSAManager()
            loader.load_private_key(key_path, password=password)

            # Confirm encryption/decryption works
            ciphertext = loader.encrypt(plaintext)
            recovered = loader.decrypt(ciphertext)
            self.assertEqual(plaintext, recovered)

    def test_error_without_public_key(self) -> None:
        """Attempt encryption without a public key, expecting a ValueError."""
        manager = RSAManager()
        with self.assertRaises(ValueError):
            manager.encrypt(b"data")

    def test_error_without_private_key(self) -> None:
        """Attempt decryption without a private key, expecting a ValueError."""
        manager = RSAManager()
        with self.assertRaises(ValueError):
            manager.decrypt(b"data")


if __name__ == "__main__":
    unittest.main()
