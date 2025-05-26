"""End-to-end tests for the Cipher Nexus encryption/decryption pipeline.

This file verifies that data can be successfully encrypted and then decrypted using random RSA keys, ensuring the final output matches the original.
"""

import os
import unittest
import tempfile
import secrets

from src.utils.pipeline import encrypt_file, decrypt_file
from tests.helpers.rsa_test_helpers import generate_rsa_key_pair_and_save


class TestEndToEnd(unittest.TestCase):
    """Test the full encryption/decryption pipeline with randomly generated RSA keys."""

    def test_end_to_end_small_data(self) -> None:
        """Encrypt and decrypt a small plaintext, verifying the output matches the original."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Generate random RSA key pair
            pub_key_path, priv_key_path = generate_rsa_key_pair_and_save(temp_dir, 2048)

            # Create a small plaintext file
            plaintext_data = b"Hello, Cipher Nexus!"
            input_path = os.path.join(temp_dir, "plaintext.txt")
            with open(input_path, "wb") as f_in:
                f_in.write(plaintext_data)

            # Define output paths
            encrypted_path = os.path.join(temp_dir, "encrypted.bin")
            decrypted_path = os.path.join(temp_dir, "decrypted.txt")

            # Encrypt
            encrypt_file(input_path, encrypted_path, pub_key_path)

            # Decrypt
            decrypt_file(encrypted_path, decrypted_path, priv_key_path)

            # Verify decryption correctness
            with open(decrypted_path, "rb") as f_out:
                result_data = f_out.read()

            self.assertEqual(plaintext_data, result_data)

    def test_end_to_end_random_data(self) -> None:
        """Encrypt and decrypt random binary data, verifying the output matches."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Generate random RSA key pair
            pub_key_path, priv_key_path = generate_rsa_key_pair_and_save(temp_dir, 2048)

            # Create random binary data
            plaintext_data = secrets.token_bytes(1024)  # 1 KB of random data
            input_path = os.path.join(temp_dir, "plaintext.bin")
            with open(input_path, "wb") as f_in:
                f_in.write(plaintext_data)

            # Define output paths
            encrypted_path = os.path.join(temp_dir, "encrypted.bin")
            decrypted_path = os.path.join(temp_dir, "decrypted.bin")

            # Encrypt
            encrypt_file(input_path, encrypted_path, pub_key_path)

            # Decrypt
            decrypt_file(encrypted_path, decrypted_path, priv_key_path)

            # Verify decryption correctness
            with open(decrypted_path, "rb") as f_out:
                result_data = f_out.read()

            self.assertEqual(plaintext_data, result_data)


if __name__ == "__main__":
    unittest.main()
