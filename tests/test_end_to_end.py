"""End-to-end tests for the Cipher Nexus encryption/decryption pipeline.

This file verifies that data can be successfully encrypted and then decrypted using random RSA keys, ensuring the final output matches the original.
"""

import os
import unittest
import tempfile
import secrets

from src.utils.classical_pipeline import encrypt_classical, decrypt_classical
from src.utils.hybrid_crypto import (
    envelope_encrypt_params,
    envelope_decrypt_params,
)
from src.crypto.hashing import sha256_hash_data
from src.crypto.rsa_manager import RSAManager
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

            # Classical encrypt in memory
            ciphertext, cipher_params = encrypt_classical(input_path)

            # Compute and store file hash
            cipher_params["sha256"] = sha256_hash_data(plaintext_data)

            # Envelope encrypt the cipher parameters
            ephemeral_data_enc, param_ciphertext, param_tag = envelope_encrypt_params(
                cipher_params, pub_key_path
            )

            # Write final structure to the encrypted file:
            #  [4-byte length of ephemeral_data_enc][ephemeral_data_enc]
            #  [4-byte length of param_ciphertext][param_ciphertext]
            #  [ciphertext]
            with open(encrypted_path, "wb") as f_enc:
                f_enc.write(len(ephemeral_data_enc).to_bytes(4, "big"))
                f_enc.write(ephemeral_data_enc)
                f_enc.write(len(param_ciphertext).to_bytes(4, "big"))
                f_enc.write(param_ciphertext)
                f_enc.write(ciphertext)

            # Now read back the encrypted file and parse the sections
            with open(encrypted_path, "rb") as f_enc:
                full_data = f_enc.read()

            cursor = 0
            ephemeral_len = int.from_bytes(full_data[cursor : cursor + 4], "big")
            cursor += 4
            ephemeral_data_encrypted = full_data[cursor : cursor + ephemeral_len]
            cursor += ephemeral_len
            param_len = int.from_bytes(full_data[cursor : cursor + 4], "big")
            cursor += 4
            param_cipher = full_data[cursor : cursor + param_len]
            cursor += param_len
            extracted_ciphertext = full_data[cursor:]

            # RSA-decrypt ephemeral data to retrieve AES key, IV, and the real GCM tag
            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(priv_key_path)
            ephemeral_data = rsa_mgr.decrypt(ephemeral_data_encrypted)

            # ephemeral_data = aes_key + aes_iv + param_tag
            # The tag is the last 16 bytes of ephemeral_data
            actual_tag = ephemeral_data[-16:]

            # Now properly decrypt the parameters with the correct tag
            cipher_params_decrypted = envelope_decrypt_params(
                ephemeral_data_encrypted,
                param_cipher,
                actual_tag,
                priv_key_path,
            )

            # Classical decrypt the final ciphertext
            recovered_plaintext = decrypt_classical(
                extracted_ciphertext, cipher_params_decrypted
            )

            self.assertEqual(plaintext_data, recovered_plaintext)

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

            # Classical encrypt
            ciphertext, cipher_params = encrypt_classical(input_path)
            cipher_params["sha256"] = sha256_hash_data(plaintext_data)

            # Envelope encrypt
            ephemeral_data_enc, param_ciphertext, param_tag = envelope_encrypt_params(
                cipher_params, pub_key_path
            )

            encrypted_path = os.path.join(temp_dir, "encrypted.bin")
            with open(encrypted_path, "wb") as f_enc:
                f_enc.write(len(ephemeral_data_enc).to_bytes(4, "big"))
                f_enc.write(ephemeral_data_enc)
                f_enc.write(len(param_ciphertext).to_bytes(4, "big"))
                f_enc.write(param_ciphertext)
                f_enc.write(ciphertext)

            # Now read back
            with open(encrypted_path, "rb") as f_enc:
                full_data = f_enc.read()

            cursor = 0
            ephemeral_len = int.from_bytes(full_data[cursor : cursor + 4], "big")
            cursor += 4
            ephemeral_enc = full_data[cursor : cursor + ephemeral_len]
            cursor += ephemeral_len

            param_len = int.from_bytes(full_data[cursor : cursor + 4], "big")
            cursor += 4
            param_cipher = full_data[cursor : cursor + param_len]
            cursor += param_len

            final_ciphertext = full_data[cursor:]

            # RSA-decrypt ephemeral data so we can confirm the real tag
            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(priv_key_path)
            ephemeral_data = rsa_mgr.decrypt(ephemeral_enc)
            actual_tag = ephemeral_data[-16:]

            # Decrypt the parameters
            cipher_params_decrypted = envelope_decrypt_params(
                ephemeral_enc, param_cipher, actual_tag, priv_key_path
            )

            # Classical decrypt
            recovered_data = decrypt_classical(
                final_ciphertext, cipher_params_decrypted
            )
            self.assertEqual(plaintext_data, recovered_data)

    def test_end_to_end_large_data(self) -> None:
        """Encrypt and decrypt a multi-megabyte file to ensure streaming pipeline can handle it."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Generate random RSA key pair
            pub_key_path, priv_key_path = generate_rsa_key_pair_and_save(temp_dir, 2048)

            # Create a multi-megabyte file (e.g., 5 MB)
            large_data = secrets.token_bytes(5 * 1024 * 1024)
            input_path = os.path.join(temp_dir, "large_input.bin")
            with open(input_path, "wb") as f_in:
                f_in.write(large_data)

            # Perform classical + hybrid encryption
            ciphertext, cipher_params = encrypt_classical(input_path)
            cipher_params["sha256"] = sha256_hash_data(large_data)
            ephemeral_data_enc, param_ciphertext, param_tag = envelope_encrypt_params(
                cipher_params, pub_key_path
            )

            encrypted_path = os.path.join(temp_dir, "encrypted_large.bin")
            with open(encrypted_path, "wb") as f_enc:
                f_enc.write(len(ephemeral_data_enc).to_bytes(4, "big"))
                f_enc.write(ephemeral_data_enc)
                f_enc.write(len(param_ciphertext).to_bytes(4, "big"))
                f_enc.write(param_ciphertext)
                f_enc.write(ciphertext)

            # Decrypt
            with open(encrypted_path, "rb") as f_enc:
                file_data = f_enc.read()

            cursor = 0
            ephemeral_len = int.from_bytes(file_data[cursor : cursor + 4], "big")
            cursor += 4
            ephemeral_enc = file_data[cursor : cursor + ephemeral_len]
            cursor += ephemeral_len

            param_len = int.from_bytes(file_data[cursor : cursor + 4], "big")
            cursor += 4
            param_cipher = file_data[cursor : cursor + param_len]
            cursor += param_len

            final_ciphertext = file_data[cursor:]

            # RSA-decrypt ephemeral data
            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(priv_key_path)
            ephemeral_data = rsa_mgr.decrypt(ephemeral_enc)
            actual_tag = ephemeral_data[-16:]

            # Envelope-decrypt
            cipher_params_dec = envelope_decrypt_params(
                ephemeral_enc, param_cipher, actual_tag, priv_key_path
            )

            # Classical
            recovered_data = decrypt_classical(final_ciphertext, cipher_params_dec)
            self.assertEqual(large_data, recovered_data)


if __name__ == "__main__":
    unittest.main()
