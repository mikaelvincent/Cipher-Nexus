"""Main entry point for the Cipher Nexus application.

This module provides a command-line interface for encrypting or decrypting files, generating RSA keys, and can launch the Tkinter GUI if called without arguments.
"""

import logging
import sys

from src.gui import start_gui
from src.utils.classical_pipeline import (
    encrypt_classical,
    decrypt_classical,
    write_data,
)
from src.utils.hybrid_crypto import envelope_encrypt_params, envelope_decrypt_params
from src.crypto.hashing import sha256_hash_data
from src.crypto.rsa_manager import RSAManager
from src.utils.file_io import read_file_in_chunks
from src.utils.constants import LENGTH_HEADER_SIZE, AES_KEY_SIZE, GCM_IV_SIZE


def main() -> None:
    """Entry point for Cipher Nexus.

    Usage (CLI):
        If called with no arguments, launches the GUI.
        Otherwise:
            python main.py encrypt <input> <output> <public_key.pem>
            python main.py decrypt <input> <output> <private_key.pem>
            python main.py genkey <private_key.pem> <public_key.pem> [<key_size>]
    """
    # Configure basic logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        # No arguments provided; launch the GUI
        start_gui()
        return

    cmd = sys.argv[1].lower()
    if cmd == "encrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        pub_key_path = sys.argv[4]

        try:
            # 1. Classical encryption
            ciphertext, cipher_params = encrypt_classical(input_path)

            # 2. Compute file hash
            plaintext_data = b"".join(read_file_in_chunks(input_path))
            cipher_params["sha256"] = sha256_hash_data(plaintext_data)

            # 3. Envelope-encrypt parameters
            ephemeral_enc, param_ciphertext, param_tag = envelope_encrypt_params(
                cipher_params, pub_key_path
            )

            # 4. Construct final output
            header_1 = len(ephemeral_enc).to_bytes(LENGTH_HEADER_SIZE, "big")
            header_2 = len(param_ciphertext).to_bytes(LENGTH_HEADER_SIZE, "big")
            final_output = (
                header_1 + ephemeral_enc + header_2 + param_ciphertext + ciphertext
            )

            # 5. Write output
            write_data(output_path, final_output)

            logger.info("Encryption complete. Output written to %s", output_path)
        except Exception as exc:
            logger.exception("Encryption failed.")
            print(f"Encryption failed: {exc}")

    elif cmd == "decrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        priv_key_path = sys.argv[4]

        try:
            # Read entire file
            file_data = b"".join(read_file_in_chunks(input_path))

            cursor = 0
            ephemeral_len = int.from_bytes(
                file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big"
            )
            cursor += LENGTH_HEADER_SIZE
            ephemeral_data_encrypted = file_data[cursor : cursor + ephemeral_len]
            cursor += ephemeral_len

            param_len = int.from_bytes(
                file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big"
            )
            cursor += LENGTH_HEADER_SIZE
            param_ciphertext = file_data[cursor : cursor + param_len]
            cursor += param_len

            ciphertext = file_data[cursor:]

            # Decrypt ephemeral data
            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(priv_key_path)
            ephemeral_data = rsa_mgr.decrypt(ephemeral_data_encrypted)

            # Extract param_tag from ephemeral_data
            param_tag = ephemeral_data[AES_KEY_SIZE + GCM_IV_SIZE :]

            # Envelope-decrypt cipher params
            cipher_params = envelope_decrypt_params(
                ephemeral_data_encrypted, param_ciphertext, param_tag, priv_key_path
            )

            # Classical decryption
            plaintext = decrypt_classical(ciphertext, cipher_params)

            # Verify hash
            old_hash = cipher_params["sha256"]
            new_hash = sha256_hash_data(plaintext)
            if new_hash != old_hash:
                raise ValueError("SHA-256 mismatch: possible corruption or tampering.")

            write_data(output_path, plaintext)
            logger.info("Decryption complete. Output written to %s", output_path)
        except Exception as exc:
            logger.exception("Decryption failed.")
            print(f"Decryption failed: {exc}")
    
    elif cmd == "genkey" and len(sys.argv) in (4, 5):
        # Usage: python main.py genkey <private_key.pem> <public_key.pem> [<key_size>]
        private_key_path = sys.argv[2]
        public_key_path = sys.argv[3]
        if len(sys.argv) == 5:
            try:
                key_size = int(sys.argv[4])
            except ValueError:
                print("Invalid key size specified. Must be an integer.")
                return
        else:
            key_size = 2048  # Default

        try:
            rsa_mgr = RSAManager()
            rsa_mgr.generate_key_pair(key_size=key_size)
            rsa_mgr.save_private_key(private_key_path)
            rsa_mgr.save_public_key(public_key_path)
            logger.info(
                "Key generation complete. Private key: %s, Public key: %s",
                private_key_path,
                public_key_path,
            )
        except Exception as exc:
            logger.exception("Key generation failed.")
            print(f"Key generation failed: {exc}")

    else:
        print("Usage:")
        print("  python main.py encrypt <input> <output> <public_key.pem>")
        print("  python main.py decrypt <input> <output> <private_key.pem>")
        print("  python main.py genkey <private_key.pem> <public_key.pem> [<key_size>]")


if __name__ == "__main__":
    main()
