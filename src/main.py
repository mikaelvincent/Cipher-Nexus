"""Main entry point for the Cipher Nexus application.

This module provides a command-line interface for encrypting or decrypting files and can launch the Tkinter GUI if called without arguments. The encryption logic includes multiple classical ciphers wrapped by RSA-based key management.
"""

import sys
import pickle

from src.gui import start_gui
from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher
from src.crypto.rsa_manager import RSAManager
from src.crypto.hashing import sha256_hash_data


def main() -> None:
    """Entry point for Cipher Nexus.

    Usage:
        If called with no arguments, launches the GUI.
        Otherwise, call:
            python main.py encrypt <input> <output> <public_key.pem>
            python main.py decrypt <input> <output> <private_key.pem>
    """
    if len(sys.argv) < 2:
        # No arguments provided; launch the GUI
        start_gui()
        return

    cmd = sys.argv[1].lower()
    if cmd == "encrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        pub_key_path = sys.argv[4]
        encrypt_file(input_path, output_path, pub_key_path)
    elif cmd == "decrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        priv_key_path = sys.argv[4]
        decrypt_file(input_path, output_path, priv_key_path)
    else:
        print("Usage:")
        print("  python main.py encrypt <input> <output> <public_key.pem>")
        print("  python main.py decrypt <input> <output> <private_key.pem>")


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt a file using layered classical ciphers and RSA key management.

    Args:
        input_path: Path to the plaintext file.
        output_path: Path where the ciphertext will be written.
        public_key_path: Path to the RSA public key (PEM file).
    """
    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    mono = MonoalphabeticCipher()
    poly = PolyalphabeticCipher()
    trans = TranspositionCipher()
    vig = VigenereCipher()
    ver = VernamCipher()

    # Encryption pipeline
    data = trans.encrypt(plaintext)
    data = mono.encrypt(data)
    data = poly.encrypt(data)
    data = vig.encrypt(data)
    data = ver.encrypt(data)

    # Collect cipher parameters and original file hash
    cipher_params = {
        "mono_key": mono.key,
        "poly_key": poly.key,
        "trans_columns": trans.columns,
        "vig_passphrase": vig.passphrase,
        "ver_key": ver.key,
        "sha256": sha256_hash_data(plaintext),
    }
    param_bytes = pickle.dumps(cipher_params)

    # Load public key and encrypt parameter block
    rsa_mgr = RSAManager()
    rsa_mgr.load_public_key(public_key_path)
    encrypted_params = rsa_mgr.encrypt(param_bytes)

    # Write out [4-byte param length] [encrypted params] [ciphertext]
    with open(output_path, "wb") as f_out:
        f_out.write(len(encrypted_params).to_bytes(4, "big"))
        f_out.write(encrypted_params)
        f_out.write(data)

    print(f"Encryption complete. Output written to {output_path}")


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Decrypt a file using layered classical ciphers and RSA key management.

    Args:
        input_path: Path to the ciphertext file (includes RSA-encrypted parameters).
        output_path: Path where the decrypted plaintext will be written.
        private_key_path: Path to the RSA private key (PEM file).
    """
    with open(input_path, "rb") as f_in:
        param_len_bytes = f_in.read(4)
        param_len = int.from_bytes(param_len_bytes, "big")
        encrypted_params = f_in.read(param_len)
        ciphertext = f_in.read()

    # Load private key and decrypt parameter block
    rsa_mgr = RSAManager()
    rsa_mgr.load_private_key(private_key_path)

    param_bytes = rsa_mgr.decrypt(encrypted_params)
    cipher_params = pickle.loads(param_bytes)

    mono = MonoalphabeticCipher(key=cipher_params["mono_key"])
    poly = PolyalphabeticCipher(key=cipher_params["poly_key"])
    trans = TranspositionCipher(columns=cipher_params["trans_columns"])
    vig = VigenereCipher(passphrase=cipher_params["vig_passphrase"])
    ver = VernamCipher(key=cipher_params["ver_key"])

    # Decryption pipeline
    data = ver.decrypt(ciphertext)
    data = vig.decrypt(data)
    data = poly.decrypt(data)
    data = mono.decrypt(data)
    data = trans.decrypt(data)

    # Check file integrity
    original_hash = cipher_params["sha256"]
    new_hash = sha256_hash_data(data)
    if new_hash != original_hash:
        print("WARNING: File hash mismatch. Possible corruption or tampering.")
    else:
        print("File integrity verified (SHA-256).")

    with open(output_path, "wb") as f_out:
        f_out.write(data)

    print(f"Decryption complete. Output written to {output_path}")


if __name__ == "__main__":
    main()
