"""High-level encryption/decryption pipeline using layered classical ciphers and RSA.

This module centralizes the logic to:
1. Read a plaintext or ciphertext file
2. Apply or reverse multiple classical ciphers
3. Encrypt/decrypt the cipher parameters with RSA
4. Write the resulting data to an output file
"""

import pickle

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher
from src.crypto.rsa_manager import RSAManager
from src.crypto.hashing import sha256_hash_data


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt a file using layered classical ciphers and RSA key management.

    Args:
        input_path: Path to the plaintext file.
        output_path: Path where the ciphertext will be written.
        public_key_path: Path to the RSA public key (PEM file).

    Raises:
        OSError, ValueError, and others if reading/writing or encryption fails.
    """
    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    # Instantiate ciphers with random parameters
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


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Decrypt a file using layered classical ciphers and RSA key management.

    Args:
        input_path: Path to the ciphertext file (includes RSA-encrypted parameters).
        output_path: Path where the decrypted plaintext will be written.
        private_key_path: Path to the RSA private key (PEM file).

    Raises:
        OSError, ValueError, and others if reading/writing or decryption fails.
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
        # We won't raise an error here; just a heads-up to the caller
        print("WARNING: File hash mismatch. Possible corruption or tampering.")
    else:
        print("File integrity verified (SHA-256).")

    with open(output_path, "wb") as f_out:
        f_out.write(data)
