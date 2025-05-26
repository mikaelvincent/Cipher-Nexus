"""High-level encryption/decryption pipeline using layered classical ciphers and RSA.

This module centralizes the logic to:
1. Read a plaintext or ciphertext file.
2. Apply or reverse multiple classical ciphers.
3. Encrypt or decrypt the cipher parameters with RSA, leveraging a hybrid AES + RSA approach.
4. Write or read the resulting data to/from an output file.
"""

import pickle
import secrets
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher
from src.crypto.rsa_manager import RSAManager
from src.crypto.hashing import sha256_hash_data


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt a file using layered classical ciphers and RSA-based hybrid encryption.

    This function performs the following steps:
    1. Reads the plaintext from the input file.
    2. Encrypts the plaintext with multiple classical ciphers in sequence.
    3. Gathers all cipher parameters (keys, passphrases, etc.) plus a SHA-256 hash of the original file into a dictionary.
    4. Serializes the dictionary and encrypts it with AES-GCM (using a random key and IV).
    5. Encrypts the small AES key/IV/tag bundle with RSA-OAEP using the provided public key (hybrid approach).
    6. Writes the output file in the order: [RSA length][RSA data][AES length][AES data][ciphertext].

    Args:
        input_path: Path to the plaintext file.
        output_path: Path for writing the output ciphertext file.
        public_key_path: Path to the RSA public key (PEM file).

    Raises:
        ValueError: If encryption fails due to invalid or missing parameters.
        OSError: If reading/writing files fails.
    """
    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    # Instantiate ciphers with random parameters
    mono = MonoalphabeticCipher()
    poly = PolyalphabeticCipher()
    trans = TranspositionCipher()
    vig = VigenereCipher()
    ver = VernamCipher()

    # Layered classical cipher encryption
    data = trans.encrypt(plaintext)
    data = mono.encrypt(data)
    data = poly.encrypt(data)
    data = vig.encrypt(data)
    data = ver.encrypt(data)

    # Collect cipher parameters and file hash
    cipher_params: Dict[str, Any] = {
        "mono_key": mono.key,
        "poly_key": poly.key,
        "trans_columns": trans.columns,
        "vig_passphrase": vig.passphrase,
        "ver_key": ver.key,
        "sha256": sha256_hash_data(plaintext),
    }
    param_bytes = pickle.dumps(cipher_params)

    # Hybrid AES+RSA encryption for cipher parameters
    aes_key = secrets.token_bytes(32)  # 256-bit AES key
    aes_iv = secrets.token_bytes(12)  # 12-byte IV for AES-GCM

    aes_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv))
    encryptor = aes_cipher.encryptor()
    param_ciphertext = encryptor.update(param_bytes) + encryptor.finalize()
    param_tag = encryptor.tag

    # Combine AES key, IV, and tag for RSA encryption
    ephemeral_data = aes_key + aes_iv + param_tag

    # RSA encryption using the provided public key
    rsa_mgr = RSAManager()
    rsa_mgr.load_public_key(public_key_path)
    ephemeral_data_encrypted = rsa_mgr.encrypt(ephemeral_data)

    # Write output file: RSA data first, then AES-encrypted parameters, then final ciphertext
    with open(output_path, "wb") as f_out:
        f_out.write(len(ephemeral_data_encrypted).to_bytes(4, "big"))
        f_out.write(ephemeral_data_encrypted)

        f_out.write(len(param_ciphertext).to_bytes(4, "big"))
        f_out.write(param_ciphertext)

        f_out.write(data)


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Decrypt a file using layered classical ciphers and RSA-based hybrid decryption.

    This function reverses the process used by encrypt_file:
    1. Reads and RSA-decrypts the ephemeral AES key/IV/tag from the input file using the provided private key.
    2. Reconstructs the AES-GCM context to decrypt the serialized cipher parameters.
    3. Restores the classical cipher parameters (keys, passphrases, etc.).
    4. Decrypts the final ciphertext using the classical ciphers in reverse order.
    5. Verifies the SHA-256 hash of the resulting data matches the stored value, printing a warning if it does not.

    Args:
        input_path: Path to the ciphertext file to be decrypted.
        output_path: Path for writing the decrypted plaintext file.
        private_key_path: Path to the RSA private key (PEM file).

    Raises:
        ValueError: If decryption fails due to invalid or missing parameters.
        OSError: If reading/writing files fails.
    """
    with open(input_path, "rb") as f_in:
        ephemeral_len = int.from_bytes(f_in.read(4), "big")
        ephemeral_data_encrypted = f_in.read(ephemeral_len)

        param_len = int.from_bytes(f_in.read(4), "big")
        param_ciphertext = f_in.read(param_len)

        ciphertext = f_in.read()

    # RSA decryption to recover the AES key, IV, and tag
    rsa_mgr = RSAManager()
    rsa_mgr.load_private_key(private_key_path)
    ephemeral_data = rsa_mgr.decrypt(ephemeral_data_encrypted)

    aes_key = ephemeral_data[:32]
    aes_iv = ephemeral_data[32:44]
    param_tag = ephemeral_data[44:]

    # AES-GCM decryption for the cipher parameters
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv, param_tag))
    decryptor = aes_cipher.decryptor()
    param_bytes = decryptor.update(param_ciphertext) + decryptor.finalize()

    cipher_params = pickle.loads(param_bytes)

    # Rebuild classical ciphers
    mono = MonoalphabeticCipher(key=cipher_params["mono_key"])
    poly = PolyalphabeticCipher(key=cipher_params["poly_key"])
    trans = TranspositionCipher(columns=cipher_params["trans_columns"])
    vig = VigenereCipher(passphrase=cipher_params["vig_passphrase"])
    ver = VernamCipher(key=cipher_params["ver_key"])

    # Layered decryption
    data = ver.decrypt(ciphertext)
    data = vig.decrypt(data)
    data = poly.decrypt(data)
    data = mono.decrypt(data)
    data = trans.decrypt(data)

    # Verify integrity
    original_hash = cipher_params["sha256"]
    new_hash = sha256_hash_data(data)
    if new_hash != original_hash:
        print("WARNING: File hash mismatch. Possible corruption or tampering.")
    else:
        print("File integrity verified (SHA-256).")

    with open(output_path, "wb") as f_out:
        f_out.write(data)
