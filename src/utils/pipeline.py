"""High-level encryption/decryption pipeline using layered classical ciphers and RSA.

This module centralizes the logic to:
1. Read a plaintext or ciphertext file in chunks.
2. Apply or reverse multiple classical ciphers in memory.
3. Encrypt or decrypt the cipher parameters with RSA, leveraging a hybrid AES + RSA approach.
4. Write or read the resulting data to/from an output file in chunks.
"""

import pickle
import secrets
from typing import Dict, Any, Generator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher
from src.crypto.rsa_manager import RSAManager
from src.crypto.hashing import sha256_hash_data
from src.utils.file_io import read_file_in_chunks, write_file_in_chunks
from src.utils.constants import AES_KEY_SIZE, GCM_IV_SIZE, LENGTH_HEADER_SIZE


def _byte_chunker(data: bytes, chunk_size: int = 4096) -> Generator[bytes, None, None]:
    """Yield chunks from a bytes object."""
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt a file using layered classical ciphers and RSA-based hybrid encryption.

    Steps:
    1. Read the plaintext from the input file in chunks, accumulate in memory.
    2. Encrypt the plaintext with multiple classical ciphers in sequence.
    3. Gather cipher parameters + a SHA-256 hash of the original file into a dictionary.
    4. Serialize the dictionary and encrypt it with AES-GCM (using a random key/IV).
    5. Encrypt the small AES key/IV/tag bundle with RSA-OAEP (hybrid approach).
    6. Write the output file in chunks:
       [4-byte length of RSA data][RSA data][4-byte length of AES params][AES params][final ciphertext].
    """
    # Read entire plaintext in memory (still chunked from disk)
    plaintext = bytearray()
    for chunk in read_file_in_chunks(input_path):
        plaintext.extend(chunk)

    # Instantiate ciphers with random parameters
    mono = MonoalphabeticCipher()
    poly = PolyalphabeticCipher()
    trans = TranspositionCipher()
    vig = VigenereCipher()
    ver = VernamCipher()

    # Layered classical cipher encryption in memory
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
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    aes_iv = secrets.token_bytes(GCM_IV_SIZE)

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

    # Prepare final output as a single byte buffer
    header_1 = len(ephemeral_data_encrypted).to_bytes(LENGTH_HEADER_SIZE, "big")
    header_2 = len(param_ciphertext).to_bytes(LENGTH_HEADER_SIZE, "big")

    final_output = (
        header_1 + ephemeral_data_encrypted + header_2 + param_ciphertext + data
    )

    # Write output in chunks
    write_file_in_chunks(output_path, _byte_chunker(final_output))


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Decrypt a file using layered classical ciphers and RSA-based hybrid decryption.

    Reverses encrypt_file steps:
    1. Read and parse the RSA-encrypted data length & data, AES-encrypted parameters length & data, and final ciphertext.
    2. RSA-decrypt ephemeral AES key/IV/tag, reconstruct AES-GCM to decrypt cipher parameters.
    3. Rebuild classical ciphers with extracted parameters, then decrypt final ciphertext.
    4. Verify SHA-256 hash of the result.
    5. Write plaintext to disk in chunks.
    """
    # Read all data in memory, but originally chunked from disk
    file_contents = bytearray()
    for chunk in read_file_in_chunks(input_path):
        file_contents.extend(chunk)

    # Parse the first 4 bytes for RSA data length
    cursor = 0
    ephemeral_len = int.from_bytes(file_contents[cursor : cursor + 4], "big")
    cursor += 4

    # Next ephemeral_len bytes are the RSA-encrypted ephemeral data
    ephemeral_data_encrypted = file_contents[cursor : cursor + ephemeral_len]
    cursor += ephemeral_len

    # Next 4 bytes for param ciphertext length
    param_len = int.from_bytes(file_contents[cursor : cursor + 4], "big")
    cursor += 4

    # Next param_len bytes for AES-encrypted cipher parameters
    param_ciphertext = file_contents[cursor : cursor + param_len]
    cursor += param_len

    # Remaining bytes are the final layered ciphertext
    ciphertext = file_contents[cursor:]

    # RSA decryption to recover the AES key, IV, and tag
    rsa_mgr = RSAManager()
    rsa_mgr.load_private_key(private_key_path)
    ephemeral_data = rsa_mgr.decrypt(ephemeral_data_encrypted)

    # Separate AES key, IV, and GCM tag
    # AES_KEY_SIZE = 32, GCM_IV_SIZE = 12
    aes_key = ephemeral_data[:AES_KEY_SIZE]
    aes_iv = ephemeral_data[AES_KEY_SIZE : AES_KEY_SIZE + GCM_IV_SIZE]
    param_tag = ephemeral_data[AES_KEY_SIZE + GCM_IV_SIZE :]

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

    # Write final plaintext in chunks
    write_file_in_chunks(output_path, _byte_chunker(data))
