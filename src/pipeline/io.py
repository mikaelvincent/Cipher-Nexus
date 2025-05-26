"""File-level operations combining classical encryption/decryption with RSA + AES-GCM.

Provides high-level functions:
    encrypt_file(input_path, output_path, public_key_path)
    decrypt_file(input_path, output_path, private_key_path)

Usage Example:
    >>> from src.pipeline.io import encrypt_file, decrypt_file
    >>> encrypt_file("mydoc.txt", "mydoc.enc", "public_key.pem")
    >>> decrypt_file("mydoc.enc", "mydoc_decrypted.txt", "private_key.pem")

Steps:
1. Read the entire input file into memory.
2. Run the classical pipeline (encrypt_classical or decrypt_classical).
3. Envelope-encrypt or decrypt the cipher parameters (RSA + AES-GCM).
4. Construct/parse the final output structure with ephemeral data.
5. Write or restore the final file data.
6. A SHA-256 hash in cipher_params["sha256"] verifies integrity upon decryption.
"""

from __future__ import annotations

import logging

from src.pipeline.classical import encrypt_classical, decrypt_classical
from src.crypto.hybrid import envelope_encrypt_params, envelope_decrypt_params
from src.crypto.hashing import sha256_hash_data
from src.crypto.rsa_manager import RSAManager
from src.utils.file_io import read_entire_file, write_file_in_chunks
from src.utils.constants import LENGTH_HEADER_SIZE, AES_KEY_SIZE, GCM_IV_SIZE

logger = logging.getLogger(__name__)


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt the file at input_path and write the result to output_path.

    The classical pipeline is used first, then the resulting cipher_params are envelope-encrypted using RSA (public_key_path) plus an ephemeral AES-GCM.

    Args:
        input_path: Path to the plaintext file.
        output_path: Path to the resulting encrypted file.
        public_key_path: Path to the RSA public key (PEM).

    Raises:
        OSError: If reading or writing files fails.
        ValueError: If encryption steps or key usage fail.
    """
    # 1. Read entire file
    plaintext = read_entire_file(input_path)

    # 2. Classical encryption
    ciphertext, cipher_params = encrypt_classical(plaintext)

    # 3. Compute SHA-256 of original data
    cipher_params["sha256"] = sha256_hash_data(plaintext)

    # 4. Envelope-encrypt the parameters
    ephemeral_enc, param_ciphertext, param_tag = envelope_encrypt_params(
        cipher_params, public_key_path
    )

    # 5. Build final output structure
    #    [4-byte length of ephemeral_enc][ephemeral_enc]
    #    [4-byte length of param_ciphertext][param_ciphertext]
    #    [ciphertext]
    header_1 = len(ephemeral_enc).to_bytes(LENGTH_HEADER_SIZE, "big")
    header_2 = len(param_ciphertext).to_bytes(LENGTH_HEADER_SIZE, "big")

    final_output = header_1 + ephemeral_enc + header_2 + param_ciphertext + ciphertext

    # 6. Write output (in chunks)
    write_file_in_chunks(output_path, _in_chunks(final_output))


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Decrypt a file produced by encrypt_file and restore original data.

    The final output structure is parsed to extract ephemeral data, param ciphertext, and the classical ciphertext. Then the classical pipeline is reversed.

    A SHA-256 check ensures integrity of the recovered plaintext.

    Args:
        input_path: Path to the encrypted file.
        output_path: Path to write the recovered plaintext.
        private_key_path: Path to the RSA private key (PEM).

    Raises:
        OSError: If reading or writing files fails.
        ValueError: If an integrity check fails or keys are invalid.
    """
    # 1. Read entire file
    file_data = read_entire_file(input_path)

    # 2. Parse ephemeral_enc
    cursor = 0
    ephemeral_len = int.from_bytes(
        file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big"
    )
    cursor += LENGTH_HEADER_SIZE
    ephemeral_data_enc = file_data[cursor : cursor + ephemeral_len]
    cursor += ephemeral_len

    # 3. Parse param_ciphertext
    param_len = int.from_bytes(file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big")
    cursor += LENGTH_HEADER_SIZE
    param_ciphertext = file_data[cursor : cursor + param_len]
    cursor += param_len

    # 4. Remaining = classical ciphertext
    ciphertext = file_data[cursor:]

    # 5. Decrypt ephemeral data to retrieve AES key + IV + param_tag
    rsa_mgr = RSAManager()
    rsa_mgr.load_private_key(private_key_path)
    ephemeral_data = rsa_mgr.decrypt(ephemeral_data_enc)

    param_tag = ephemeral_data[AES_KEY_SIZE + GCM_IV_SIZE :]

    # 6. Envelope-decrypt cipher_params
    cipher_params = envelope_decrypt_params(
        ephemeral_data_enc, param_ciphertext, param_tag, private_key_path
    )

    # 7. Classical decryption
    plaintext = decrypt_classical(ciphertext, cipher_params)

    # 8. Verify integrity
    old_hash = cipher_params["sha256"]
    new_hash = sha256_hash_data(plaintext)
    if new_hash != old_hash:
        raise ValueError("SHA-256 mismatch: possible corruption or tampering.")

    # 9. Write recovered plaintext
    write_file_in_chunks(output_path, _in_chunks(plaintext))


def _in_chunks(data: bytes, chunk_size: int = 4096):
    """Generator that yields the data in chunks of chunk_size.

    Args:
        data: The bytes to be chunked.
        chunk_size: Number of bytes per chunk.

    Yields:
        Subsets of 'data' of length up to chunk_size.
    """
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]
