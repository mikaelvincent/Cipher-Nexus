"""High-level classical encryption/decryption pipeline using layered ciphers.

This module:
1. Reads input data in chunks (to avoid large memory usage).
2. Applies or reverses multiple classical ciphers in sequence.
3. Streams the final result to the output file.

Note: Some ciphers (like Transposition) still require in-memory rearrangement,
so data is accumulated in memory for them.
"""

from __future__ import annotations
import logging
from typing import Generator

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher
from src.utils.file_io import read_file_in_chunks, write_file_in_chunks

logger = logging.getLogger(__name__)


def _accumulate_data(input_path: str) -> bytes:
    """Accumulate all file data into memory from the given path.

    Args:
        input_path: The path to the file to be read.

    Returns:
        A bytes object containing the entire file contents.
    """
    data = bytearray()
    for chunk in read_file_in_chunks(input_path):
        data.extend(chunk)
    return bytes(data)


def encrypt_classical(input_path: str) -> tuple[bytes, dict[str, bytes | int | str]]:
    """Encrypt the file at input_path with multiple classical ciphers in sequence.

    1. Read all input data (some ciphers must see full data).
    2. Apply transposition, monoalphabetic, polyalphabetic, vigenere, vernam.
    3. Collect cipher parameters in a dictionary (for later serialization).

    Args:
        input_path: The path to the plaintext file.

    Returns:
        A tuple of (ciphertext, cipher_params).
    """
    # Read entire file data into memory
    plaintext = _accumulate_data(input_path)

    # Instantiate ciphers with random parameters
    mono = MonoalphabeticCipher()
    poly = PolyalphabeticCipher()
    trans = TranspositionCipher()
    vig = VigenereCipher()
    ver = VernamCipher()

    # Layered encryption
    data = trans.encrypt(plaintext)
    data = mono.encrypt(data)
    data = poly.encrypt(data)
    data = vig.encrypt(data)
    data = ver.encrypt(data)

    # Gather cipher parameters
    cipher_params: dict[str, bytes | int | str] = {
        "mono_key": mono.key,
        "poly_key": poly.key,
        "trans_columns": trans.columns,
        "vig_passphrase": vig.passphrase,
        "ver_key": ver.key,
    }
    return data, cipher_params


def decrypt_classical(
    ciphertext: bytes,
    cipher_params: dict[str, bytes | int | str],
) -> bytes:
    """Decrypt ciphertext with the classical ciphers, reversing the order.

    1. Rebuild ciphers using the provided parameters.
    2. Reverse layered encryption: vernam -> vigenere -> polyalphabetic -> monoalphabetic -> transposition.

    Args:
        ciphertext: The full ciphertext bytes from the classical pipeline.
        cipher_params: A dictionary containing the cipher parameters.

    Returns:
        The fully decrypted data (plaintext).
    """
    mono = MonoalphabeticCipher(key=cipher_params["mono_key"])  # type: ignore
    poly = PolyalphabeticCipher(key=cipher_params["poly_key"])  # type: ignore
    trans = TranspositionCipher(columns=cipher_params["trans_columns"])  # type: ignore
    vig = VigenereCipher(passphrase=cipher_params["vig_passphrase"])  # type: ignore
    ver = VernamCipher(key=cipher_params["ver_key"])  # type: ignore

    # Reverse the layered process
    data = ver.decrypt(ciphertext)
    data = vig.decrypt(data)
    data = poly.decrypt(data)
    data = mono.decrypt(data)
    plaintext = trans.decrypt(data)
    return plaintext


def write_data(output_path: str, data: bytes) -> None:
    """Write data to the output file in chunks.

    Args:
        output_path: The path of the output file.
        data: The bytes to write.
    """

    def _byte_chunker(
        input_data: bytes, chunk_size: int = 4096
    ) -> Generator[bytes, None, None]:
        for i in range(0, len(input_data), chunk_size):
            yield input_data[i : i + chunk_size]

    write_file_in_chunks(output_path, _byte_chunker(data))
