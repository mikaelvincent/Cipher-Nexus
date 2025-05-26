"""Utility functions for stream ciphers that repeat a key over data.

These helpers allow operations like repeated XOR or repeated add-mod-256 for each byte of data with a key byte, cycling the key.
"""

from __future__ import annotations
from typing import Callable


def repeat_key_operation(
    data: bytes,
    key: bytes,
    operation: Callable[[int, int], int],
) -> bytes:
    """Apply an operation to each byte in data using repeated key bytes.

    Args:
        data: The input data (plaintext or ciphertext).
        key: The key bytes to repeat over the data.
        operation: A function accepting (data_byte, key_byte) -> int result.

    Returns:
        A new bytes object representing the transformed data.
    """
    output = bytearray(len(data))
    key_length = len(key)
    for i, byte_val in enumerate(data):
        output[i] = operation(byte_val, key[i % key_length])
    return bytes(output)


def repeated_xor(data: bytes, key: bytes) -> bytes:
    """Perform repeated XOR of data bytes with key bytes.

    Args:
        data: The input data (plaintext or ciphertext).
        key: The key bytes to repeat over the data.

    Returns:
        A bytes object where each byte of data is XORed with a repeated key byte.
    """
    return repeat_key_operation(data, key, lambda d, k: d ^ k)


def repeated_add_mod_256(data: bytes, key: bytes) -> bytes:
    """Perform repeated add-mod-256 of data bytes with key bytes.

    Args:
        data: The input data (plaintext or ciphertext).
        key: The key bytes to repeat over the data.

    Returns:
        A bytes object where each byte of data is (d + k) mod 256.
    """
    return repeat_key_operation(data, key, lambda d, k: (d + k) % 256)


def repeated_sub_mod_256(data: bytes, key: bytes) -> bytes:
    """Perform repeated subtract-mod-256 of data bytes with key bytes.

    Args:
        data: The input data.
        key: The key bytes to repeat.

    Returns:
        A bytes object where each byte of data is (d - k) mod 256.
    """
    return repeat_key_operation(data, key, lambda d, k: (d - k) % 256)
