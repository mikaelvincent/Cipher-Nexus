"""Hashing utilities for data and files using SHA-256.

This module provides functions to compute SHA-256 digests for in-memory data or files. A chunk-based file hashing function is available to support large files without excessive memory usage.
"""

import hashlib


def sha256_hash_data(data: bytes) -> bytes:
    """Compute the SHA-256 hash of the given data.

    Args:
        data: A bytes object containing the data to be hashed.

    Returns:
        A bytes object containing the 32-byte SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def sha256_hash_file(filepath: str, chunk_size: int = 4096) -> bytes:
    """Compute the SHA-256 hash of a file by reading it in chunks.

    Args:
        filepath: The path to the file to be hashed.
        chunk_size: The size of each read chunk in bytes. Defaults to 4096.

    Returns:
        A bytes object containing the 32-byte SHA-256 digest.

    Raises:
        OSError: If an error occurs opening or reading the file.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            sha256.update(data)
    return sha256.digest()
