"""Utility functions for file I/O operations.

This module includes helpers for reading and writing files in chunks, which is especially useful for large files in encryption/decryption scenarios to manage memory usage.
"""

from typing import Generator


def read_file_in_chunks(
    filepath: str, chunk_size: int = 4096
) -> Generator[bytes, None, None]:
    """Read binary data from a file in fixed-size chunks.

    Args:
        filepath: The path to the file to be read.
        chunk_size: The size of each chunk in bytes. Defaults to 4096.

    Yields:
        A sequence of byte chunks read from the file.

    Raises:
        OSError: If an error occurs opening or reading the file.
    """
    with open(filepath, mode="rb") as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            yield data


def write_file_in_chunks(
    filepath: str, data_stream: Generator[bytes, None, None]
) -> None:
    """Write binary data to a file from a generator of byte chunks.

    Args:
        filepath: The path to the file to write to.
        data_stream: A generator producing chunks of bytes to be written.

    Raises:
        OSError: If an error occurs opening or writing to the file.
    """
    with open(filepath, mode="wb") as file:
        for chunk in data_stream:
            file.write(chunk)
