"""Utility functions for file I/O operations.

Includes:
- Chunked read/write for large files.
- A helper to read an entire file into memory.
- A helper to chunk a bytes object into pieces.
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


def read_entire_file(filepath: str) -> bytes:
    """Read the entire file into memory as bytes.

    Args:
        filepath: The path to the file.

    Returns:
        All file contents as a bytes object.
    """
    data = bytearray()
    for chunk in read_file_in_chunks(filepath):
        data.extend(chunk)
    return bytes(data)


def bytes_to_chunks(
    data: bytes, chunk_size: int = 4096
) -> Generator[bytes, None, None]:
    """Yield the given bytes in successive chunk_size slices.

    Args:
        data: The full bytes object.
        chunk_size: Number of bytes per chunk. Default 4096.

    Yields:
        Slices of the data of length up to chunk_size.
    """
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]
