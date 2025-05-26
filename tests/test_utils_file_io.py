"""Tests for src.utils.file_io functions involving chunked read/write and entire file reading."""

import os
import unittest
import tempfile

from src.utils.file_io import (
    read_file_in_chunks,
    write_file_in_chunks,
    read_entire_file,
    bytes_to_chunks,
)


class TestFileIO(unittest.TestCase):
    """Test the file I/O utilities in src.utils.file_io."""

    def test_read_write_file_in_chunks(self) -> None:
        """Test writing data in chunks, then reading it back in chunks."""
        data = b"Chunked data for testing." * 100  # some repeated pattern
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_chunks.bin")

            # Write in chunks
            chunk_generator = bytes_to_chunks(data, chunk_size=64)
            write_file_in_chunks(filepath, chunk_generator)

            # Read in chunks
            read_back = bytearray()
            for chunk in read_file_in_chunks(filepath, chunk_size=32):
                read_back.extend(chunk)
            self.assertEqual(read_back, data)

    def test_read_entire_file(self) -> None:
        """Test reading an entire file into memory."""
        data = b"Full file content.\nAnother line."
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_full_read.txt")
            with open(filepath, "wb") as f_out:
                f_out.write(data)

            result = read_entire_file(filepath)
            self.assertEqual(result, data)

    def test_bytes_to_chunks(self) -> None:
        """Test that bytes_to_chunks splits data correctly."""
        data = b"abcdefghijk"
        chunked = list(bytes_to_chunks(data, chunk_size=4))
        self.assertEqual(chunked, [b"abcd", b"efgh", b"ijk"])


if __name__ == "__main__":
    unittest.main()
