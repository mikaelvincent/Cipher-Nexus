"""Tests for sha256 hashing functions in src.crypto.hashing."""

import os
import unittest
import tempfile
from src.crypto.hashing import sha256_hash_data, sha256_hash_file


class TestHashing(unittest.TestCase):
    """Test sha256 hashing utilities."""

    def test_sha256_hash_data(self):
        """Test hashing in-memory data."""
        data = b"123456"
        digest = sha256_hash_data(data)
        self.assertEqual(len(digest), 32)
        # Re-hash must match
        self.assertEqual(digest, sha256_hash_data(data))

    def test_sha256_hash_file(self):
        """Test hashing a file's contents."""
        data = b"Testing file hashing"
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "hash_test.bin")
            with open(filepath, "wb") as f_out:
                f_out.write(data)

            digest_file = sha256_hash_file(filepath)
            digest_memory = sha256_hash_data(data)
            self.assertEqual(digest_file, digest_memory)

    def test_sha256_hash_file_missing(self):
        """Ensure OSError is raised for missing file."""
        with self.assertRaises(OSError):
            sha256_hash_file("non_existent_file")


if __name__ == "__main__":
    unittest.main()
