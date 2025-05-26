"""Tests for src.utils.common utility functions."""

import unittest
from src.utils.common import (
    generate_random_bytes,
    generate_random_passphrase,
    generate_permutation_bytes,
)


class TestUtilsCommon(unittest.TestCase):
    """Test the common utilities in src.utils.common."""

    def test_generate_random_bytes(self) -> None:
        """Verify length and randomness of generate_random_bytes output."""
        length = 32
        rand_data = generate_random_bytes(length)
        self.assertEqual(len(rand_data), length)
        # Not a strict randomness test, just check different calls produce different results.
        self.assertNotEqual(
            generate_random_bytes(length), generate_random_bytes(length)
        )

    def test_generate_random_passphrase(self) -> None:
        """Ensure generated passphrase has correct length and valid characters."""
        length = 20
        passphrase = generate_random_passphrase(length)
        self.assertEqual(len(passphrase), length)
        for ch in passphrase:
            self.assertTrue(ch.isalpha(), "Passphrase must contain only letters.")

    def test_generate_permutation_bytes(self) -> None:
        """Verify generate_permutation_bytes returns a permutation of [0..size-1]."""
        size = 256
        perm = generate_permutation_bytes(size)
        self.assertEqual(len(perm), size)
        # Check that sorted(perm) is [0..255]
        self.assertEqual(sorted(perm), list(range(size)))


if __name__ == "__main__":
    unittest.main()
