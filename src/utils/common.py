"""Common utility functions for the Cipher Nexus project.

This module centralizes shared logic like random key generation or passphrase creation.
"""

import secrets
import string


def generate_random_bytes(length: int = 16) -> bytes:
    """Generate random bytes of the specified length.

    Args:
        length: The number of bytes to generate. Defaults to 16.

    Returns:
        A bytes object of length 'length' containing random data.
    """
    return secrets.token_bytes(length)


def generate_random_passphrase(length: int = 16) -> str:
    """Generate a random passphrase of the specified length, using A-Z and a-z.

    Args:
        length: The number of characters to generate. Defaults to 16.

    Returns:
        A string containing randomly chosen alphabetical characters.
    """
    alphabet = string.ascii_letters
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_permutation_bytes(size: int) -> bytes:
    """Generate a random permutation of the byte values [0..size-1].

    Args:
        size: The range of values to permute.

    Returns:
        A bytes object containing a permutation of [0..size-1].
    """
    arr = list(range(size))
    secrets.SystemRandom().shuffle(arr)
    return bytes(arr)
