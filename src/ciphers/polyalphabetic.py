"""Polyalphabetic cipher implementation.

This module provides a repeated-shift cipher for byte data. Each byte of the key determines the shift for the corresponding plaintext byte, cycling through the key as needed.
"""

from __future__ import annotations
from typing import Optional

from src.ciphers.cipher_base import CipherBase
from src.ciphers._stream_cipher_utils import repeated_add_mod_256, repeated_sub_mod_256
from src.utils.common import generate_random_bytes


class PolyalphabeticCipher(CipherBase):
    """A polyalphabetic cipher that applies a repeated shift to each byte.

    Each byte in the key is added (mod 256) to the corresponding plaintext byte to encrypt. For decryption, the key byte is subtracted (mod 256).

    Attributes:
        key: The sequence of bytes used for repeated shifting.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        """Initialize a PolyalphabeticCipher with a provided or randomly generated key.

        Args:
            key: An optional bytes object for the cipher. If None, a random 16-byte key is generated.

        Raises:
            ValueError: If the provided key is empty.
        """
        if key is None:
            self.key = generate_random_bytes(16)
        else:
            if len(key) == 0:
                raise ValueError("Key must not be empty.")
            self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the given plaintext by repeatedly shifting each byte.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            The encrypted data as bytes.
        """
        return repeated_add_mod_256(plaintext, self.key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the given ciphertext by reversing the repeated shift.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            The decrypted data as bytes.
        """
        return repeated_sub_mod_256(ciphertext, self.key)
