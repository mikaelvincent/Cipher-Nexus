"""Polyalphabetic cipher implementation.

This module provides a repeated-shift cipher for byte data. Each byte of the key determines the shift for the corresponding byte of plaintext, cycling through the key as needed.
"""

import secrets
from typing import Optional


class PolyalphabeticCipher:
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
            self.key = self._generate_random_key()
        else:
            if len(key) == 0:
                raise ValueError("Key must not be empty.")
            self.key = key

    @staticmethod
    def _generate_random_key(length: int = 16) -> bytes:
        """Generate a random key of the given length.

        Args:
            length: The number of bytes in the generated key. Defaults to 16.

        Returns:
            A bytes object containing random data of the specified length.
        """
        return secrets.token_bytes(length)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the given plaintext by repeatedly shifting each byte.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            The encrypted data as bytes.
        """
        ciphertext = bytearray(len(plaintext))
        key_length = len(self.key)
        for i, byte_val in enumerate(plaintext):
            shift = self.key[i % key_length]
            ciphertext[i] = (byte_val + shift) % 256
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the given ciphertext by reversing the repeated shift.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            The decrypted data as bytes.
        """
        plaintext = bytearray(len(ciphertext))
        key_length = len(self.key)
        for i, byte_val in enumerate(ciphertext):
            shift = self.key[i % key_length]
            plaintext[i] = (byte_val - shift) % 256
        return bytes(plaintext)
