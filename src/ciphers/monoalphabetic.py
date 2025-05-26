"""Monoalphabetic cipher implementation.

This module provides a mapping-based substitution cipher for byte data. A single substitution mapping is applied for all bytes in the 0-255 range.
"""

from __future__ import annotations
from typing import Optional

from src.ciphers.cipher_base import CipherBase
from src.utils.common import generate_permutation_bytes


class MonoalphabeticCipher(CipherBase):
    """A monoalphabetic cipher that substitutes each byte with a unique mapping.

    This cipher uses a 256-byte 'key' representing a permutation of 0-255. Each position in the key corresponds to a plaintext byte (0-255), and the value at that position is the substituted byte for encryption. The decryption process uses the inverse of this mapping.

    Attributes:
        key: The 256-byte key (permutation of 0-255) used for substitution.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        """Initialize a MonoalphabeticCipher with a provided or randomly generated key.

        Args:
            key: An optional 256-byte value for the cipher. If None, a random key is generated.

        Raises:
            ValueError: If the provided key is not exactly 256 bytes long.
        """
        if key is None:
            self.key = self.generate_random_key()
        else:
            if len(key) != 256:
                raise ValueError(
                    "Key must be exactly 256 bytes representing a permutation of 0-255."
                )
            self.key = key

        # Create translation tables for encryption and decryption.
        self._encryption_table = bytes.maketrans(bytes(range(256)), self.key)
        self._decryption_table = bytes.maketrans(self.key, bytes(range(256)))

    @staticmethod
    def generate_random_key() -> bytes:
        """Generate a random 256-byte key (permutation of 0-255).

        Returns:
            A bytes object representing a random permutation of the values 0-255.
        """
        return generate_permutation_bytes(256)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes using the monoalphabetic substitution.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            A bytes object containing the encrypted data.
        """
        return plaintext.translate(self._encryption_table)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext bytes using the inverse of the monoalphabetic substitution.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            A bytes object containing the decrypted data.
        """
        return ciphertext.translate(self._decryption_table)
