"""Vernam cipher implementation.

This module provides an XOR-based cipher for byte data. Each byte in the key is XORed with the corresponding plaintext byte to encrypt. For decryption, the same operation is applied again since XOR is its own inverse.
"""

from __future__ import annotations
from typing import Optional

from src.ciphers.cipher_base import CipherBase
from src.ciphers._stream_cipher_utils import repeated_xor
from src.utils.common import generate_random_bytes


class VernamCipher(CipherBase):
    """An XOR-based Vernam cipher that repeatedly XORs each byte with a key.

    Attributes:
        key: The sequence of bytes used for the XOR operation.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        """Initialize a VernamCipher with a provided or randomly generated key.

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
        """Encrypt the given plaintext by XORing each byte with the key.

        The key is repeated if necessary to match the length of the plaintext.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            The encrypted data as bytes.
        """
        return repeated_xor(plaintext, self.key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the given ciphertext by XORing each byte with the key.

        Since XOR is its own inverse, the same operation is used for decryption.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            The decrypted data as bytes.
        """
        return repeated_xor(ciphertext, self.key)
