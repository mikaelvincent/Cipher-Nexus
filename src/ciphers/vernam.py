"""Vernam cipher implementation.

This module provides an XOR-based cipher for byte data. Each byte in the key is XORed with the corresponding plaintext byte to encrypt. For decryption, the same operation is applied again since XOR is its own inverse.
"""

import secrets
from typing import Optional


class VernamCipher:
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
        """Encrypt the given plaintext by XORing each byte with the key.

        The key is repeated if necessary to match the length of the plaintext.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            The encrypted data as bytes.
        """
        return self._xor_data(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the given ciphertext by XORing each byte with the key.

        Since XOR is its own inverse, the same operation is used for decryption.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            The decrypted data as bytes.
        """
        return self._xor_data(ciphertext)

    def _xor_data(self, data: bytes) -> bytes:
        """Perform XOR between the data and the key, repeating the key if needed.

        Args:
            data: A bytes object to be XORed with the key.

        Returns:
            A bytes object resulting from XORing the data with the key.
        """
        output = bytearray(len(data))
        key_length = len(self.key)
        for i, byte_val in enumerate(data):
            output[i] = byte_val ^ self.key[i % key_length]
        return bytes(output)
