"""Abstract base class for all ciphers in Cipher Nexus.

Defines a consistent interface (encrypt/decrypt) that all ciphers must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class CipherBase(ABC):
    """Abstract base class for ciphers providing a consistent interface."""

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt the provided data.

        Args:
            data: The plaintext bytes to encrypt.

        Returns:
            Encrypted bytes.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt the provided data.

        Args:
            data: The ciphertext bytes to decrypt.

        Returns:
            Decrypted bytes.
        """
        raise NotImplementedError
