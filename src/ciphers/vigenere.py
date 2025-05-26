"""Vigenere cipher implementation.

This module provides a classical Vigenere cipher for text-based shifts keyed by a passphrase. Only alphabetic characters (A–Z, a–z) are shifted; other bytes remain unchanged. Encryption and decryption each iterate over the passphrase repeatedly to determine shift amounts.
"""

import secrets
import string
from typing import Optional


class VigenereCipher:
    """A classical Vigenere cipher that shifts letters by passphrase-based offsets.

    Only A–Z and a–z are shifted. Non-alphabetic characters are left as is. The passphrase is repeated across the length of the plaintext or ciphertext.

    Attributes:
        passphrase: The string key used for encryption/decryption.
    """

    def __init__(self, passphrase: Optional[str] = None) -> None:
        """Initialize a VigenereCipher with a provided or randomly generated passphrase.

        Args:
            passphrase: An optional string used as the cipher key. If None, a random 16-character passphrase is generated.

        Raises:
            ValueError: If the provided passphrase is empty or only whitespace.
        """
        if passphrase is None:
            self.passphrase = self._generate_random_passphrase()
        else:
            if not passphrase.strip():
                raise ValueError("Passphrase must not be empty or only whitespace.")
            self.passphrase = passphrase

        # Precompute shift values for each character in the passphrase.
        self._shifts = self._compute_shifts(self.passphrase)

    @staticmethod
    def _generate_random_passphrase(length: int = 16) -> str:
        """Generate a random passphrase of the given length, using A–Z and a–z.

        Args:
            length: The number of characters in the generated passphrase. Defaults to 16.

        Returns:
            A string containing random alphabetical characters.
        """
        alphabet = string.ascii_letters
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _compute_shifts(passphrase: str) -> list[int]:
        """Compute a list of shifts for each character in the passphrase.

        Each character's shift is derived from its lowercase alphabet index (A/a = 0, Z/z = 25).

        Args:
            passphrase: The passphrase string.

        Returns:
            A list of integer shift values (0–25) corresponding to each character in the passphrase.
        """
        shifts = []
        for ch in passphrase:
            ch_lower = ch.lower()
            if "a" <= ch_lower <= "z":
                shifts.append(ord(ch_lower) - ord("a"))
            else:
                # Non-alphabetic passphrase char defaults to zero shift
                shifts.append(0)
        return shifts

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the given plaintext using the Vigenere cipher.

        Alphabetic characters (A–Z, a–z) are shifted by passphrase-based offsets. Other characters remain unchanged.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            The encrypted data as bytes.
        """
        ciphertext = bytearray(len(plaintext))
        pass_len = len(self._shifts)
        shift_index = 0

        for i, byte_val in enumerate(plaintext):
            ch = byte_val
            shift = self._shifts[shift_index % pass_len]

            if 65 <= ch <= 90:  # 'A'–'Z'
                # Shift within uppercase range
                ch = ((ch - 65 + shift) % 26) + 65
                shift_index += 1
            elif 97 <= ch <= 122:  # 'a'–'z'
                # Shift within lowercase range
                ch = ((ch - 97 + shift) % 26) + 97
                shift_index += 1

            ciphertext[i] = ch

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the given ciphertext using the Vigenere cipher.

        Alphabetic characters are reversed by passphrase-based offsets. Other characters remain unchanged.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            The decrypted data as bytes.
        """
        plaintext = bytearray(len(ciphertext))
        pass_len = len(self._shifts)
        shift_index = 0

        for i, byte_val in enumerate(ciphertext):
            ch = byte_val
            shift = self._shifts[shift_index % pass_len]

            if 65 <= ch <= 90:  # 'A'–'Z'
                # Reverse shift within uppercase range
                ch = ((ch - 65 - shift) % 26) + 65
                shift_index += 1
            elif 97 <= ch <= 122:  # 'a'–'z'
                # Reverse shift within lowercase range
                ch = ((ch - 97 - shift) % 26) + 97
                shift_index += 1

            plaintext[i] = ch

        return bytes(plaintext)
