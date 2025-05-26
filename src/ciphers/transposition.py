"""Transposition cipher implementation.

This module provides a columnar transposition cipher for byte data. A rectangular table is formed by writing plaintext bytes row by row, then reading them out column by column for encryption. Decryption reverses the process.
"""

import secrets
from typing import Optional


class TranspositionCipher:
    """A columnar transposition cipher that rearranges bytes into columns.

    Attributes:
        columns: The number of columns used to build the transposition table.
    """

    def __init__(self, columns: Optional[int] = None) -> None:
        """Initialize a TranspositionCipher with a provided or random column count.

        Args:
            columns: The number of columns for the transposition. If None, a random value between 4 and 16 is chosen.

        Raises:
            ValueError: If columns <= 1.
        """
        if columns is None:
            self.columns = self._generate_random_columns()
        else:
            if columns <= 1:
                raise ValueError("Number of columns must be greater than 1.")
            self.columns = columns

    @staticmethod
    def _generate_random_columns() -> int:
        """Generate a random number of columns between 4 and 16.

        Returns:
            An integer specifying the column count.
        """
        return secrets.randbelow(13) + 4  # Generates a value in [4..16]

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes using columnar transposition.

        The plaintext is placed in a table row by row, and read out column by column to form the ciphertext.

        Args:
            plaintext: The data to be encrypted.

        Returns:
            A bytes object containing the transposed ciphertext.
        """
        length = len(plaintext)
        columns = self.columns
        rows = (length + columns - 1) // columns

        # Build a list of rows from the plaintext
        table = [plaintext[r * columns : r * columns + columns] for r in range(rows)]

        # Read column by column to form ciphertext
        ciphertext = bytearray(length)
        idx = 0
        for col in range(columns):
            for row_data in table:
                if col < len(row_data):
                    ciphertext[idx] = row_data[col]
                    idx += 1

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext bytes using columnar transposition.

        The ciphertext is placed in a table column by column, then read out row by row to recover the original plaintext.

        Args:
            ciphertext: The data to be decrypted.

        Returns:
            A bytes object containing the transposed plaintext.
        """
        length = len(ciphertext)
        columns = self.columns
        rows = (length + columns - 1) // columns

        # Initialize table for columnar placement
        table = [bytearray(columns) for _ in range(rows)]

        # Fill the table column by column from the ciphertext
        idx = 0
        for col in range(columns):
            for row in range(rows):
                if idx < length:
                    table[row][col] = ciphertext[idx]
                    idx += 1

        # Read row by row to form plaintext
        plaintext = bytearray(length)
        out_idx = 0
        for row in range(rows):
            for col in range(columns):
                plaintext[out_idx] = table[row][col]
                out_idx += 1
                if out_idx == length:
                    break
            if out_idx == length:
                break

        return bytes(plaintext)
