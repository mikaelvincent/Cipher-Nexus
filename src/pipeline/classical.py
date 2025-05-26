"""High-level classical encryption/decryption pipeline using layered ciphers.

This module exports two main functions:

- encrypt_classical(plaintext: bytes) -> (ciphertext: bytes, cipher_params: dict)
- decrypt_classical(ciphertext: bytes, cipher_params: dict) -> plaintext: bytes

It applies or reverses multiple classical ciphers in sequence:

1. Transposition
2. Monoalphabetic
3. Polyalphabetic
4. Vigenere
5. Vernam

The returned cipher_params dictionary includes necessary keys/passphrases to reconstruct the decryption in the reverse order.
"""

from __future__ import annotations

from typing import Union

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vigenere import VigenereCipher
from src.ciphers.vernam import VernamCipher


def encrypt_classical(
    plaintext: bytes,
) -> tuple[bytes, dict[str, Union[bytes, int, str]]]:
    """Encrypt the plaintext bytes using multiple classical ciphers in sequence.

    1. Transposition
    2. Monoalphabetic
    3. Polyalphabetic
    4. Vigenere
    5. Vernam

    Args:
        plaintext: The data to be encrypted (in memory).

    Returns:
        A tuple of (ciphertext, cipher_params).
    """
    # Instantiate ciphers with random parameters
    mono = MonoalphabeticCipher()
    poly = PolyalphabeticCipher()
    trans = TranspositionCipher()
    vig = VigenereCipher()
    ver = VernamCipher()

    # Layered encryption
    data = trans.encrypt(plaintext)
    data = mono.encrypt(data)
    data = poly.encrypt(data)
    data = vig.encrypt(data)
    data = ver.encrypt(data)

    # Gather cipher parameters
    cipher_params: dict[str, Union[bytes, int, str]] = {
        "mono_key": mono.key,
        "poly_key": poly.key,
        "trans_columns": trans.columns,
        "vig_passphrase": vig.passphrase,
        "ver_key": ver.key,
    }
    return data, cipher_params


def decrypt_classical(
    ciphertext: bytes,
    cipher_params: dict[str, Union[bytes, int, str]],
) -> bytes:
    """Decrypt the ciphertext bytes using the reverse order of classical ciphers.

    1. Vernam
    2. Vigenere
    3. Polyalphabetic
    4. Monoalphabetic
    5. Transposition

    Args:
        ciphertext: The data to be decrypted.
        cipher_params: A dictionary containing the cipher parameters.

    Returns:
        The fully decrypted plaintext bytes.
    """
    from src.ciphers.monoalphabetic import MonoalphabeticCipher
    from src.ciphers.polyalphabetic import PolyalphabeticCipher
    from src.ciphers.transposition import TranspositionCipher
    from src.ciphers.vigenere import VigenereCipher
    from src.ciphers.vernam import VernamCipher

    mono = MonoalphabeticCipher(key=cipher_params["mono_key"])  # type: ignore
    poly = PolyalphabeticCipher(key=cipher_params["poly_key"])  # type: ignore
    trans = TranspositionCipher(columns=cipher_params["trans_columns"])  # type: ignore
    vig = VigenereCipher(passphrase=cipher_params["vig_passphrase"])  # type: ignore
    ver = VernamCipher(key=cipher_params["ver_key"])  # type: ignore

    data = ver.decrypt(ciphertext)
    data = vig.decrypt(data)
    data = poly.decrypt(data)
    data = mono.decrypt(data)
    plaintext = trans.decrypt(data)
    return plaintext
