"""Hybrid encryption/decryption utilities with RSA + AES-GCM.

This module:
1. Handles pickling cipher parameters.
2. Wraps them with AES-GCM, then encrypts that small AES key/IV/tag with RSA (envelope).
3. Conversely, decrypts with RSA, reconstructs AES-GCM, and unpickles cipher parameters.
"""

from __future__ import annotations

import logging
import pickle
import secrets
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.crypto.rsa_manager import RSAManager
from src.utils.constants import AES_KEY_SIZE, GCM_IV_SIZE

logger = logging.getLogger(__name__)


def envelope_encrypt_params(
    cipher_params: Dict[str, Any],
    rsa_public_key_path: str,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt cipher parameters using AES-GCM, then wrap AES key with RSA.

    Args:
        cipher_params: The dictionary of cipher parameters to serialize and encrypt.
        rsa_public_key_path: Path to the RSA public key (PEM).

    Returns:
        A tuple (ephemeral_data_encrypted, param_ciphertext, param_tag),
        where ephemeral_data_encrypted is the RSA-encrypted AES key + IV + tag,
        and param_ciphertext is the AES-GCM-encrypted cipher_params,
        with param_tag as the GCM authentication tag.
    """
    # Serialize cipher parameters
    param_bytes = pickle.dumps(cipher_params)

    # Generate ephemeral AES key and IV
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    aes_iv = secrets.token_bytes(GCM_IV_SIZE)

    # Encrypt parameters with AES-GCM
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv))
    encryptor = aes_cipher.encryptor()
    param_ciphertext = encryptor.update(param_bytes) + encryptor.finalize()
    param_tag = encryptor.tag

    # Wrap AES key, IV, and GCM tag with RSA
    ephemeral_data = aes_key + aes_iv + param_tag
    rsa_mgr = RSAManager()
    rsa_mgr.load_public_key(rsa_public_key_path)
    ephemeral_data_encrypted = rsa_mgr.encrypt(ephemeral_data)

    return ephemeral_data_encrypted, param_ciphertext, param_tag


def envelope_decrypt_params(
    ephemeral_data_encrypted: bytes,
    param_ciphertext: bytes,
    param_tag: bytes,
    rsa_private_key_path: str,
) -> Dict[str, Any]:
    """Recover cipher parameters by unwrapping RSA, then AES-GCM decryption.

    Args:
        ephemeral_data_encrypted: RSA-encrypted data containing AES key + IV + tag.
        param_ciphertext: The AES-GCM-encrypted cipher parameter data.
        param_tag: The GCM authentication tag (extracted from decrypted ephemeral data).
        rsa_private_key_path: Path to the RSA private key (PEM).

    Returns:
        The original dictionary of cipher parameters.

    Raises:
        ValueError: If the RSA or AES decryption fails, or if the loaded parameters are invalid.
    """
    rsa_mgr = RSAManager()
    rsa_mgr.load_private_key(rsa_private_key_path)
    ephemeral_data = rsa_mgr.decrypt(ephemeral_data_encrypted)

    # ephemeral_data should be: aes_key + aes_iv + param_tag
    aes_key = ephemeral_data[:AES_KEY_SIZE]
    aes_iv = ephemeral_data[AES_KEY_SIZE : AES_KEY_SIZE + GCM_IV_SIZE]
    embedded_tag = ephemeral_data[AES_KEY_SIZE + GCM_IV_SIZE :]

    if embedded_tag != param_tag:
        logger.error("GCM tag mismatch from ephemeral data vs param_tag.")
        raise ValueError("AES-GCM tag mismatch: possible data corruption.")

    # Decrypt parameters with AES-GCM
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv, param_tag))
    decryptor = aes_cipher.decryptor()
    param_bytes = decryptor.update(param_ciphertext) + decryptor.finalize()

    # Unpickle to recover the parameter dictionary
    cipher_params = pickle.loads(param_bytes)
    return cipher_params
