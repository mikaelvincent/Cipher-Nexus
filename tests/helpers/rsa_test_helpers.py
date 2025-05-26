"""Shared RSA testing helpers for Cipher Nexus tests."""

import os

from src.crypto.rsa_manager import RSAManager


def generate_rsa_key_pair_and_save(
    directory: str, key_size: int = 2048
) -> tuple[str, str]:
    """Generate an RSA key pair, save the public and private keys to disk, and return their file paths.

    Args:
        directory: The directory where the keys will be saved.
        key_size: The size of the RSA key in bits. Defaults to 2048.

    Returns:
        A tuple (public_key_path, private_key_path).
    """
    rsa_mgr = RSAManager()
    rsa_mgr.generate_key_pair(key_size=key_size)

    pub_key_path = os.path.join(directory, "public_key.pem")
    priv_key_path = os.path.join(directory, "private_key.pem")

    rsa_mgr.save_public_key(pub_key_path)
    rsa_mgr.save_private_key(priv_key_path)

    return pub_key_path, priv_key_path
