"""RSA key management using the cryptography library.

This module provides functionality to:
1. Generate RSA key pairs
2. Encrypt data with a public key
3. Decrypt data with a private key
4. Save/load keys in PEM files (optionally password-protected)
"""

from __future__ import annotations
import logging
from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

logger = logging.getLogger(__name__)


class RSAManagerError(Exception):
    """Custom exception for RSAManager file operations or key errors."""


class RSAManager:
    """A manager for RSA key generation, encryption, and decryption.

    This class supports:
    1. Generating a new RSA key pair
    2. Encrypting data with the public key
    3. Decrypting data with the private key
    4. Saving and loading keys in PEM format

    Attributes:
        private_key: An optional RSA private key object.
        public_key: An optional RSA public key object.
    """

    def __init__(
        self,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        public_key: Optional[rsa.RSAPublicKey] = None,
    ) -> None:
        """Initialize an RSAManager with an optional existing key pair.

        Args:
            private_key: An RSA private key object, if already available.
            public_key: An RSA public key object, if already available.
        """
        self.private_key = private_key
        self.public_key = public_key

    def generate_key_pair(self, key_size: int = 2048) -> None:
        """Generate a new RSA key pair using the specified key size.

        Args:
            key_size: The size of the RSA key in bits. Defaults to 2048.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with the stored public key using OAEP with MGF1 (SHA-256).

        Args:
            data: A bytes object containing the plaintext data.

        Returns:
            The ciphertext as bytes.

        Raises:
            ValueError: If the public key is not set.
        """
        if self.public_key is None:
            raise ValueError("Public key is not available for encryption.")

        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with the stored private key using OAEP with MGF1 (SHA-256).

        Args:
            data: A bytes object containing the ciphertext.

        Returns:
            The decrypted plaintext as bytes.

        Raises:
            ValueError: If the private key is not set.
        """
        if self.private_key is None:
            raise ValueError("Private key is not available for decryption.")

        return self.private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def save_private_key(self, filepath: str, password: Optional[bytes] = None) -> None:
        """Save the RSA private key to a PEM file.

        Args:
            filepath: The path where the PEM file will be created.
            password: An optional password for encrypting the private key.

        Raises:
            ValueError: If the private key is not set.
            RSAManagerError: If there's an error writing to the file.
        """
        if self.private_key is None:
            raise ValueError("No private key to save.")

        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        pem_data = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm,
        )

        try:
            with open(filepath, "wb") as file:
                file.write(pem_data)
        except OSError as e:
            logger.exception("Failed to save private key to file.")
            raise RSAManagerError(
                f"Failed to save private key to '{filepath}'. Search for 'RSAManagerError' logs."
            ) from e

    def load_private_key(self, filepath: str, password: Optional[bytes] = None) -> None:
        """Load an RSA private key from a PEM file.

        Args:
            filepath: The path of the PEM file containing the private key.
            password: An optional password if the private key is encrypted.

        Raises:
            ValueError: If the loaded key is not a valid RSA private key.
            RSAManagerError: If there's an error reading from the file.
        """
        try:
            with open(filepath, "rb") as file:
                pem_data = file.read()
        except OSError as e:
            logger.exception("Failed to load private key from file.")
            raise RSAManagerError(
                f"Failed to load private key from '{filepath}'. Search for 'RSAManagerError' logs."
            ) from e

        try:
            private_key = serialization.load_pem_private_key(
                pem_data, password=password
            )
        except Exception as e:
            logger.exception("Failed to deserialize private key.")
            raise ValueError("Loaded key is not a valid RSA private key.") from e

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Loaded key is not a valid RSA private key.")

        self.private_key = private_key
        self.public_key = private_key.public_key()

    def save_public_key(self, filepath: str) -> None:
        """Save the RSA public key to a PEM file.

        Args:
            filepath: The path where the PEM file will be created.

        Raises:
            ValueError: If the public key is not set.
            RSAManagerError: If there's an error writing to the file.
        """
        if self.public_key is None:
            raise ValueError("No public key to save.")

        pem_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        try:
            with open(filepath, "wb") as file:
                file.write(pem_data)
        except OSError as e:
            logger.exception("Failed to save public key to file.")
            raise RSAManagerError(
                f"Failed to save public key to '{filepath}'. Search for 'RSAManagerError' logs."
            ) from e

    def load_public_key(self, filepath: str) -> None:
        """Load an RSA public key from a PEM file.

        Args:
            filepath: The path of the PEM file containing the public key.

        Raises:
            ValueError: If the loaded key is not a valid RSA public key.
            RSAManagerError: If there's an error reading from the file.
        """
        try:
            with open(filepath, "rb") as file:
                pem_data = file.read()
        except OSError as e:
            logger.exception("Failed to load public key from file.")
            raise RSAManagerError(
                f"Failed to load public key from '{filepath}'. Search for 'RSAManagerError' logs."
            ) from e

        try:
            public_key = serialization.load_pem_public_key(pem_data)
        except Exception as e:
            logger.exception("Failed to deserialize public key.")
            raise ValueError("Loaded key is not a valid RSA public key.") from e

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Loaded key is not a valid RSA public key.")

        self.public_key = public_key
