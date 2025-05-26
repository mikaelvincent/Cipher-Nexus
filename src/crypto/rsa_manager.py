"""RSA key management using the cryptography library.

This module provides functionality to generate RSA key pairs, encrypt data with a public key, and decrypt data with a private key. Keys can also be saved to and loaded from PEM files. By default, the keys use 2048-bit RSA and OAEP (SHA-256) padding.
"""

from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSAManager:
    """A manager for RSA key generation, encryption, and decryption.

    This class supports:
    1. Generating a new RSA key pair
    2. Encrypting data with the public key
    3. Decrypting data with the private key
    4. Saving and loading keys in PEM format

    Attributes:
        private_key: An optional RSA private key.
        public_key: An optional RSA public key.
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

        ciphertext = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

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

        plaintext = self.private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext

    def save_private_key(self, filepath: str, password: Optional[bytes] = None) -> None:
        """Save the RSA private key to a PEM file.

        Args:
            filepath: The path where the PEM file will be created.
            password: An optional password for encrypting the private key.

        Raises:
            ValueError: If the private key is not set.
            OSError: If there's an error writing to the file.
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

        with open(filepath, "wb") as file:
            file.write(pem_data)

    def load_private_key(self, filepath: str, password: Optional[bytes] = None) -> None:
        """Load an RSA private key from a PEM file.

        Args:
            filepath: The path of the PEM file containing the private key.
            password: An optional password if the private key is encrypted.

        Raises:
            ValueError: If the loaded key is not a valid RSA private key.
            OSError: If there's an error reading from the file.
        """
        with open(filepath, "rb") as file:
            pem_data = file.read()

        private_key = serialization.load_pem_private_key(pem_data, password=password)

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
            OSError: If there's an error writing to the file.
        """
        if self.public_key is None:
            raise ValueError("No public key to save.")

        pem_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(filepath, "wb") as file:
            file.write(pem_data)

    def load_public_key(self, filepath: str) -> None:
        """Load an RSA public key from a PEM file.

        Args:
            filepath: The path of the PEM file containing the public key.

        Raises:
            ValueError: If the loaded key is not a valid RSA public key.
            OSError: If there's an error reading from the file.
        """
        with open(filepath, "rb") as file:
            pem_data = file.read()

        public_key = serialization.load_pem_public_key(pem_data)

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Loaded key is not a valid RSA public key.")

        self.public_key = public_key
