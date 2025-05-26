"""Tests for direct usage of encrypt_file and decrypt_file from src.pipeline.io."""

import os
import unittest
import tempfile

from src.pipeline.io import encrypt_file, decrypt_file
from src.crypto.rsa_manager import RSAManager
from src.utils.file_io import read_entire_file


class TestPipelineIO(unittest.TestCase):
    """Test encrypt_file/decrypt_file end-to-end with RSA keys."""

    def setUp(self) -> None:
        """Create an RSA key pair and temporary directory for files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pub_key_path = os.path.join(self.temp_dir.name, "public.pem")
        self.priv_key_path = os.path.join(self.temp_dir.name, "private.pem")

        rsa_mgr = RSAManager()
        rsa_mgr.generate_key_pair()
        rsa_mgr.save_public_key(self.pub_key_path)
        rsa_mgr.save_private_key(self.priv_key_path)

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_encrypt_decrypt_file(self) -> None:
        """Test file-level encryption and decryption with classical + hybrid pipeline."""
        plaintext = b"Hello file pipeline!"
        input_file = os.path.join(self.temp_dir.name, "test_input.txt")
        with open(input_file, "wb") as f_in:
            f_in.write(plaintext)

        output_file_enc = os.path.join(self.temp_dir.name, "test_enc.bin")
        output_file_dec = os.path.join(self.temp_dir.name, "test_dec.txt")

        # Encrypt
        encrypt_file(input_file, output_file_enc, self.pub_key_path)
        # Decrypt
        decrypt_file(output_file_enc, output_file_dec, self.priv_key_path)

        recovered = read_entire_file(output_file_dec)
        self.assertEqual(recovered, plaintext)

    def test_missing_input_raises(self) -> None:
        """Ensure OSError is raised if input file does not exist."""
        with self.assertRaises(OSError):
            encrypt_file("no_such_input.txt", "out.enc", self.pub_key_path)


if __name__ == "__main__":
    unittest.main()
