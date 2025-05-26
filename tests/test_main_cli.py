"""Basic CLI tests for main.py argument parsing and usage."""

import os
import unittest
import tempfile
import subprocess
import sys

from src.crypto.rsa_manager import RSAManager


class TestMainCLI(unittest.TestCase):
    """Minimal tests to ensure the CLI usage in main.py runs without error under valid arguments, and fails appropriately under invalid usage."""

    def setUp(self) -> None:
        """Generate RSA keys for CLI tests."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pub_key_path = os.path.join(self.temp_dir.name, "public.pem")
        self.priv_key_path = os.path.join(self.temp_dir.name, "private.pem")

        # Generate keys
        rsa_mgr = RSAManager()
        rsa_mgr.generate_key_pair()
        rsa_mgr.save_public_key(self.pub_key_path)
        rsa_mgr.save_private_key(self.priv_key_path)

        # Create a sample file
        self.sample_file = os.path.join(self.temp_dir.name, "sample.txt")
        with open(self.sample_file, "wb") as f:
            f.write(b"CLI test data")

    def tearDown(self) -> None:
        """Remove temp dir."""
        self.temp_dir.cleanup()

    def test_encrypt_decrypt_cli(self) -> None:
        """Run main.py with encrypt/decrypt arguments and verify output."""
        encrypted_file = os.path.join(self.temp_dir.name, "sample.enc")
        decrypted_file = os.path.join(self.temp_dir.name, "sample.dec")

        # Use '-m src.main' so Python recognizes 'src' as a package
        cmd_encrypt = [
            sys.executable,
            "-m",
            "src.main",
            "encrypt",
            self.sample_file,
            encrypted_file,
            self.pub_key_path,
        ]
        cmd_decrypt = [
            sys.executable,
            "-m",
            "src.main",
            "decrypt",
            encrypted_file,
            decrypted_file,
            self.priv_key_path,
        ]

        # Encrypt
        result = subprocess.run(cmd_encrypt, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        # Decrypt
        result = subprocess.run(cmd_decrypt, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        # Compare
        with open(self.sample_file, "rb") as f1, open(decrypted_file, "rb") as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_genkey_cli(self) -> None:
        """Generate a new key pair via main.py CLI."""
        new_priv = os.path.join(self.temp_dir.name, "cli_priv.pem")
        new_pub = os.path.join(self.temp_dir.name, "cli_pub.pem")

        cmd_genkey = [
            sys.executable,
            "-m",
            "src.main",
            "genkey",
            new_priv,
            new_pub,
            "1024",
        ]
        result = subprocess.run(cmd_genkey, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(os.path.exists(new_priv))
        self.assertTrue(os.path.exists(new_pub))

    def test_invalid_args(self) -> None:
        """Check that invalid arguments produce usage help."""
        cmd_invalid = [sys.executable, "-m", "src.main", "unknown_cmd"]
        result = subprocess.run(cmd_invalid, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
