"""Main entry point for the Cipher Nexus application.

Usage (CLI):
    If called with no arguments, launches the GUI.
    Otherwise:
        python main.py encrypt <input> <output> <public_key.pem>
        python main.py decrypt <input> <output> <private_key.pem>
        python main.py genkey <private_key.pem> <public_key.pem> [<key_size>]
"""

import logging
import sys

from src.gui import start_gui
from src.pipeline.io import encrypt_file, decrypt_file
from src.crypto.rsa_manager import RSAManager


def main() -> None:
    """Entry point for Cipher Nexus."""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    if len(sys.argv) < 2:
        # No arguments provided; launch the GUI
        start_gui()
        return

    cmd = sys.argv[1].lower()
    if cmd == "encrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        pub_key_path = sys.argv[4]

        try:
            encrypt_file(input_path, output_path, pub_key_path)
            logger.info("Encryption complete. Output written to %s", output_path)
        except Exception as exc:
            logger.exception("Encryption failed.")
            print(f"Encryption failed: {exc}")
            sys.exit(1)

    elif cmd == "decrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        priv_key_path = sys.argv[4]

        try:
            decrypt_file(input_path, output_path, priv_key_path)
            logger.info("Decryption complete. Output written to %s", output_path)
        except Exception as exc:
            logger.exception("Decryption failed.")
            print(f"Decryption failed: {exc}")
            sys.exit(1)

    elif cmd == "genkey" and len(sys.argv) in (4, 5):
        private_key_path = sys.argv[2]
        public_key_path = sys.argv[3]
        if len(sys.argv) == 5:
            try:
                key_size = int(sys.argv[4])
            except ValueError:
                print("Invalid key size specified. Must be an integer.")
                sys.exit(1)
        else:
            key_size = 2048  # Default

        try:
            rsa_mgr = RSAManager()
            rsa_mgr.generate_key_pair(key_size=key_size)
            rsa_mgr.save_private_key(private_key_path)
            rsa_mgr.save_public_key(public_key_path)
            logger.info(
                "Key generation complete. Private key: %s, Public key: %s",
                private_key_path,
                public_key_path,
            )
        except Exception as exc:
            logger.exception("Key generation failed.")
            print(f"Key generation failed: {exc}")
            sys.exit(1)

    else:
        print("Usage:")
        print("  python main.py encrypt <input> <output> <public_key.pem>")
        print("  python main.py decrypt <input> <output> <private_key.pem>")
        print("  python main.py genkey <private_key.pem> <public_key.pem> [<key_size>]")
        sys.exit(1)


if __name__ == "__main__":
    main()
