"""Main entry point for the Cipher Nexus application.

This module provides a command-line interface for encrypting or decrypting files and can launch the Tkinter GUI if called without arguments.
"""

import sys

from src.gui import start_gui
from src.utils.pipeline import encrypt_file, decrypt_file


def main() -> None:
    """Entry point for Cipher Nexus.

    Usage:
        If called with no arguments, launches the GUI.
        Otherwise, call:
            python main.py encrypt <input> <output> <public_key.pem>
            python main.py decrypt <input> <output> <private_key.pem>
    """
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
            print(f"Encryption complete. Output written to {output_path}")
        except Exception as exc:
            print(f"Encryption failed: {exc}")
    elif cmd == "decrypt" and len(sys.argv) == 5:
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        priv_key_path = sys.argv[4]
        try:
            decrypt_file(input_path, output_path, priv_key_path)
            print(f"Decryption complete. Output written to {output_path}")
        except Exception as exc:
            print(f"Decryption failed: {exc}")
    else:
        print("Usage:")
        print("  python main.py encrypt <input> <output> <public_key.pem>")
        print("  python main.py decrypt <input> <output> <private_key.pem>")


if __name__ == "__main__":
    main()
