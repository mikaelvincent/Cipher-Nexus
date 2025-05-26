"""GUI for the Cipher Nexus project using Tkinter.

This module defines a simple interface for selecting input, output, and key files, generating RSA keys, and performing encryption or decryption. The RSA key file (PEM) can be either a public key (for encryption) or a private key (for decryption).
"""

import logging
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional

from src.utils.classical_pipeline import (
    encrypt_classical,
    decrypt_classical,
    write_data,
)
from src.utils.hybrid_crypto import envelope_encrypt_params, envelope_decrypt_params
from src.crypto.hashing import sha256_hash_data
from src.crypto.rsa_manager import RSAManager
from src.utils.file_io import read_file_in_chunks

logger = logging.getLogger(__name__)


def start_gui() -> None:
    """Launch the Tkinter-based GUI for the Cipher Nexus project."""
    root = tk.Tk()
    root.title("Cipher Nexus")
    root.resizable(False, False)
    app = CipherNexusGUI(master=root)
    app.mainloop()


class CipherNexusGUI(tk.Frame):
    """A Tkinter-based GUI for the Cipher Nexus encryption/decryption pipeline."""

    def __init__(self, master: Optional[tk.Tk] = None) -> None:
        """Initialize the CipherNexusGUI and create UI elements.

        Args:
            master: An optional Tkinter root or parent widget.
        """
        super().__init__(master)
        self.pack(padx=10, pady=(10, 5))
        self._create_widgets()
        # Hide status label until an operation completes
        self.status_label.grid_remove()

    def _create_widgets(self) -> None:
        """Create the layout of labels, buttons, and entry fields for file selection."""

        # ------------------------------
        # Row 0: Input file
        # ------------------------------
        label_input = tk.Label(self, text="File to Process:")
        label_input.grid(row=0, column=0, sticky="e")

        self.entry_input = tk.Entry(self, width=50)
        self.entry_input.grid(row=0, column=1, padx=5, pady=5)

        button_browse_input = tk.Button(
            self, text="Browse...", command=self._browse_input
        )
        button_browse_input.grid(row=0, column=2, padx=5, pady=5)

        # ------------------------------
        # Row 1: Output file
        # ------------------------------
        label_output = tk.Label(self, text="Output File:")
        label_output.grid(row=1, column=0, sticky="e")

        self.entry_output = tk.Entry(self, width=50)
        self.entry_output.grid(row=1, column=1, padx=5, pady=5)

        button_browse_output = tk.Button(
            self, text="Browse...", command=self._browse_output
        )
        button_browse_output.grid(row=1, column=2, padx=5, pady=5)

        # ------------------------------
        # Row 2: Key file
        # ------------------------------
        label_key = tk.Label(self, text="Key File (PEM):")
        label_key.grid(row=2, column=0, sticky="e")

        self.entry_key = tk.Entry(self, width=50)
        self.entry_key.grid(row=2, column=1, padx=5, pady=5)

        button_browse_key = tk.Button(self, text="Browse...", command=self._browse_key)
        button_browse_key.grid(row=2, column=2, padx=5, pady=5)

        # ------------------------------
        # Row 3: Subframe for action buttons
        # ------------------------------
        self.button_frame = tk.Frame(self)
        self.button_frame.grid(row=3, column=0, columnspan=3, sticky="ew", padx=5)

        # Configure columns for equal horizontal expansion
        self.button_frame.columnconfigure(0, weight=1)
        self.button_frame.columnconfigure(1, weight=1)
        self.button_frame.columnconfigure(2, weight=1)

        button_encrypt = tk.Button(
            self.button_frame, text="Encrypt", command=self._encrypt_file
        )
        button_encrypt.grid(row=0, column=0, sticky="ew", padx=(0, 5), pady=5)

        button_decrypt = tk.Button(
            self.button_frame, text="Decrypt", command=self._decrypt_file
        )
        button_decrypt.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        button_genkey = tk.Button(
            self.button_frame, text="Generate Key", command=self._generate_key
        )
        button_genkey.grid(row=0, column=2, sticky="ew", padx=(5, 0), pady=5)

        # ------------------------------
        # Row 4: Status label (initially hidden)
        # ------------------------------
        self.status_label = tk.Label(self, text="", fg="blue")
        self.status_label.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

    def _browse_input(self) -> None:
        """Open a file dialog for selecting an input file."""
        path = filedialog.askopenfilename()
        if path:
            self.entry_input.delete(0, tk.END)
            self.entry_input.insert(0, path)

    def _browse_output(self) -> None:
        """Open a file dialog for selecting an output file."""
        path = filedialog.asksaveasfilename()
        if path:
            self.entry_output.delete(0, tk.END)
            self.entry_output.insert(0, path)

    def _browse_key(self) -> None:
        """Open a file dialog for selecting a PEM key file."""
        path = filedialog.askopenfilename()
        if path:
            self.entry_key.delete(0, tk.END)
            self.entry_key.insert(0, path)

    def _encrypt_file(self) -> None:
        """Perform encryption using the classical pipeline plus RSA envelope."""
        input_path = self.entry_input.get()
        output_path = self.entry_output.get()
        key_path = self.entry_key.get()

        if not input_path or not output_path or not key_path:
            messagebox.showerror("Error", "Please select input, output, and key files.")
            return

        try:
            # Run classical encryption
            ciphertext, cipher_params = encrypt_classical(input_path)

            # Compute file hash for integrity
            plaintext_hash = sha256_hash_data(_read_entire_file(input_path))
            cipher_params["sha256"] = plaintext_hash

            # Envelope-encrypt the cipher params with RSA + AES-GCM
            ephemeral_data_enc, param_ciphertext, param_tag = envelope_encrypt_params(
                cipher_params, key_path
            )

            # Build final output structure:
            # [4-byte length of ephemeral_data_enc][ephemeral_data_enc]
            # [4-byte length of param_ciphertext][param_ciphertext]
            # [ciphertext]
            from src.utils.constants import LENGTH_HEADER_SIZE

            header_1 = len(ephemeral_data_enc).to_bytes(LENGTH_HEADER_SIZE, "big")
            header_2 = len(param_ciphertext).to_bytes(LENGTH_HEADER_SIZE, "big")

            final_output = (
                header_1 + ephemeral_data_enc + header_2 + param_ciphertext + ciphertext
            )

            # Write output
            write_data(output_path, final_output)

            self.status_label.config(text="Encryption complete.")
            self.status_label.grid()
        except Exception as exc:
            logger.exception("Encryption failed.")
            messagebox.showerror("Error", f"Encryption failed: {exc}")

    def _decrypt_file(self) -> None:
        """Perform decryption using the classical pipeline plus RSA envelope."""
        input_path = self.entry_input.get()
        output_path = self.entry_output.get()
        key_path = self.entry_key.get()

        if not input_path or not output_path or not key_path:
            messagebox.showerror("Error", "Please select input, output, and key files.")
            return

        try:
            file_data = b"".join(read_file_in_chunks(input_path))

            from src.utils.constants import LENGTH_HEADER_SIZE

            # 1) Extract ephemeral_data_enc
            cursor = 0
            ephemeral_len = int.from_bytes(
                file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big"
            )
            cursor += LENGTH_HEADER_SIZE
            ephemeral_data_enc = file_data[cursor : cursor + ephemeral_len]
            cursor += ephemeral_len

            # 2) Extract param_ciphertext
            param_len = int.from_bytes(
                file_data[cursor : cursor + LENGTH_HEADER_SIZE], "big"
            )
            cursor += LENGTH_HEADER_SIZE
            param_ciphertext = file_data[cursor : cursor + param_len]
            cursor += param_len

            # 3) Remaining bytes = ciphertext
            ciphertext = file_data[cursor:]

            # Decrypt cipher params
            from src.crypto.rsa_manager import RSAManager

            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(key_path)
            ephemeral_data = rsa_mgr.decrypt(ephemeral_data_enc)

            from src.utils.constants import AES_KEY_SIZE, GCM_IV_SIZE

            param_tag = ephemeral_data[AES_KEY_SIZE + GCM_IV_SIZE :]

            from src.utils.hybrid_crypto import envelope_decrypt_params

            cipher_params = envelope_decrypt_params(
                ephemeral_data_enc, param_ciphertext, param_tag, key_path
            )

            from src.utils.classical_pipeline import decrypt_classical

            plaintext = decrypt_classical(ciphertext, cipher_params)

            # Verify integrity
            old_hash = cipher_params["sha256"]
            new_hash = sha256_hash_data(plaintext)

            if new_hash != old_hash:
                raise ValueError("SHA-256 mismatch: possible corruption or tampering.")

            from src.utils.classical_pipeline import write_data

            write_data(output_path, plaintext)

            self.status_label.config(text="Decryption complete.")
            self.status_label.grid()
        except Exception as exc:
            logger.exception("Decryption failed.")
            messagebox.showerror("Error", f"Decryption failed: {exc}")

    def _generate_key(self) -> None:
        """Generate a new RSA key pair and save to user-chosen locations."""
        # Ask user for private key path
        priv_path = filedialog.asksaveasfilename(
            title="Save Private Key As", defaultextension=".pem"
        )
        if not priv_path:
            return

        # Ask user for public key path
        pub_path = filedialog.asksaveasfilename(
            title="Save Public Key As", defaultextension=".pem"
        )
        if not pub_path:
            return

        # Ask for key size (simple prompt)
        # If you want a more advanced dialog, create a top-level window. For brevity, use an input dialog.
        # Here, we’ll use a default or a simple prompt. If user cancels, use default 2048.

        key_size = 2048
        answer = messagebox.askquestion(
            "Key Size",
            "By default, a 2048-bit key will be created.\n"
            "Click 'Yes' to proceed with 2048 bits, or 'No' to enter a custom size.",
        )
        if answer == "no":
            # Simple approach: ask the user for a numeric input in a new dialog
            size_str = tk.simpledialog.askstring(
                "Custom Key Size", "Enter key size in bits (e.g., 2048, 3072, 4096):"
            )
            if size_str is None:
                # User canceled, revert to default
                key_size = 2048
            else:
                try:
                    key_size = int(size_str)
                except ValueError:
                    messagebox.showerror(
                        "Invalid Input", "Key size must be an integer. Using 2048 bits."
                    )
                    key_size = 2048

        # Generate and save
        try:
            rsa_mgr = RSAManager()
            rsa_mgr.generate_key_pair(key_size=key_size)
            rsa_mgr.save_private_key(priv_path)
            rsa_mgr.save_public_key(pub_path)

            self.status_label.config(
                text=(
                    f"Key generation complete.\n"
                    f"Private key: {priv_path}\n"
                    f"Public key: {pub_path}"
                )
            )
            self.status_label.grid()
        except Exception as exc:
            logger.exception("Key generation failed.")
            messagebox.showerror("Error", f"Key generation failed: {exc}")


def _read_entire_file(filepath: str) -> bytes:
    """Helper to read an entire file into memory."""
    data = bytearray()
    for chunk in read_file_in_chunks(filepath):
        data.extend(chunk)
    return bytes(data)
