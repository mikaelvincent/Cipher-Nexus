"""GUI for the Cipher Nexus project using Tkinter.

This module defines a simple interface for selecting input, output, and key files and performing encryption or decryption. The RSA key file (PEM) can be either a public key (for encryption) or a private key (for decryption).
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import pickle
from typing import Optional

from src.ciphers.monoalphabetic import MonoalphabeticCipher
from src.ciphers.polyalphabetic import PolyalphabeticCipher
from src.ciphers.transposition import TranspositionCipher
from src.ciphers.vernam import VernamCipher
from src.ciphers.vigenere import VigenereCipher
from src.crypto.rsa_manager import RSAManager
from src.crypto.hashing import sha256_hash_data


def start_gui() -> None:
    """Launch the Tkinter-based GUI for the Cipher Nexus project."""
    root = tk.Tk()
    app = CipherNexusGUI(master=root)
    app.mainloop()


class CipherNexusGUI(tk.Frame):
    """A Tkinter-based GUI for the Cipher Nexus encryption/decryption pipeline.

    This GUI allows the user to select an input file, an output file, and an RSA key file in PEM format. Depending on whether the user clicks "Encrypt" or "Decrypt," the selected files are processed accordingly.
    """

    def __init__(self, master: Optional[tk.Tk] = None) -> None:
        """Initialize the CipherNexusGUI and create UI elements.

        Args:
            master: An optional Tkinter root or parent widget.
        """
        super().__init__(master)
        self.master = master
        self.master.title("Cipher Nexus")
        self.pack(padx=10, pady=10)
        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create the layout of labels, buttons, and entry fields for file selection."""
        # Row 0: Input file
        label_input = tk.Label(self, text="File to Process:")
        label_input.grid(row=0, column=0, sticky="e")

        self.entry_input = tk.Entry(self, width=50)
        self.entry_input.grid(row=0, column=1, padx=5, pady=5)

        button_browse_input = tk.Button(
            self, text="Browse...", command=self._browse_input
        )
        button_browse_input.grid(row=0, column=2, padx=5, pady=5)

        # Row 1: Output file
        label_output = tk.Label(self, text="Output File:")
        label_output.grid(row=1, column=0, sticky="e")

        self.entry_output = tk.Entry(self, width=50)
        self.entry_output.grid(row=1, column=1, padx=5, pady=5)

        button_browse_output = tk.Button(
            self, text="Browse...", command=self._browse_output
        )
        button_browse_output.grid(row=1, column=2, padx=5, pady=5)

        # Row 2: Key file
        label_key = tk.Label(self, text="Key File (PEM):")
        label_key.grid(row=2, column=0, sticky="e")

        self.entry_key = tk.Entry(self, width=50)
        self.entry_key.grid(row=2, column=1, padx=5, pady=5)

        button_browse_key = tk.Button(self, text="Browse...", command=self._browse_key)
        button_browse_key.grid(row=2, column=2, padx=5, pady=5)

        # Row 3: Encrypt/Decrypt buttons
        button_encrypt = tk.Button(self, text="Encrypt", command=self._encrypt_file)
        button_encrypt.grid(row=3, column=0, padx=5, pady=5)

        button_decrypt = tk.Button(self, text="Decrypt", command=self._decrypt_file)
        button_decrypt.grid(row=3, column=1, padx=5, pady=5)

        # Row 4: Status label
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
        """Perform encryption using layered classical ciphers and an RSA public key."""
        input_path = self.entry_input.get()
        output_path = self.entry_output.get()
        key_path = self.entry_key.get()

        if not input_path or not output_path or not key_path:
            messagebox.showerror("Error", "Please select input, output, and key files.")
            return

        try:
            # Read all data from the input file (for simplicity).
            with open(input_path, "rb") as f:
                plaintext = f.read()

            # Instantiate ciphers with random parameters.
            mono = MonoalphabeticCipher()
            poly = PolyalphabeticCipher()
            trans = TranspositionCipher()
            vig = VigenereCipher()
            ver = VernamCipher()

            # Layered encryption pipeline: trans -> mono -> poly -> vig -> ver
            data = trans.encrypt(plaintext)
            data = mono.encrypt(data)
            data = poly.encrypt(data)
            data = vig.encrypt(data)
            data = ver.encrypt(data)

            # Prepare parameters and original file hash for RSA encryption.
            cipher_params = {
                "mono_key": mono.key,
                "poly_key": poly.key,
                "trans_columns": trans.columns,
                "vig_passphrase": vig.passphrase,
                "ver_key": ver.key,
                "sha256": sha256_hash_data(plaintext),
            }
            param_bytes = pickle.dumps(cipher_params)

            # Load RSA public key and encrypt the parameter block.
            rsa_mgr = RSAManager()
            rsa_mgr.load_public_key(key_path)
            encrypted_params = rsa_mgr.encrypt(param_bytes)

            # Simple file format: [4-byte param length] [encrypted params] [ciphertext]
            with open(output_path, "wb") as out_f:
                out_f.write(len(encrypted_params).to_bytes(4, "big"))
                out_f.write(encrypted_params)
                out_f.write(data)

            self.status_label.config(text="Encryption complete.")
        except Exception as exc:
            messagebox.showerror("Error", f"Encryption failed: {exc}")

    def _decrypt_file(self) -> None:
        """Perform decryption using layered classical ciphers and an RSA private key."""
        input_path = self.entry_input.get()
        output_path = self.entry_output.get()
        key_path = self.entry_key.get()

        if not input_path or not output_path or not key_path:
            messagebox.showerror("Error", "Please select input, output, and key files.")
            return

        try:
            # Read the parameter block length and data.
            with open(input_path, "rb") as f:
                param_len_bytes = f.read(4)
                param_len = int.from_bytes(param_len_bytes, "big")
                encrypted_params = f.read(param_len)
                ciphertext = f.read()

            # Load RSA private key and decrypt the parameter block.
            rsa_mgr = RSAManager()
            rsa_mgr.load_private_key(key_path)

            param_bytes = rsa_mgr.decrypt(encrypted_params)
            cipher_params = pickle.loads(param_bytes)

            # Reconstruct ciphers with the stored parameters.
            mono = MonoalphabeticCipher(key=cipher_params["mono_key"])
            poly = PolyalphabeticCipher(key=cipher_params["poly_key"])
            trans = TranspositionCipher(columns=cipher_params["trans_columns"])
            vig = VigenereCipher(passphrase=cipher_params["vig_passphrase"])
            ver = VernamCipher(key=cipher_params["ver_key"])

            # Reverse the encryption pipeline: ver -> vig -> poly -> mono -> trans
            data = ver.decrypt(ciphertext)
            data = vig.decrypt(data)
            data = poly.decrypt(data)
            data = mono.decrypt(data)
            data = trans.decrypt(data)

            # Verify the integrity of the decrypted file.
            original_hash = cipher_params["sha256"]
            new_hash = sha256_hash_data(data)
            if new_hash != original_hash:
                messagebox.showwarning(
                    "Warning",
                    "Decrypted file hash does not match the original. Possible tampering.",
                )
            else:
                messagebox.showinfo("Info", "File integrity verified (SHA-256).")

            # Write the recovered plaintext.
            with open(output_path, "wb") as out_f:
                out_f.write(data)

            self.status_label.config(text="Decryption complete.")
        except Exception as exc:
            messagebox.showerror("Error", f"Decryption failed: {exc}")
