import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import ECC, RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
import hashlib
import os
import json

class GroupSignature:
    def __init__(self):
        self.gpk, self.gmk, self.grk, self.gsk = self.keygen(1, 3)

    def keygen(self, one, n):
        gpk = ECC.generate(curve='P-256').public_key()
        gmk = ECC.generate(curve='P-256')
        grk = RSA.generate(2048)
        gsk = [ECC.generate(curve='P-256') for _ in range(n)]
        return gpk, gmk, grk, gsk

    def sign(self, gpk, gsk_i, M):
        h = SHA256.new(M)
        signer = DSS.new(gsk_i, 'fips-186-3')
        signature = signer.sign(h)
        return signature

    def verify(self, gpk, M, sig):
        h = SHA256.new(M)
        verifier = DSS.new(gpk, 'fips-186-3')
        try:
            verifier.verify(h, sig)
            return True
        except ValueError:
            return False

    def tracing(self, sig, M, grk):
        h = SHA256.new(M)
        for i, sk in enumerate(self.gsk):
            signer = DSS.new(sk, 'fips-186-3')
            try:
                signer.verify(h, sig)
                return i, "Argument"  # In practice, this should be a valid argument
            except ValueError:
                continue
        return None, None

    def vertracing(self, sig, M, gpk, i, arg):
        return True  # Assuming tracing is correct for the demo


class DataProducer:
    def __init__(self, gs):
        self.gs = gs
        self.dp_id = "DP01"
        self.do_private_key = RSA.generate(2048)
        self.do_public_key = self.do_private_key.publickey()
        self.rm_private_key = RSA.generate(2048)
        self.rm_public_key = self.rm_private_key.publickey()

    def make_proc(self, raw_data):
        return raw_data.encode('utf-8')

    def create_identifier(self, md):
        return hashlib.sha256(md).hexdigest()

    def generate_random_key(self):
        return get_random_bytes(32)  # 256-bit key

    def encrypt_md(self, md, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(md)
        return cipher.nonce, ciphertext, tag

    def encrypt_with_public_key(self, data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    def encrypt_dp_info(self, dp_info, id_md, public_key):
        combined_data = dp_info + id_md.encode('utf-8')
        encrypted_data = b""
        max_chunk_size = 190  # Adjusted for RSA encryption limit

        for i in range(0, len(combined_data), max_chunk_size):
            chunk = combined_data[i:i + max_chunk_size]
            encrypted_data += self.encrypt_with_public_key(chunk, public_key)

        return encrypted_data

    def sign_data(self, data, private_key):
        h = SHA256.new(data)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        return signature

    def data_producing_scheme(self, raw_data):
        # Produce MD from RD
        md = self.make_proc(raw_data)

        # Create an identifier for MD
        id_md = self.create_identifier(md)

        # Generate a random key K
        k = self.generate_random_key()

        # Encrypt MD using K
        nonce, encrypted_md, tag = self.encrypt_md(md, k)

        # Encrypt DP’s IdDP and K using PKDO and PCS
        dp_info = self.encrypt_with_public_key(self.dp_id.encode('utf-8') + k, self.do_public_key)

        # Encrypt DPInfo and IdMD using PKRM and PCS
        encrypted_id_md = self.encrypt_dp_info(dp_info, id_md, self.rm_public_key)

        # Generate a signature on EMD
        signature = self.gs.sign(self.gs.gpk, self.gs.gsk[0], encrypted_md)  # Using first group member key for demo

        # Certificate includes (SD, EId)
        cert = (signature, encrypted_id_md)

        # Output EMD, CERT, and DPInfo
        return nonce, encrypted_md, tag, cert, dp_info

    def verify_data(self, nonce, encrypted_md, tag, cert, dp_info):
        # Decrypt DPInfo using DO's private key
        cipher_rsa = PKCS1_OAEP.new(self.do_private_key)
        decrypted_dp_info = cipher_rsa.decrypt(dp_info)

        dp_id, k = decrypted_dp_info[:len(decrypted_dp_info) - 32], decrypted_dp_info[-32:]

        # Decrypt EMD using K
        cipher_aes = AES.new(k, AES.MODE_GCM, nonce)
        md = cipher_aes.decrypt_and_verify(encrypted_md, tag)

        # Verify the integrity of MD
        id_md = self.create_identifier(md)

        # Decrypt CERT.EId using RM's private key
        decrypted_cert_eid = b""
        max_chunk_size = 256  # Adjusted for RSA decryption limit
        for i in range(0, len(cert[1]), max_chunk_size):
            chunk = cert[1][i:i + max_chunk_size]
            cipher_rsa = PKCS1_OAEP.new(self.rm_private_key)
            decrypted_cert_eid += cipher_rsa.decrypt(chunk)

        dp_info_in_cert, id_md_in_cert = decrypted_cert_eid[:len(decrypted_cert_eid) - 64], decrypted_cert_eid[-64:].decode('utf-8')

        # Verify the DPInfo and IdMD
        if dp_info_in_cert != dp_info or id_md_in_cert != id_md:
            return False

        # Verify the signature
        is_valid = self.gs.verify(self.gs.gpk, encrypted_md, cert[0])
        return is_valid


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Data Producing Scheme")
        self.geometry("600x400")
        self.gs = GroupSignature()
        self.dp = DataProducer(self.gs)

        self.label = tk.Label(self, text="Enter Raw Data:")
        self.label.pack(pady=10)

        self.entry = tk.Entry(self, width=50)
        self.entry.pack(pady=10)

        self.import_button = tk.Button(self, text="Import Raw Data", command=self.import_raw_data)
        self.import_button.pack(pady=10)

        self.produce_button = tk.Button(self, text="Produce Data", command=self.produce_data)
        self.produce_button.pack(pady=10)

        self.export_md_button = tk.Button(self, text="Export MD", command=self.export_md)
        self.export_md_button.pack(pady=10)

        self.export_cert_button = tk.Button(self, text="Export CERT", command=self.export_cert)
        self.export_cert_button.pack(pady=10)

        self.export_dpinfo_button = tk.Button(self, text="Export DPInfo", command=self.export_dpinfo)
        self.export_dpinfo_button.pack(pady=10)

        self.import_md_button = tk.Button(self, text="Import MD", command=self.import_md)
        self.import_md_button.pack(pady=10)

        self.import_cert_button = tk.Button(self, text="Import CERT", command=self.import_cert)
        self.import_cert_button.pack(pady=10)

        self.import_dpinfo_button = tk.Button(self, text="Import DPInfo", command=self.import_dpinfo)
        self.import_dpinfo_button.pack(pady=10)

        self.verify_button = tk.Button(self, text="Verify Data", command=self.verify_data)
        self.verify_button.pack(pady=10)

        self.status_label = tk.Label(self, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def import_raw_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                raw_data = file.read()
                self.entry.delete(0, tk.END)
                self.entry.insert(0, raw_data)
                self.update_status("Raw data imported successfully.")
                messagebox.showinfo("Success", "Raw data imported successfully.")

    def produce_data(self):
        raw_data = self.entry.get()
        self.nonce, self.encrypted_md, self.tag, self.cert, self.dp_info = self.dp.data_producing_scheme(raw_data)
        self.update_status("Data produced and encrypted successfully.")
        messagebox.showinfo("Success", "Data produced and encrypted successfully.")

    def export_md(self):
        md_data = {
            'nonce': self.nonce.hex(),
            'encrypted_md': self.encrypted_md.hex(),
            'tag': self.tag.hex()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(json.dumps(md_data, indent=4))
                self.update_status("MD data exported successfully.")
                messagebox.showinfo("Success", "MD data exported successfully.")

    def export_cert(self):
        cert_data = {
            'signature': self.cert[0].hex(),
            'encrypted_id_md': self.cert[1].hex()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(json.dumps(cert_data, indent=4))
                self.update_status("CERT data exported successfully.")
                messagebox.showinfo("Success", "CERT data exported successfully.")

    def export_dpinfo(self):
        dpinfo_data = {
            'dp_info': self.dp_info.hex()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(json.dumps(dpinfo_data, indent=4))
                self.update_status("DPInfo data exported successfully.")
                messagebox.showinfo("Success", "DPInfo data exported successfully.")

    def import_md(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                md_data = json.load(file)
                self.nonce = bytes.fromhex(md_data['nonce'])
                self.encrypted_md = bytes.fromhex(md_data['encrypted_md'])
                self.tag = bytes.fromhex(md_data['tag'])
                self.update_status("MD data imported successfully.")
                messagebox.showinfo("Success", "MD data imported successfully.")

    def import_cert(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                cert_data = json.load(file)
                self.cert = (
                    bytes.fromhex(cert_data['signature']),
                    bytes.fromhex(cert_data['encrypted_id_md'])
                )
                self.update_status("CERT data imported successfully.")
                messagebox.showinfo("Success", "CERT data imported successfully.")

    def import_dpinfo(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                dpinfo_data = json.load(file)
                self.dp_info = bytes.fromhex(dpinfo_data['dp_info'])
                self.update_status("DPInfo data imported successfully.")
                messagebox.showinfo("Success", "DPInfo data imported successfully.")

    def verify_data(self):
        is_valid = self.dp.verify_data(self.nonce, self.encrypted_md, self.tag, self.cert, self.dp_info)
        if is_valid:
            self.update_status("Data verified successfully.")
            messagebox.showinfo("Success", "Data verified successfully.")
        else:
            self.update_status("Data verification failed.")
            messagebox.showerror("Failure", "Data verification failed.")


if __name__ == "__main__":
    app = App()
    app.mainloop()
