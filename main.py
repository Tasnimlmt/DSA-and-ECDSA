import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import random
import time
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import sympy
import base64

class DSA_ECDSA_Suite:
    def __init__(self, root):
        self.root = root
        self.root.title("🏛️ DSA & ECDSA SIGNATURE SUITE | FIPS 186-5 🏛️")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0a0a2a')  # Government/standard theme
        
        # Government/standards colors
        self.bg_color = "#0a0a2a"
        self.nist_blue = "#003366"
        self.fips_red = "#cc0000"
        self.standard_white = "#ffffff"
        self.crypto_green = "#00cc88"
        
        # DSA parameters
        self.dsa_private_key = None
        self.dsa_public_key = None
        self.dsa_signature = None
        
        # ECDSA parameters
        self.ecdsa_private_key = None
        self.ecdsa_public_key = None
        self.ecdsa_signature = None
        
        self.current_message = None
        
        self.setup_ui()
        
    def setup_ui(self):
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        self.create_header(main_container)
        
        # Main paned window
        paned = tk.PanedWindow(main_container, bg=self.bg_color, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame - DSA
        left_frame = tk.Frame(paned, bg=self.bg_color)
        paned.add(left_frame, width=750)
        self.setup_dsa(left_frame)
        
        # Right frame - ECDSA
        right_frame = tk.Frame(paned, bg=self.bg_color)
        paned.add(right_frame, width=750)
        self.setup_ecdsa(right_frame)
        
        self.create_status_bar(main_container)
    
    def create_header(self, parent):
        header = tk.Frame(parent, bg=self.bg_color, height=80)
        header.pack(fill=tk.X, pady=(10, 0))
        
        header_text = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗ █████╗     ███████╗ ██████╗ ██████╗ ███████╗ █████╗                     ║
║  ██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝ ██╔══██╗██╔════╝██╔══██╗                    ║
║  ██║  ██║█████╗  ███████║    ███████╗██║  ███╗██████╔╝█████╗  ███████║                    ║
║  ██║  ██║██╔══╝  ██╔══██║    ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║                    ║
║  ██████╔╝███████╗██║  ██║    ███████║╚██████╔╝██║  ██║███████╗██║  ██║                    ║
║  ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                    ║
║                    DIGITAL SIGNATURE ALGORITHM (DSA) & ECDSA                            ║
║                              FIPS 186-5 | NIST APPROVED                                ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""
        lbl = tk.Label(header, text=header_text, font=('Courier', 7), fg=self.standard_white,
                      bg=self.bg_color, justify=tk.LEFT)
        lbl.pack()
    
    def create_status_bar(self, parent):
        status_frame = tk.Frame(parent, bg='#0a0a3a', height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_frame, text="🏛️ DSA/ECDSA READY | FIPS COMPLIANT",
                                     font=('Courier', 9), fg=self.standard_white, bg='#0a0a3a')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        for _ in range(3):
            sym = tk.Label(status_frame, text="⚙️", font=('Arial', 10), fg=self.nist_blue, bg='#0a0a3a')
            sym.pack(side=tk.RIGHT, padx=5)
    
    # ==================== DSA SECTION ====================
    def setup_dsa(self, parent):
        # Title
        title = tk.Label(parent, text="DSA (Digital Signature Algorithm)", 
                        font=('Courier', 12, 'bold'), fg=self.nist_blue, bg=self.bg_color)
        title.pack(pady=5)
        
        sub = tk.Label(parent, text="Based on Discrete Logarithm Problem | FIPS 186-5", 
                      font=('Courier', 8), fg=self.standard_white, bg=self.bg_color)
        sub.pack()
        
        # Key generation
        key_frame = tk.LabelFrame(parent, text="🔑 KEY GENERATION", 
                                  font=('Courier', 9, 'bold'),
                                  fg=self.nist_blue, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        key_frame.pack(fill=tk.X, pady=10, padx=10)
        
        key_control = tk.Frame(key_frame, bg=self.bg_color)
        key_control.pack(pady=10)
        
        tk.Label(key_control, text="Key Size:", font=('Courier', 9),
                fg=self.standard_white, bg=self.bg_color).pack(side=tk.LEFT, padx=5)
        
        self.dsa_size = ttk.Combobox(key_control, values=["1024", "2048", "3072"], width=8)
        self.dsa_size.set("2048")
        self.dsa_size.pack(side=tk.LEFT, padx=5)
        
        tk.Button(key_control, text="GENERATE DSA KEYS", command=self.generate_dsa_keys,
                 font=('Courier', 9, 'bold'), bg=self.nist_blue, fg='white', padx=10).pack(side=tk.LEFT, padx=10)
        
        # Key display
        dsa_pub_frame = tk.LabelFrame(parent, text="🔓 DSA PUBLIC KEY", 
                                      font=('Courier', 8, 'bold'),
                                      fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        dsa_pub_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.dsa_pub_text = tk.Text(dsa_pub_frame, height=6, font=('Courier', 7),
                                    bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.dsa_pub_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        dsa_priv_frame = tk.LabelFrame(parent, text="🔒 DSA PRIVATE KEY", 
                                       font=('Courier', 8, 'bold'),
                                       fg=self.fips_red, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        dsa_priv_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.dsa_priv_text = tk.Text(dsa_priv_frame, height=4, font=('Courier', 7),
                                     bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.dsa_priv_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input
        msg_frame = tk.LabelFrame(parent, text="📝 MESSAGE", 
                                  font=('Courier', 9, 'bold'),
                                  fg=self.nist_blue, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        msg_frame.pack(fill=tk.X, pady=5, padx=10)
        
        self.dsa_message = tk.Text(msg_frame, height=3, font=('Courier', 9),
                                   bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.dsa_message.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.dsa_message.insert('1.0', "Message to sign with DSA")
        
        # Buttons
        btn_frame = tk.Frame(parent, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=5, padx=10)
        
        tk.Button(btn_frame, text="🔐 DSA SIGN", command=self.dsa_sign,
                 font=('Courier', 9, 'bold'), bg=self.nist_blue, fg='white', padx=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="✅ DSA VERIFY", command=self.dsa_verify,
                 font=('Courier', 9, 'bold'), bg=self.crypto_green, fg='black', padx=10).pack(side=tk.LEFT, padx=5)
        
        # Signature display
        sig_frame = tk.LabelFrame(parent, text="🔏 DSA SIGNATURE (r, s)", 
                                  font=('Courier', 8, 'bold'),
                                  fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        sig_frame.pack(fill=tk.X, pady=5, padx=10)
        
        self.dsa_sig_text = tk.Text(sig_frame, height=3, font=('Courier', 7),
                                    bg='#0a0a3a', fg='#ffcc00', wrap=tk.WORD)
        self.dsa_sig_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Result
        result_frame = tk.LabelFrame(parent, text="⚖️ VERIFICATION", 
                                     font=('Courier', 8, 'bold'),
                                     fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.dsa_result = tk.Text(result_frame, height=4, font=('Courier', 8),
                                  bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.dsa_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def generate_dsa_keys(self):
        try:
            size = int(self.dsa_size.get())
            
            self.dsa_result.delete('1.0', tk.END)
            self.dsa_result.insert('1.0', f"Generating DSA-{size} keys...\n")
            self.root.update()
            
            start_time = time.time()
            
            # Generate DSA parameters and keys
            self.dsa_private_key = dsa.generate_private_key(key_size=size, backend=default_backend())
            self.dsa_public_key = self.dsa_private_key.public_key()
            
            gen_time = time.time() - start_time
            
            # Serialize keys for display
            pem_public = self.dsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            pem_private = self.dsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self.dsa_pub_text.delete('1.0', tk.END)
            self.dsa_pub_text.insert('1.0', pem_public.decode())
            
            self.dsa_priv_text.delete('1.0', tk.END)
            self.dsa_priv_text.insert('1.0', pem_private.decode())
            
            self.dsa_result.insert(tk.END, f"✅ DSA keys generated in {gen_time:.2f}s\n")
            self.dsa_result.insert(tk.END, f"Key size: {size} bits\n")
            
            self.status_label.config(text=f"🔑 DSA-{size} keys generated | FIPS compliant")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def dsa_sign(self):
        if self.dsa_private_key is None:
            messagebox.showerror("Error", "Generate DSA keys first!")
            return
        
        try:
            message = self.dsa_message.get('1.0', tk.END).strip()
            self.current_message = message
            
            start_time = time.time()
            signature = self.dsa_private_key.sign(
                message.encode(),
                hashes.SHA256()
            )
            sig_time = time.time() - start_time
            
            self.dsa_signature = signature
            
            # DSA signature is ASN.1 encoded, show base64
            sig_b64 = base64.b64encode(signature).decode()
            
            self.dsa_sig_text.delete('1.0', tk.END)
            self.dsa_sig_text.insert('1.0', f"Signature (base64):\n{sig_b64}")
            
            self.dsa_result.delete('1.0', tk.END)
            self.dsa_result.insert('1.0', f"✅ DSA signature created in {sig_time*1000:.2f} ms\n")
            self.dsa_result.insert(tk.END, f"Signature size: {len(signature)} bytes\n")
            
            self.status_label.config(text="🔐 DSA signature created | Ready for verification")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def dsa_verify(self):
        if self.dsa_public_key is None:
            messagebox.showerror("Error", "Generate DSA keys first!")
            return
        
        if self.dsa_signature is None:
            messagebox.showerror("Error", "Sign a message first!")
            return
        
        try:
            message = self.dsa_message.get('1.0', tk.END).strip()
            
            start_time = time.time()
            try:
                self.dsa_public_key.verify(
                    self.dsa_signature,
                    message.encode(),
                    hashes.SHA256()
                )
                valid = True
            except InvalidSignature:
                valid = False
            verify_time = time.time() - start_time
            
            self.dsa_result.insert(tk.END, "\n" + "=" * 40 + "\n")
            self.dsa_result.insert(tk.END, "VERIFICATION RESULT\n")
            self.dsa_result.insert(tk.END, "-" * 40 + "\n")
            
            if valid:
                self.dsa_result.insert(tk.END, "✅ SIGNATURE VALID!\n\n")
                self.dsa_result.insert(tk.END, "DSA guarantees:\n")
                self.dsa_result.insert(tk.END, "  • Authenticity - Signed by private key holder\n")
                self.dsa_result.insert(tk.END, "  • Integrity - Message unchanged\n")
                self.dsa_result.insert(tk.END, "  • Non-repudiation - Signer cannot deny\n")
                self.status_label.config(text="✅ DSA signature valid | Authenticity confirmed")
            else:
                self.dsa_result.insert(tk.END, "❌ SIGNATURE INVALID!\n")
                self.status_label.config(text="❌ DSA signature invalid | Message may be tampered")
            
            self.dsa_result.insert(tk.END, f"\nVerification time: {verify_time*1000:.2f} ms")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # ==================== ECDSA SECTION ====================
    def setup_ecdsa(self, parent):
        # Title
        title = tk.Label(parent, text="ECDSA (Elliptic Curve DSA)", 
                        font=('Courier', 12, 'bold'), fg=self.nist_blue, bg=self.bg_color)
        title.pack(pady=5)
        
        sub = tk.Label(parent, text="Based on Elliptic Curve DLP | NIST P-256", 
                      font=('Courier', 8), fg=self.standard_white, bg=self.bg_color)
        sub.pack()
        
        # Key generation
        key_frame = tk.LabelFrame(parent, text="🔑 KEY GENERATION", 
                                  font=('Courier', 9, 'bold'),
                                  fg=self.nist_blue, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        key_frame.pack(fill=tk.X, pady=10, padx=10)
        
        key_control = tk.Frame(key_frame, bg=self.bg_color)
        key_control.pack(pady=10)
        
        tk.Label(key_control, text="Curve:", font=('Courier', 9),
                fg=self.standard_white, bg=self.bg_color).pack(side=tk.LEFT, padx=5)
        
        self.ecdsa_curve = ttk.Combobox(key_control, values=["P-256 (secp256r1)", "P-384", "P-521"], width=18)
        self.ecdsa_curve.set("P-256 (secp256r1)")
        self.ecdsa_curve.pack(side=tk.LEFT, padx=5)
        
        tk.Button(key_control, text="GENERATE ECDSA KEYS", command=self.generate_ecdsa_keys,
                 font=('Courier', 9, 'bold'), bg=self.nist_blue, fg='white', padx=10).pack(side=tk.LEFT, padx=10)
        
        # Key display
        ecdsa_pub_frame = tk.LabelFrame(parent, text="🔓 ECDSA PUBLIC KEY", 
                                        font=('Courier', 8, 'bold'),
                                        fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        ecdsa_pub_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.ecdsa_pub_text = tk.Text(ecdsa_pub_frame, height=6, font=('Courier', 7),
                                      bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.ecdsa_pub_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ecdsa_priv_frame = tk.LabelFrame(parent, text="🔒 ECDSA PRIVATE KEY", 
                                         font=('Courier', 8, 'bold'),
                                         fg=self.fips_red, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        ecdsa_priv_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.ecdsa_priv_text = tk.Text(ecdsa_priv_frame, height=4, font=('Courier', 7),
                                       bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.ecdsa_priv_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input
        msg_frame = tk.LabelFrame(parent, text="📝 MESSAGE", 
                                  font=('Courier', 9, 'bold'),
                                  fg=self.nist_blue, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        msg_frame.pack(fill=tk.X, pady=5, padx=10)
        
        self.ecdsa_message = tk.Text(msg_frame, height=3, font=('Courier', 9),
                                     bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.ecdsa_message.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ecdsa_message.insert('1.0', "Message to sign with ECDSA")
        
        # Buttons
        btn_frame = tk.Frame(parent, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=5, padx=10)
        
        tk.Button(btn_frame, text="🔐 ECDSA SIGN", command=self.ecdsa_sign,
                 font=('Courier', 9, 'bold'), bg=self.nist_blue, fg='white', padx=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="✅ ECDSA VERIFY", command=self.ecdsa_verify,
                 font=('Courier', 9, 'bold'), bg=self.crypto_green, fg='black', padx=10).pack(side=tk.LEFT, padx=5)
        
        # Signature display
        sig_frame = tk.LabelFrame(parent, text="🔏 ECDSA SIGNATURE (DER)", 
                                  font=('Courier', 8, 'bold'),
                                  fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        sig_frame.pack(fill=tk.X, pady=5, padx=10)
        
        self.ecdsa_sig_text = tk.Text(sig_frame, height=3, font=('Courier', 7),
                                      bg='#0a0a3a', fg='#ffcc00', wrap=tk.WORD)
        self.ecdsa_sig_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Result
        result_frame = tk.LabelFrame(parent, text="⚖️ VERIFICATION", 
                                     font=('Courier', 8, 'bold'),
                                     fg=self.crypto_green, bg=self.bg_color, relief=tk.GROOVE, bd=2)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=10)
        
        self.ecdsa_result = tk.Text(result_frame, height=4, font=('Courier', 8),
                                    bg='#0a0a3a', fg='#00ff00', wrap=tk.WORD)
        self.ecdsa_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def generate_ecdsa_keys(self):
        try:
            curve_name = self.ecdsa_curve.get()
            if "P-256" in curve_name:
                curve = ec.SECP256R1()
                size = 256
            elif "P-384" in curve_name:
                curve = ec.SECP384R1()
                size = 384
            else:
                curve = ec.SECP521R1()
                size = 521
            
            self.ecdsa_result.delete('1.0', tk.END)
            self.ecdsa_result.insert('1.0', f"Generating ECDSA-{size} keys...\n")
            self.root.update()
            
            start_time = time.time()
            
            self.ecdsa_private_key = ec.generate_private_key(curve, default_backend())
            self.ecdsa_public_key = self.ecdsa_private_key.public_key()
            
            gen_time = time.time() - start_time
            
            pem_public = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            pem_private = self.ecdsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self.ecdsa_pub_text.delete('1.0', tk.END)
            self.ecdsa_pub_text.insert('1.0', pem_public.decode())
            
            self.ecdsa_priv_text.delete('1.0', tk.END)
            self.ecdsa_priv_text.insert('1.0', pem_private.decode())
            
            self.ecdsa_result.insert(tk.END, f"✅ ECDSA keys generated in {gen_time:.2f}s\n")
            self.ecdsa_result.insert(tk.END, f"Curve: {curve_name}\n")
            self.ecdsa_result.insert(tk.END, f"Security: {size//2} bits\n")
            
            self.status_label.config(text=f"🔑 ECDSA keys generated | {curve_name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def ecdsa_sign(self):
        if self.ecdsa_private_key is None:
            messagebox.showerror("Error", "Generate ECDSA keys first!")
            return
        
        try:
            message = self.ecdsa_message.get('1.0', tk.END).strip()
            
            start_time = time.time()
            signature = self.ecdsa_private_key.sign(
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            sig_time = time.time() - start_time
            
            self.ecdsa_signature = signature
            sig_b64 = base64.b64encode(signature).decode()
            
            self.ecdsa_sig_text.delete('1.0', tk.END)
            self.ecdsa_sig_text.insert('1.0', f"Signature (base64):\n{sig_b64}")
            
            self.ecdsa_result.delete('1.0', tk.END)
            self.ecdsa_result.insert('1.0', f"✅ ECDSA signature created in {sig_time*1000:.2f} ms\n")
            self.ecdsa_result.insert(tk.END, f"Signature size: {len(signature)} bytes\n")
            
            self.status_label.config(text="🔐 ECDSA signature created | Ready for verification")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def ecdsa_verify(self):
        if self.ecdsa_public_key is None:
            messagebox.showerror("Error", "Generate ECDSA keys first!")
            return
        
        if self.ecdsa_signature is None:
            messagebox.showerror("Error", "Sign a message first!")
            return
        
        try:
            message = self.ecdsa_message.get('1.0', tk.END).strip()
            
            start_time = time.time()
            try:
                self.ecdsa_public_key.verify(
                    self.ecdsa_signature,
                    message.encode(),
                    ec.ECDSA(hashes.SHA256())
                )
                valid = True
            except InvalidSignature:
                valid = False
            verify_time = time.time() - start_time
            
            self.ecdsa_result.insert(tk.END, "\n" + "=" * 40 + "\n")
            self.ecdsa_result.insert(tk.END, "VERIFICATION RESULT\n")
            self.ecdsa_result.insert(tk.END, "-" * 40 + "\n")
            
            if valid:
                self.ecdsa_result.insert(tk.END, "✅ SIGNATURE VALID!\n\n")
                self.ecdsa_result.insert(tk.END, "ECDSA guarantees:\n")
                self.ecdsa_result.insert(tk.END, "  • Authenticity - Signed by private key holder\n")
                self.ecdsa_result.insert(tk.END, "  • Integrity - Message unchanged\n")
                self.ecdsa_result.insert(tk.END, "  • Non-repudiation - Signer cannot deny\n")
                self.status_label.config(text="✅ ECDSA signature valid | Authenticity confirmed")
            else:
                self.ecdsa_result.insert(tk.END, "❌ SIGNATURE INVALID!\n")
                self.status_label.config(text="❌ ECDSA signature invalid | Message may be tampered")
            
            self.ecdsa_result.insert(tk.END, f"\nVerification time: {verify_time*1000:.2f} ms")
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = DSA_ECDSA_Suite(root)
    root.mainloop()

if __name__ == "__main__":
    print("Starting DSA & ECDSA Signature Suite...")
    print("GUI window should open shortly.")
    main()