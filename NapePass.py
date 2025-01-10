import customtkinter as ctk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import os
import pyperclip
import webbrowser
import string
import random

# Belgeler/Napes Studios/NapePass dizin yolunu ayarlama
BASE_DIR = os.path.expanduser(r"~\Documents\Napes Studios\NapePass")

# Dosya yolları
PRIVATE_KEY_FILE = os.path.join(BASE_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "public_key.pem")
DATA_FILE = os.path.join(BASE_DIR, "data.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")

# Klasörü oluşturma (varsa geç)
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

# RSA anahtarlarını oluşturma veya yükleme
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    # Anahtarları dosyalara kaydetme
    with open(PRIVATE_KEY_FILE, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_rsa_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        generate_rsa_keypair()
    with open(PRIVATE_KEY_FILE, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
        )
        
    with open(PUBLIC_KEY_FILE, "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read()
        )
    return private_key, public_key

private_key, public_key = load_rsa_keys()

# AES şifreleme ve deşifreleme
def encrypt_data_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data_aes(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()

# Anahtar türetme
def derive_key(password, salt, length=32):
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())
    return key

# Veriyi şifreleme
def encrypt_data_hybrid(public_key, data, password):
    salt = os.urandom(16)
    aes_key = derive_key(password, salt)
    encrypted_data = encrypt_data_aes(data, aes_key)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(salt + encrypted_key + encrypted_data).decode()

# Veriyi deşifreleme
def decrypt_data_hybrid(private_key, encrypted_data, password):
    try:
        encrypted_data = base64.b64decode(encrypted_data.encode())
        salt = encrypted_data[:16]
        encrypted_key = encrypted_data[16:16 + private_key.key_size // 8]
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = encrypted_data[16 + private_key.key_size // 8:]
        decrypted_data = decrypt_data_aes(data, aes_key)
        return decrypted_data
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

# Veriyi yükleme
def load_data(password):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data_hybrid(private_key, encrypted_data, password)
            if decrypted_data:
                return json.loads(decrypted_data)
    return {}

# Veriyi kaydetme
def save_data(data, password):
    encrypted_data = encrypt_data_hybrid(public_key, json.dumps(data), password)
    with open(DATA_FILE, "w") as file:
        file.write(encrypted_data)

# Ayarları yükleme
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as file:
            return json.load(file)
    return {
        "copy_to_clipboard_enabled": True,
        "site_open_enabled": True,
    }

# Ayarları kaydetme
def save_settings(settings):
    with open(SETTINGS_FILE, "w") as file:
        json.dump(settings, file)

# Master şifreyi kaydetme
def save_master_password(master_password):
    encrypted_password = encrypt_data_hybrid(public_key, master_password, master_password)
    with open(os.path.join(BASE_DIR, "master.key"), "w") as file:
        file.write(encrypted_password)

# Master şifreyi doğrulama
def verify_master_password(master_password):
    if not os.path.exists(os.path.join(BASE_DIR, "master.key")):
        return False
    with open(os.path.join(BASE_DIR, "master.key"), "r") as file:
        encrypted_password = file.read()
    try:
        decrypted_password = decrypt_data_hybrid(private_key, encrypted_password, master_password)
        return decrypted_password == master_password
    except Exception as e:
        print(f"Error during password verification: {e}")
        return False

# Rastgele şifre oluşturma
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(random.choice(characters) for i in range(length))
    return random_password

# Uygulama sınıfı
class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NapePass - Şifre Yöneticisi")
        self.geometry("500x400")
        self.settings = load_settings()
        self.copy_to_clipboard_enabled = self.settings["copy_to_clipboard_enabled"]
        self.site_open_enabled = self.settings["site_open_enabled"]
        
        if not os.path.exists(os.path.join(BASE_DIR, "master.key")):
            self.show_register_screen()
        else:
            self.show_login_screen()
    
    def show_message(self, message, color="green"):
        if hasattr(self, "message_label") and self.message_label:
            self.message_label.destroy()
        self.message_label = ctk.CTkLabel(self, text=message, text_color=color)
        self.message_label.pack(pady=10)
    
    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()
    
    def create_password_entry(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=5)
        
        entry = ctk.CTkEntry(frame, show="*")
        entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        eye_button = ctk.CTkButton(frame, text="👁️", width=30, command=lambda: self.toggle_password_visibility(entry))
        eye_button.grid(row=0, column=1, padx=5)
        
        return entry
    
    def toggle_password_visibility(self, entry):
        if entry.cget("show") == "*":
            entry.configure(show="")
        else:
            entry.configure(show="*")
    
    def show_register_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Master Şifre Oluşturun").pack(pady=20)
        self.master_password_entry = self.create_password_entry(self)
        ctk.CTkButton(self, text="Kaydet", command=self.save_master_password).pack(pady=10)
    
    def save_master_password(self):
        master_password = self.master_password_entry.get()
        if master_password:
            save_master_password(master_password)
            self.show_message("Master şifre kaydedildi!")
            self.show_login_screen()
        else:
            self.show_message("Şifre boş olamaz!", "red")
    
    def show_login_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Master Şifre Girin").pack(pady=20)
        self.master_password_entry = self.create_password_entry(self)
        ctk.CTkButton(self, text="Giriş Yap", command=self.verify_master_password).pack(pady=10)
    
    def verify_master_password(self):
        master_password = self.master_password_entry.get()
        if verify_master_password(master_password):
            self.data = load_data(master_password)
            self.password = master_password
            self.show_main_screen()
        else:
            self.show_message("Hatalı şifre!", "red")
    
    def show_main_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="NapePass - Şifre Yöneticisi").pack(pady=20)
        ctk.CTkButton(self, text="Şifre Ekle", command=self.show_add_password_screen).pack(pady=10)
        ctk.CTkButton(self, text="Şifreleri Listele", command=self.show_list_passwords_screen).pack(pady=10)
        ctk.CTkButton(self, text="Ayarlar", command=self.show_settings_screen).pack(pady=10)

    def show_add_password_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Site, Kullanıcı Adı ve Şifre Girin").pack(pady=20)
        self.site_entry = ctk.CTkEntry(self, placeholder_text="Site")  # Placeholder metin
        self.site_entry.pack(pady=5)
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Kullanıcı Adı")  # Placeholder metin
        self.username_entry.pack(pady=5)

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(pady=5)
        
        self.password_entry = ctk.CTkEntry(frame, show="*", placeholder_text="Şifre")  # Placeholder metin
        self.password_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        eye_button = ctk.CTkButton(frame, text="👁️", width=30, command=lambda: self.toggle_password_visibility(self.password_entry))
        eye_button.grid(row=0, column=1, padx=5)

        generate_button = ctk.CTkButton(frame, text="🔄", width=30, command=self.generate_and_set_password)
        generate_button.grid(row=0, column=2, padx=5)
        
        ctk.CTkButton(self, text="Kaydet", command=self.add_password).pack(pady=10)
        ctk.CTkButton(self, text="İptal", command=self.show_main_screen).pack(pady=5)

    def generate_and_set_password(self):
        random_password = generate_random_password()
        self.password_entry.delete(0, ctk.END)
        self.password_entry.insert(0, random_password)

    def add_password(self):
        site = self.site_entry.get() if self.site_entry.get() else "N/A"
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            self.data[site] = {"username": username, "password": password}
            save_data(self.data, self.password)
            self.show_message("Şifre başarıyla kaydedildi!")
            self.show_main_screen()
        else:
            self.show_message("Lütfen tüm alanları doldurun!", "red")

    def delete_password(self, site):
        if site in self.data:
            del self.data[site]
            save_data(self.data, self.password)
            self.show_list_passwords_screen()
        else:
            self.show_message("Şifre bulunamadı!", "red")

    def show_list_passwords_screen(self):
        self.clear_window()
        scrollable_frame = ctk.CTkScrollableFrame(self, width=450, height=300)
        scrollable_frame.pack(pady=20, padx=10, fill="both", expand=True)

        if not self.data:
            ctk.CTkLabel(scrollable_frame, text="Kayıtlı şifre bulunamadı.", text_color="red").pack(pady=20)
        else:
            for site, credentials in self.data.items():
                frame = ctk.CTkFrame(scrollable_frame, fg_color="transparent", border_color="gray", border_width=1, corner_radius=10)
                frame.pack(pady=5, padx=10, fill="x", expand=True)
                site_label = ctk.CTkLabel(frame, text=f"Site: {site}")
                site_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
                if self.site_open_enabled and site != "N/A":
                    site_label.bind("<Double-1>", lambda event, site=site: webbrowser.open(f"https://{site}"))

                ctk.CTkLabel(frame, text=f"Kullanıcı Adı: {credentials['username']}").grid(row=1, column=0, padx=10, pady=5, sticky="w")
                password_label = ctk.CTkLabel(frame, text=f"Şifre: {credentials['password']}")
                password_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
                password_label.bind("<Double-1>", lambda event, pwd=credentials['password']: self.copy_to_clipboard(pwd))

                delete_button = ctk.CTkButton(frame, text="🗑️", command=lambda site=site: self.confirm_delete_password(site))
                delete_button.grid(row=0, column=1, rowspan=3, padx=5, pady=5)

        ctk.CTkButton(self, text="Geri", command=self.show_main_screen).pack(pady=10)
    
    def copy_to_clipboard(self, text):
        if self.copy_to_clipboard_enabled:
            pyperclip.copy(text)
            self.show_message("Şifre panoya kopyalandı!")

    def confirm_delete_password(self, site):
        self.clear_window()
        ctk.CTkLabel(self, text=f"{site} sitesine ait şifreyi silmek istediğinizden emin misiniz?").pack(pady=20)
        ctk.CTkButton(self, text="Evet", command=lambda: self.delete_password(site)).pack(pady=10)
        ctk.CTkButton(self, text="Hayır", command=self.show_list_passwords_screen).pack(pady=10)

    def show_settings_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Ayarlar").pack(pady=20)

        self.copy_to_clipboard_checkbox = ctk.CTkCheckBox(
            self, 
            text="Şifreler panoya kopyalanabilir", 
            command=self.toggle_copy_to_clipboard
        )
        self.copy_to_clipboard_checkbox.pack(pady=5)
        self.copy_to_clipboard_checkbox.select() if self.copy_to_clipboard_enabled else self.copy_to_clipboard_checkbox.deselect()

        self.site_open_checkbox = ctk.CTkCheckBox(
            self,
            text="Siteler açılabilir",
            command=self.toggle_site_open
        )
        self.site_open_checkbox.pack(pady=5)
        self.site_open_checkbox.select() if self.site_open_enabled else self.site_open_checkbox.deselect()

        ctk.CTkButton(self, text="Şifreyi Sıfırla", command=self.show_reset_password_screen).pack(pady=20)
        ctk.CTkButton(self, text="Geri", command=self.show_main_screen).pack(pady=10)

    def toggle_copy_to_clipboard(self):
        self.copy_to_clipboard_enabled = self.copy_to_clipboard_checkbox.get()
        self.settings["copy_to_clipboard_enabled"] = self.copy_to_clipboard_enabled
        save_settings(self.settings)

    def toggle_site_open(self):
        self.site_open_enabled = self.site_open_checkbox.get()
        self.settings["site_open_enabled"] = self.site_open_enabled
        save_settings(self.settings)

    def show_reset_password_screen(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Yeni Master Şifre Girin").pack(pady=20)
        new_password_entry = self.create_password_entry(self)
        ctk.CTkLabel(self, text="Yeni Master Şifreyi Tekrar Girin").pack(pady=10)
        confirm_password_entry = self.create_password_entry(self)

        def reset_password():
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            if new_password and new_password == confirm_password:
                save_master_password(new_password)
                self.show_message("Master şifre başarıyla sıfırlandı!")
                self.show_main_screen()
            else:
                self.show_message("Şifreler eşleşmiyor ya da boş bırakılamaz!", "red")

        ctk.CTkButton(self, text="Kaydet", command=reset_password).pack(pady=20)
        ctk.CTkButton(self, text="İptal", command=self.show_main_screen).pack(pady=10)

# Uygulamayı çalıştırma
if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()