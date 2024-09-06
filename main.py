import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Anahtar çifti oluşturma (bu işlem sadece bir kez yapılmalıdır)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


# Şifreleme fonksiyonu
def save_and_encrypt():
    title = title_input.get()
    secret = secret_input.get("1.0", tk.END)  # Text alanındaki tüm içeriği alıyoruz

    # Veriyi şifreleme (public key ile)
    encrypted_secret = public_key.encrypt(
        secret.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Şifrelenmiş veriyi dosyaya kaydetme
    with open(f"{title}.txt", "wb") as file:  # Dosyayı binary modda açıyoruz
        file.write(encrypted_secret)

    messagebox.showinfo("Success", f"'{title}.txt' başarıyla şifrelendi!")


# Deşifreleme fonksiyonu
def decrypt():
    title = title_input.get()
    try:
        # Şifrelenmiş veriyi dosyadan okuma
        with open(f"{title}.txt", "rb") as file:
            encrypted_secret = file.read()

        # Veriyi deşifre etme (private key ile)
        decrypted_secret = private_key.decrypt(
            encrypted_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Deşifre edilmiş metni gösterme
        messagebox.showinfo("Decrypted Secret", decrypted_secret.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Deşifreleme hatası: {e}")


window = tk.Tk()
window.title("Secret Notes")
window.config(padx=75, pady=75)

title_label = tk.Label(text="Enter your title")
title_label.pack()
title_input = tk.Entry(width=25)
title_input.pack()

secret_label = tk.Label(text="Enter your secret")
secret_label.pack()
secret_input = tk.Text(height=10, width=25)
secret_input.pack()

key_label = tk.Label(text="Enter master key", font=(16))
key_label.pack()
key_input = tk.Entry(width=50)
key_input.pack()

save_button = tk.Button(text="Save & Encrypt", command=save_and_encrypt)
save_button.pack()

dec_button = tk.Button(text="Decrypt", command=decrypt)
dec_button.pack()

window.mainloop()
