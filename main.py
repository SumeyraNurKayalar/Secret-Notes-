import tkinter as tk
from tkinter import messagebox
import base64

def encrypt_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def save_and_encrypt():
    title = title_input.get()
    secret = secret_input.get("1.0", tk.END).strip()

    encrypted_secret = encrypt_decrypt(secret, 3)

    with open(f"{title}.txt", "w") as file:
        file.write(encrypted_secret)

    messagebox.showinfo("Success", f"'{title}.txt' başarıyla şifrelendi!")

def decrypt():
    title = title_input.get()
    try:
        with open(f"{title}.txt", "r") as file:
            encrypted_secret = file.read()

        decrypted_secret = encrypt_decrypt(encrypted_secret, -3)

        messagebox.showinfo("Decrypted Secret", decrypted_secret)
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

save_button = tk.Button(text="Save & Encrypt", command=save_and_encrypt)
save_button.pack()

dec_button = tk.Button(text="Decrypt", command=decrypt)
dec_button.pack()

window.mainloop()
