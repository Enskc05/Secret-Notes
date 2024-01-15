from tkinter import *
from tkinter import messagebox
import base64

# apply cryptography with vigenere cipher
# https://stackoverflow.com/a/38223403

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_secret = master_secret_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!!!", message="Please enter all info.")
    else:
        message_encrypt = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypt}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypt}')
        finally:
            title_entry.delete(0, END)
            input_text.delete("1.0", END)
            master_secret_entry.delete(0, END)

def decrypt_notes():
    message_encrypt = input_text.get("1.0", END)
    master_secret = master_secret_entry.get()

    if len(message_encrypt) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!!", message="Please enter all info")
    else:
        try:
            decrypt_message = decode(master_secret, message_encrypt)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypt_message)
        except:
            messagebox.showinfo(title="Error!!",message="Please enter encrypted text")




root = Tk()
root.title("Secret Notes")
root.config(padx=30, pady=30)

photo = PhotoImage(file="topsecret.png")
photo_label = Label(image=photo)
photo_label.pack()

title_info_label = Label(text="Enter your title", font=('Verdena', 20, 'normal'))
title_info_label.pack()

title_entry = Entry()
title_entry.pack()

input_info_label = Label(text="Enter your secret", font=("Verdena", 20, "normal"))
input_info_label.pack()

input_text = Text(width=50, height=25)
input_text.pack()

master_secret_label = Label(text="Enter master key", font=('Verdena', 20, 'normal'))
master_secret_label.pack()

master_secret_entry = Entry(width=30)
master_secret_entry.pack()

save_button = Button(text="Save&Encrypt", command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()

root.mainloop()
