from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from Crypto import Random
import tkinter
from tkinter import ttk
from tkinter import messagebox 
from PIL import Image, ImageTk
import os,requests

class RSA_API:
    def generate_key_pair():
        key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def encrypt_text(text, public_key):
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext.hex()

    def decrypt_text(ciphertext_hex, private_key):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()

class AES_API:
    def __init__(self, key):
        self.bs = AES.block_size
        # Hash the user-provided key to ensure it's the right length
        self.key = hashlib.sha256(key.encode()).digest()
 
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))
 
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
 
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
 
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
        

class GUI:
    def Window():
        root = tkinter.Tk()
        root.title('Symmetric & Asymmetric - Encryption/Decryption')
        root.geometry('695x270')
        root.iconbitmap('icon.ico')
        return root
    def Elements (root):
        tkinter.Label(root, text="Choose Crypt Method :").place(x=10,y=10)         # Text Label (Choose Crypt Method :)
        def swich (ev):                                                            # if user select RSA , then lock the key entry box
            if ('RSA' in combo_box.get()) and (proc_t.get() == 1):
                key_entry.configure(state="readonly")
            else:
                key_entry.configure(state="normal")
        combo_box = ttk.Combobox(root, 
            values=["Advanced Encryption Standard (AES)", "Rivest–Shamir–Adleman (RSA)"]
            ,width=50)                                                             # Combo box ( select aes or rsa)
        combo_box.bind("<<ComboboxSelected>>", swich)                              # if user select something, call "swich" func
        combo_box.set("Advanced Encryption Standard (AES)")
        combo_box.place(x=150,y=10)
        #
        #
        proc_t = tkinter.IntVar()
        b1=ttk.Radiobutton(root, text='Encrypt', variable=proc_t,command=lambda:swich(''), value=1)
        b1.place(x=150, y=35)
        ttk.Radiobutton(root, text='Decrypt', variable=proc_t,command=lambda:swich(''), value=2).place(x=240, y=35)
        proc_t.set(1)
        #
        #
        tkinter.Label(root, text="Enter Key :").place(x=10,y=60)      # Text Label (Enter Key (AES only) :)
        key_entry = ttk.Entry(width=50)
        key_entry.place(x=150,y=60)
        #
        #
        tkinter.Label(root, text="Enter Message :").place(x=10,y=83)      # Text Label (Enter Key (AES only) :)
        msg_entry = ttk.Entry(width=50)
        msg_entry.place(x=150,y=83)
        #
        #
        def Launch ():
            try:
                if 'AES' in combo_box.get(): # ASE 
                    aes = AES_API( str(key_entry.get()) )
                    MESSAGE =  str(msg_entry.get())
                    if proc_t.get() == 1 : # encrypt
                        output = aes.encrypt(MESSAGE).decode()
                    else:            # decrypt
                        output = aes.decrypt(MESSAGE)
                    text_box.delete("1.0", tkinter.END)
                    text_box.insert(tkinter.END, str(output))
                else: # RSE
                    MESSAGE =  msg_entry.get()
                    if proc_t.get() == 1 : # encrypt
                        private_key, public_key = RSA_API.generate_key_pair()
                        output = RSA_API.encrypt_text(MESSAGE, public_key)
                        text_box.delete("1.0", tkinter.END)
                        text_box.insert(tkinter.END, 'private_key:\n'+str(private_key.decode())+'\n\npublic_key:\n'+str(public_key.decode())+'\n\noutput:\n'+str(output))
                    else:            # decrypt
                        KEY = key_entry.get().encode('utf-8')
                        output = RSA_API.decrypt_text(MESSAGE, KEY)
                        text_box.delete("1.0", tkinter.END)
                        text_box.insert(tkinter.END, output)
            except Exception as e:
                messagebox.showerror('Error', str(e)) 
        launch = ttk.Button(text='Launch',width=75,command=Launch)
        launch.place(x=10,y=110)
        #
        #
        text_box = tkinter.Text(root,height=6,width=57)
        text_box.place(x=10,y=143)
        #
        #
        im = Image.open('img.png')
        im = im.resize((200, 272), Image.ANTIALIAS)
        im = ImageTk.PhotoImage(im)
        img_ = tkinter.Label(root, image=im)
        img_.image = im
        img_.place(x=485,y=1)

if __name__ == '__main__':
    if 'img.png' not in os.listdir():
        r = requests.get('https://github.com/mohdmot/AES-RSA-Tool/blob/main/img.png?raw=true', allow_redirects=True)
        open('img.png', 'wb').write(r.content)
    if 'icon.ico' not in os.listdir():
        r = requests.get('https://github.com/mohdmot/AES-RSA-Tool/raw/main/icon.ico', allow_redirects=True)
        open('icon.ico', 'wb').write(r.content)
    win = GUI.Window()
    GUI.Elements(win)
    win.mainloop()