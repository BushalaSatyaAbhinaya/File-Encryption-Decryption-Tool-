import tkinter as tk
from tkinter import filedialog, messagebox


def select_file():
    file_path.set(filedialog.askopenfilename())

def encrypt_action():
    path = file_path.get()
    pwd = password.get()

    if not path or not pwd:
        messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
        return

    try:
        result = encrypt_file(path, pwd)
        messagebox.showinfo("Success", f"File encrypted:\n{result}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

def decrypt_action():
    path = file_path.get()
    pwd = password.get()

    if not path.endswith(".encrypted"):
        messagebox.showwarning("Invalid File", "Please select a file with '.encrypted' extension.")
        return

    if not path or not pwd:
        messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
        return

    try:
        result = decrypt_file(path, pwd)
        messagebox.showinfo("Success", f"File decrypted:\n{result}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# GUI setup
app = tk.Tk()
app.title("🔐 File Encryptor")
app.geometry("400x300")
app.resizable(False, False)

file_path = tk.StringVar()
password = tk.StringVar()

tk.Label(app, text="File Path:").pack(pady=5)
tk.Entry(app, textvariable=file_path, width=50).pack()
tk.Button(app, text="Browse", command=select_file).pack(pady=5)

tk.Label(app, text="Password:").pack(pady=5)
tk.Entry(app, textvariable=password, show='*', width=30).pack()

tk.Button(app, text="Encrypt File", command=encrypt_action, bg="green", fg="white", width=20).pack(pady=10)
tk.Button(app, text="Decrypt File", command=decrypt_action, bg="blue", fg="white", width=20).pack()

app.mainloop()
