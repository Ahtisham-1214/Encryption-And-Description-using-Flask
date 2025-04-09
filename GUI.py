import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

root = tk.Tk()
root.title("SecureFile Encryptor")
root.geometry("650x650")
root.minsize(650, 650)


# Styling
style = ttk.Style()
style.configure('TFrame', background='#f0f0f0')
style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
style.configure('TButton', font=('Arial', 9))
style.configure('TRadiobutton', background='#f0f0f0', font=('Arial', 10))

# Main container
main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

# Operation Section
operation_frame = ttk.LabelFrame(main_frame, text="Operation", padding=10)
operation_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

operation = tk.StringVar(value="encrypt")

encrypt_rb = ttk.Radiobutton(operation_frame, text="Encrypt File", variable=operation, value="encrypt")
encrypt_rb.grid(row=0, column=0, padx=10, pady=5, sticky="w")

decrypt_rb = ttk.Radiobutton(operation_frame, text="Decrypt File", variable=operation, value="decrypt")
decrypt_rb.grid(row=1, column=0, padx=10, pady=5, sticky="w")

# File Selection
file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
file_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))

ttk.Label(file_frame, text="Select File:").grid(row=0, column=0, sticky="w")

file_path = tk.StringVar()
file_entry = ttk.Entry(file_frame, textvariable=file_path, width=50)
file_entry.grid(row=1, column=0, padx=(0, 5), sticky="ew")

browse_btn = ttk.Button(file_frame, text="Browse" , command=lambda: browse_file())
browse_btn.grid(row=1, column=1, sticky="e")

# Key Section
key_frame = ttk.LabelFrame(main_frame, text="Encryption Key", padding=10)
key_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))

key_label = ttk.Label(key_frame, text="Generated Key:")
key_entry = ttk.Entry(key_frame, state="readonly", width=50)
copy_btn = ttk.Button(key_frame, text="Copy")

key_label.grid(row=0, column=0, sticky="w")
key_entry.grid(row=1, column=0, padx=(0, 5), sticky="ew")
copy_btn.grid(row=1, column=1, sticky="e")

ttk.Label(key_frame, text="Enter Decryption Key:").grid(row=2, column=0, sticky="w", pady=(10, 0))
user_key = ttk.Entry(key_frame, width=50, show="*")
user_key.grid(row=3, column=0, padx=(0, 5), sticky="ew")

# Log Section
log_frame = ttk.LabelFrame(main_frame, text="Operation Log", padding=10)
log_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(0, 10))

log_text = scrolledtext.ScrolledText(log_frame, width=70, height=10)
log_text.pack(fill=tk.BOTH, expand=True)

# Action Buttons
action_frame = ttk.Frame(main_frame)
action_frame.grid(row=4, column=0, columnspan=2, sticky="e", pady=(10, 0))


def process_file():
    selected_operation = operation.get()
    selected_file = file_path.get()
    decryption_key = user_key.get()

    if not selected_file:
        messagebox.showerror("Error", "Please select a file.")
        return

    if selected_operation == "encrypt":
        # Placeholder for encryption logic
        log_text.insert(tk.END, "Encrypting file: " + selected_file + "\n")
        log_text.see(tk.END)
    elif selected_operation == "decrypt":
        if not decryption_key:
            messagebox.showerror("Error", "Please enter the decryption key.")
            return
        # Placeholder for decryption logic
        log_text.insert(tk.END, "Decrypting file: " + selected_file + "\n")
        log_text.see(tk.END)



process_btn = ttk.Button(action_frame, text="Process File", command=process_file)
process_btn.pack(side=tk.LEFT, padx=5)

exit_btn = ttk.Button(action_frame, text="Exit", command=root.quit)
exit_btn.pack(side=tk.LEFT)

# Configure grid weights
main_frame.columnconfigure(0, weight=1)
file_frame.columnconfigure(0, weight=1)
key_frame.columnconfigure(0, weight=1)




def browse_file():
    path = filedialog.askopenfilename()
    if path:
        file_path.set(path)
        log_text.insert(tk.END, "File selected: " + path + "\n")
        log_text.see(tk.END)



root.mainloop()