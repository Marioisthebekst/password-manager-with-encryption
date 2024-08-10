import customtkinter
from customtkinter import *
import json
import pyperclip
from cryptography.fernet import Fernet
import base64
import atexit



if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
else:
    with open("key.key", "rb") as key_file:
        key = key_file.read()

fernet = Fernet(key)

def encrypt(password):
    if len(password) == 136:
        return password
    else:
        encrypted_password = fernet.encrypt(password.encode())
        encrypted_password_str = base64.b64encode(encrypted_password).decode('utf-8')
        return encrypted_password_str


def decrypt(password):
    encrypted_text = base64.b64decode(password.encode('utf-8'))
    decrypted_text = fernet.decrypt(encrypted_text).decode('utf-8')
    return decrypted_text

def encrypt_the_files():
    with open("manager.json", "r") as file:
        data = json.load(file)
    os.chmod("manager.json", 0o666)
    with open("manager.json", "w") as file:
        for software, password in data.items():
            data[software] = encrypt(password)
        json.dump(data, file, indent=4)
        file.close()
    os.chmod("manager.json", 0o444)

encrypt_the_files()
atexit.register(encrypt_the_files)
class Password:

    def __init__(self):
        self.first_key_win = CTk()
        self.first_key_win.geometry("450x400")
        self.first_key_win.title("Decrypt")
        self.first_key_win.resizable(False, False)
        CTkLabel(master=self.first_key_win, text="Enter The key to decrypt the data",
                 font=("brooklyn", 22, "bold")).place(relx=0.5, rely=0.1, anchor="center")
        self.dycentry = CTkEntry(self.first_key_win, font=("brooklyn", 18, "bold"), width=270)
        self.dycentry.place(relx=0.5, rely=0.2, anchor="center")
        CTkButton(self.first_key_win, text="Decrypt", font=("brooklyn", 22, "bold"), command=self.decrypt_window).place(
            relx=0.5, rely=0.3, anchor="center")

        self.first_key_win.mainloop()

    def decrypt_window(self):
        os.chmod("manager.json", 0o666)
        global fernet
        key = self.dycentry.get().encode()

        fernet = Fernet(key)

        with open("manager.json", "r") as file:
            data = json.load(file)
            for software, password in data.items():
                data[software] = decrypt(password)
        with open("manager.json", 'w') as file:
            json.dump(data, file, indent=4)
        os.chmod("manager.json", 0o444)
        self.first_key_win.destroy()
        self.Manager = CTk()
        self.Manager.geometry("450x400")
        self.Manager.title("Password Manager")
        self.Manager.resizable(False, False)
        self.labels()

    def labels(self):
        label = CTkLabel(master=self.Manager, text="Enter Password: ", font=("brooklyn", 22, "bold"))
        label.place(relx=0.258, rely=0.1, anchor="center")

        self.insert_password = CTkEntry(self.Manager, font=("brooklyn", 18, "bold"), width=170)
        self.insert_password.place(relx=0.65, rely=0.1, anchor="center")

        label = CTkLabel(master=self.Manager, text="Enter Service Name: ", font=("brooklyn", 22, "bold"))
        label.place(relx=0.3, rely=0.23, anchor="center")

        self.software = CTkEntry(self.Manager, font=("brooklyn", 18, "bold"), width=170)
        self.software.place(relx=0.73, rely=0.23, anchor="center")

        btn = CTkButton(self.Manager, text="Enter", font=("brooklyn", 22, "bold"), command=self.saving_password)
        btn.place(relx=0.5, rely=0.36, anchor="center", )

        btn = CTkButton(self.Manager, text="Saved Passwords", font=("brooklyn", 22, "bold"),
                        command=self.saved_passwords)
        btn.place(relx=0.5, rely=0.49, anchor="center")
        self.Manager.mainloop()

    def saving_password(self):
        with open("manager.json", "r") as file:
            data = json.load(file)
        os.chmod("manager.json", 0o666)
        with open("manager.json", "w") as file:
            data[self.software.get()] = self.insert_password.get()
            json.dump(data, file, indent=4)
        os.chmod("manager.json", 0o444)
        message = CTkLabel(master=self.Manager, text=f'Password saved for: {self.software.get()} software',
                           font=("brooklyn", 22, "bold"))
        message.place(relx=0.5, rely=0.62, anchor="center")
        self.insert_password.delete(0, customtkinter.END)
        self.software.delete(0, customtkinter.END)

    def saved_passwords(self):
        self.Passwords = CTk()
        self.Passwords.geometry("650x500")
        self.Passwords.title("Saved Passwords")
        self.Passwords.resizable(False, False)
        self.page = 0
        self.passwords_per_page = 4

        with open("manager.json", "r") as saved_pass:
            self.data = json.load(saved_pass)

        self.passwords = list(self.data.items())
        self.display_passwords()
        self.Passwords.mainloop()

    def display_passwords(self):
        self.destroy_window()
        self.increase = 0
        init_index = self.page * self.passwords_per_page
        last_index = init_index + self.passwords_per_page

        for software_name, password in self.passwords[init_index: last_index]:
            newlabel = CTkLabel(master=self.Passwords, text=software_name + ": ", font=("brooklyn", 22, "bold"))
            newlabel.place(relx=0.4, rely=(0.1 + self.increase), anchor="center")
            pass_btn = CTkButton(self.Passwords, text=password, font=("brooklyn", 22, "bold"),
                                 command=lambda id=password: self.copy(id))
            pass_btn.place(relx=0.6, rely=0.1 + self.increase, anchor="center")
            self.increase += 0.1

        label = CTkLabel(master=self.Passwords, text="Press at a password to copy it", font=("brooklyn", 22, "bold"))
        label.place(relx=0.5, rely=0.1 + self.increase, anchor="center")

        dlt_label = CTkLabel(master=self.Passwords,text="To delete a password enter the software name then click delete",font=("brooklyn", 22, "bold"))
        dlt_label.place(relx=0.5, rely=0.2 + self.increase, anchor="center")

        self.dlt_entry = CTkEntry(self.Passwords, font=("brooklyn", 22, "bold"), width=170)
        self.dlt_entry.place(relx=0.4, rely=0.3 + self.increase, anchor="center")

        dlt_button = CTkButton(self.Passwords, text="Delete Password", font=("brooklyn", 22, "bold"),
                               command=self.delete)
        dlt_button.place(relx=0.7, rely=0.3 + self.increase, anchor="center")

        previous_btn = CTkButton(master=self.Passwords, text="previous", font=("brooklyn", 22, "bold"),
                                 command=self.prev)
        previous_btn.place(relx=0.15, rely=0.9, anchor="center")

        next_btn = CTkButton(master=self.Passwords, text="next", font=("brooklyn", 22, "bold"), command=self.next)
        next_btn.place(relx=0.85, rely=0.9, anchor="center")

        page_label = CTkLabel(master=self.Passwords, text=f'page: {self.page}', font=("brooklyn", 20, "bold"))
        page_label.place(relx=0.07, rely=0.05, anchor="center")

    def copy(self, button):
        if button is not None:
            pyperclip.copy(button)

    def delete(self):
        service_name = self.dlt_entry.get()
        os.chmod("manager.json", 0o666)
        with open("manager.json", "w") as saved_pass:
            if service_name in self.data:
                del self.data[service_name]
                self.dlt_entry.delete(0, customtkinter.END)
                message = CTkLabel(master=self.Passwords,
                                   text=f'The password for {service_name} has been deleted successfully',
                                   font=("brooklyn", 22, "bold"))
                message.place(relx=0.5, rely=0.4 + self.increase, anchor="center")
                json.dump(self.data, saved_pass, indent=4)
            else:
                message = CTkLabel(master=self.Passwords, text=f'No software named {service_name} found in the system',
                                   font=("brooklyn", 22, "bold"))
                message.place(relx=0.5, rely=0.4 + self.increase, anchor="center")
                json.dump(self.data, saved_pass, indent=4)
        os.chmod("manager.json", 0o444)

    def prev(self):
        if self.page > 0:
            self.page -= 1
            self.display_passwords()

    def next(self):
        if (self.page + 1) * self.passwords_per_page < len(self.passwords):
            self.page += 1
            self.display_passwords()

    def destroy_window(self):
        for widget in self.Passwords.winfo_children():
            if isinstance(widget, CTkLabel) or isinstance(widget, CTkButton) or isinstance(widget, CTkEntry):
                widget.destroy()


if __name__ == "__main__":
    manager = Password()
