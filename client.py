import hashlib
import threading
import socket
import os
import sys
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from cryptography.fernet import Fernet
import ttkbootstrap as ttkb
import hashlib

# Define the server IP and port here
SERVER_IP = '192.168.109.1'
SERVER_PORT = 1060


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


class Send(threading.Thread):
    def __init__(self, sock, name, cipher):
        super().__init__()
        self.sock = sock
        self.name = name
        self.cipher = cipher

    def run(self):
        while True:
            try:
                print('{}: '.format(self.name), end='')
                sys.stdout.flush()
                message = sys.stdin.readline().strip()

                if message.upper() == "QUIT":
                    self.sock.sendall(self.cipher.encrypt(f'server:{self.name} has left the chat.'.encode('ascii')))
                    break
                else:
                    self.sock.sendall(self.cipher.encrypt(f'{self.name}:{message}'.encode('ascii')))
            except OSError as e:
                print(f"Error: {e}")
                break

        print("\nQuitting....")
        self.sock.close()
        os._exit(0)  # Use os._exit to forcefully exit the program


class Receive(threading.Thread):
    def __init__(self, sock, name, cipher):
        super().__init__()
        self.sock = sock
        self.name = name
        self.cipher = cipher
        self.messages = None

    def run(self):
        while True:
            try:
                message = self.sock.recv(1024)
                if not message:
                    break
                decrypted_message = self.cipher.decrypt(message).decode('ascii')

                if decrypted_message:
                    if self.messages:
                        self.messages.insert(tk.END, decrypted_message)
                        print('\r{}\n{}: '.format(decrypted_message, self.name), end='')
                    else:
                        print('\r{}\n{}: '.format(decrypted_message, self.name), end='')
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"Error: {e}")
                break

        print('\n Connection lost!!!.')
        print("\nQuitting")
        self.sock.close()
        os._exit(0)  # Use os._exit to forcefully exit the program


class Client:
    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = name
        self.messages = None
        self.cipher = None

    def start(self):
        print('Trying to connect {}:{}....'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))
        print('Successfully connected to {}:{}'.format(self.host, self.port))
        print()
        self.cipher = Fernet(self.sock.recv(1024))  # Receive the encryption key from the server
        print(f'Welcome {self.name}! Connected Successfully')

        send = Send(self.sock, self.name, self.cipher)
        receive = Receive(self.sock, self.name, self.cipher)

        send.start()
        receive.start()

        self.sock.sendall(self.cipher.encrypt(f'server:{self.name} has joined the chat system. Say Hi'.encode('ascii')))
        print('\rType QUIT to leave the room.\n')
        print('{}: '.format(self.name), end='')

        return receive

    def send(self, textInput):
        message = textInput.get()
        textInput.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, message))

        if message.upper() == "QUIT":
            self.sock.sendall(self.cipher.encrypt('server: {} has left the chat.'.format(self.name).encode('ascii')))
            print('\nQuitting...')
            self.sock.close()
            os._exit(0)  # Use os._exit to forcefully exit the program
        else:
            self.sock.sendall(self.cipher.encrypt('{}: {}'.format(self.name, message).encode('ascii')))


def login_signup(window, frame, client):
    username = frame.username_entry.get()
    password = frame.password_entry.get()
    hashed_password = hash_password(password)
    mode = frame.mode.get()

    if mode == "signup":
        with open("cred.txt", "a") as f:
            f.write(f"{username}:{hashed_password}\n")

    with open("cred.txt", "r") as f:
        credentials = f.read().splitlines()

    if f"{username}:{hashed_password}" in credentials:
        client.name = username
        receive = client.start()

        frame.destroy()  # Destroy the login/signup frame before creating the chat interface

        window.title('PyChatVerse')

        fromMessage = ttkb.Frame(master=window)
        scrollBar = ttkb.Scrollbar(master=fromMessage)
        messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set)  # Use standard tkinter Listbox
        scrollBar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
        messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        client.messages = messages
        receive.messages = messages

        fromMessage.grid(row=0, column=0, columnspan=2, sticky="nsew")

        fromEntry = ttkb.Frame(master=window)
        textInput = ttkb.Entry(master=fromEntry)
        textInput.pack(fill=tk.BOTH, expand=True)
        textInput.bind("<Return>", lambda x: client.send(textInput))
        textInput.insert(0, "Send a message")

        sendbtn = ttkb.Button(master=window, text='Send', command=lambda: client.send(textInput))
        fromEntry.grid(row=1, column=0, padx=10, sticky='ew')
        sendbtn.grid(row=1, column=1, pady=10, sticky='ew')

        window.rowconfigure(0, minsize=500, weight=1)
        window.columnconfigure(0, minsize=500, weight=1)
        window.columnconfigure(1, minsize=200, weight=0)
    else:
        messagebox.showerror("Error", "Invalid credentials!")


class LoginSignupFrame(ttkb.Frame):
    def __init__(self, master, client, **kwargs):
        super().__init__(master, **kwargs)
        self.client = client

        self.mode = ttkb.StringVar(value="login")

        self.mode_frame = ttkb.Frame(self)
        self.mode_frame.pack(pady=10)

        self.login_radio = ttkb.Radiobutton(self.mode_frame, text="Login", variable=self.mode, value="login")
        self.signup_radio = ttkb.Radiobutton(self.mode_frame, text="Signup", variable=self.mode, value="signup")
        self.login_radio.pack(side=tk.LEFT, padx=10)
        self.signup_radio.pack(side=tk.RIGHT, padx=10)

        self.username_label = ttkb.Label(self, text="Username:")
        self.username_label.pack(pady=5)
        self.username_entry = ttkb.Entry(self)
        self.username_entry.pack(pady=5)

        self.password_label = ttkb.Label(self, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = ttkb.Entry(self, show="*")
        self.password_entry.pack(pady=5)

        self.submit_button = ttkb.Button(self, text="Submit", command=lambda: login_signup(master, self, client))
        self.submit_button.pack(pady=20)


def main():
    window = ttkb.Window(themename="superhero")
    window.title('Login/Signup')

    client = Client(SERVER_IP, SERVER_PORT, "")

    frame = LoginSignupFrame(window, client)
    frame.pack(pady=50)

    window.mainloop()


if __name__ == '__main__':
    main()
