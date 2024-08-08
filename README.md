# PyChatVerse
This repository contains a secure chat application built using Python. The application consists of a server and a client that communicate securely using encryption.

## Features

- **Secure Communication:** Messages between the server and clients are encrypted using the `cryptography` library.
- **Multi-Client Support:** The server can handle multiple clients simultaneously.
- **GUI Integration:** The client includes a modern GUI for login/signup and chat functionalities, built with `ttkbootstrap`.
- **Password Hashing:** User passwords are hashed using SHA-256 before being stored.

## Requirements

To run this project, you need to install the following dependencies:

cryptography==41.0.3
ttkbootstrap==1.12.1


pip install -r requirements.txt

python3 server.py <host> -p <port>

python3 server.py localhost -p 1060

python3 client.py

