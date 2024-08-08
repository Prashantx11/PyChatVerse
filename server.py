import threading
import socket
import argparse
import os
from cryptography.fernet import Fernet


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        print(f"Encryption key: {self.key.decode()}")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        print("Listening at", sock.getsockname())

        while True:
            sc, sock_name = sock.accept()
            print(f"Accepted connection from {sc.getpeername()} to {sc.getsockname()}")
            sc.sendall(self.key)  # Send the encryption key to the client
            server_socket = ServerSocket(sc, sock_name, self)
            server_socket.start()
            self.connections.append(server_socket)
            print("Ready to receive messages from", sc.getpeername())

    def broadcast(self, message, source):
        for connection in self.connections:
            if connection.sock_name != source:
                connection.send(message)

    def remove_connection(self, connection):
        self.connections.remove(connection)


class ServerSocket(threading.Thread):
    def __init__(self, sc, sock_name, server):
        super().__init__()
        self.sc = sc
        self.sock_name = sock_name
        self.server = server
        self.cipher = Fernet(self.server.key)

    def run(self):
        while True:
            try:
                message = self.sc.recv(1024)
                if not message:
                    break
                decrypted_message = self.cipher.decrypt(message).decode('ascii')
                if decrypted_message:
                    print(f"{self.sock_name} says {decrypted_message}")
                    self.server.broadcast(decrypted_message, self.sock_name)
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"Error: {e}")
                break

        print(f"{self.sock_name} has closed the connection")
        self.sc.close()
        self.server.remove_connection(self)

    def send(self, message):
        encrypted_message = self.cipher.encrypt(message.encode('ascii'))
        self.sc.sendall(encrypted_message)


def exit_program(server):
    while True:
        ipt = input("")
        if ipt == "q":
            print("Closing all connections...")
            for connection in server.connections:
                connection.sc.close()
            print("Shutting down the server")
            os._exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom Server")
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')

    args = parser.parse_args()

    server = Server(args.host, args.p)
    server.start()

    exit_thread = threading.Thread(target=exit_program, args=(server,))
    exit_thread.start()
