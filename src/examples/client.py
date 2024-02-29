import socket, hashlib
from keysdb.aes import AES
from keysdb.yaml_editor import load_yaml, write_yaml

yamlpath = './keys.yaml'
KEY = bytes.fromhex(load_yaml(yamlpath)['key'])
IV = bytes.fromhex(load_yaml(yamlpath)['iv'])

print(KEY)
print(IV)

def send_password(sock, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()  # Hasher le mot de passe
    sock.sendall(hashed_password.encode())

def main():
    host = 'localhost'
    port = 4224

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        print("Connected to the server.")
        print("Available commands: SET, GET, DELETE, CONTAINS, ITER, HSET, HGET, LEN")
        print("Type quit to exit.")
        password = input("Enter password of db: ")
        send_password(s, password)
        print(s.recv(1024).decode())
        while True:
            command = input("keysdb>>> ").strip()

            # Encrypt the command using AES
            encrypted_command = AES(KEY).encrypt_ctr(command.encode(), IV)

            # Send encrypted command to the server
            s.sendall(encrypted_command)

            if command.startswith("SET"):
                response = s.recv(1024).decode()
                print(response)
            elif command.startswith("GET"):
                response = s.recv(1024).decode()
                print(response)
            elif command.startswith("DELETE"):
                response = s.recv(1024).decode()
                print(response)
            elif command.startswith("CONTAINS"):
                response = s.recv(1024).decode()
                print(response)
            elif command.startswith("ITER"):
                response = s.recv(1024).decode().split("\n")
                for key in response:
                    if key:
                        print(key)
                    else:
                        print("No keys in store.")
            elif command.startswith("HSET"):
                response = s.recv(1024).decode()
                print(response)

            elif command.startswith("HGET"):
                response = s.recv(1024).decode()
                print(response)

            elif command.startswith("LEN"):
                response = int.from_bytes(s.recv(4), byteorder="big")
                print("Number of key-value pairs in the store:", response)

            elif command.lower() == "quit":
                s.sendall(command.encode())
                break

            else:
                response = s.recv(1024).decode()
                print(response)

        print("Disconnected from the server.")

if __name__ == "__main__":
    main()
