import socket

def main():
    host = 'localhost'
    port = 4224

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        print("Connected to the server.")
        print("Available commands: SET, GET, DELETE, CONTAINS, ITER, HSET, HGET, LEN")
        print("Type quit to exit.")
        while True:
            command = input("keysdb>>> ").strip()

            if command.lower() == "quit":
                s.sendall(command.encode())
                break

            s.sendall(command.encode())

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
            else:
                response = s.recv(1024).decode()
                print(response)

        print("Disconnected from the server.")

if __name__ == "__main__":
    main()
