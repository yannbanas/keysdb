import socket

def main():
    host = 'localhost'
    port = 4224

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        print("Connected to the server.")
        while True:
            command = input("Enter command (or type 'quit' to exit): ").strip()

            if command.lower() == "quit":
                s.sendall(command.encode())
                break

            s.sendall(command.encode())

            if command.startswith("SET"):
                response = s.recv(1024).decode()
                if response == "OK":
                    print("Value set successfully.")
                else:
                    print(f"Error setting value: {response}")
            elif command.startswith("GET"):
                response = s.recv(1024).decode()
                if response != "Key not found":
                    print(f"Value: {response}")
                else:
                    print("Key not found in the store.")
            elif command.startswith("DELETE"):
                response = s.recv(1024).decode()
                if response == "OK":
                    print("Key deleted successfully.")
                else:
                    print(f"Error deleting key: {response}")
            elif command.startswith("CONTAINS"):
                response = s.recv(1024).decode()
                if response == "True":
                    print("Key exists in the store.")
                elif response == "False":
                    print("Key does not exist in the store.")
                else:
                    print(f"Error checking key presence: {response}")
            elif command.startswith("ITER"):
                response = s.recv(1024).decode().split("\n")
                print("Keys in store:")
                for key in response:
                    if key:
                        print(key)
            elif command.startswith("HSET"):
                response = s.recv(1024).decode()
                if response == "OK":
                    print("Hash value set successfully.")
                else:
                    print(f"Error setting hash value: {response}")

            elif command.startswith("HGET"):
                response = s.recv(1024).decode()
                if response != "Key not found":
                    print(f"Value: {response}")
                else:
                    print("Key or field not found in the store.")

            elif command.startswith("LEN"):
                response = int.from_bytes(s.recv(4), byteorder="big")
                print("Number of key-value pairs in the store:", response)
            else:
                response = s.recv(1024).decode()
                if response == "Invalid command":
                    print("Invalid command. Please check the command format and try again.")
                else:
                    print(f"Unexpected response from server: {response}")

        print("Disconnected from the server.")

if __name__ == "__main__":
    main()
