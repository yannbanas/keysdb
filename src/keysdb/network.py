import socket
import hashlib
import secrets
from .key_value_store import KeyValueStore
from .exceptions import KeyNotFoundError, InvalidDataType, DataTypeError
import logging.config

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] [MESSAGE]: %(message)s',
            'datefmt': '%d-%m-%Y %H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'NOTSET',
    },
}

logging.config.dictConfig(logging_config)

VERSION="KeysDB 0.0.1 Build 280224 64 bit"
TYPE="STANDALONE"
PORT=4224
URL="https://github.com/yannbanas/keysdb"
AUTHOR="Banas Yann"

PASSWD = secrets.token_urlsafe(8)

from keysdb.aes import AES
from keysdb.yaml_editor import load_yaml, write_yaml

yamlpath = 'D:\\Experimentation\\keysdb\\src\\keysdb\\keys.yaml'
KEY = bytes.fromhex(load_yaml(yamlpath)['key'])
IV = bytes.fromhex(load_yaml(yamlpath)['iv'])

class NetworkedKeyValueStore:
    def __init__(self, host, port, data_file,hashed_password=PASSWD):
        self.host = host
        self.port = PORT or port
        self.data_file = data_file
        self.hashed_password = hashlib.sha256(hashed_password.encode()).hexdigest()
        self.store = KeyValueStore(data_file=data_file)
        self.server_socket = None


    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"""
                 _______                  
               /@@@@@@@@@\                
             /@@@@@   @@@@@\            
            /@@@@@     @@@@@\ 
            @@@@@@@@@@@@@@@@@
            @@@@@@@@@@@@@@@@@          ╔════════════════════════════════════════════╗
             @@@@@@@@@@@@@@@           ║ {VERSION}           ║
                @@@@@@@@@              ║ Running in mode {TYPE}                 ║
                @@@@@@@@@              ║ Port: {PORT}                                 ║
                  @@@@@@@              ║ Info: {URL}  ║
                @@@@@@@@@              ║ Author: {AUTHOR}                         ║
                  @@@@@@@              ╚════════════════════════════════════════════╝
                 @@@@@@@@                           Secret: {PASSWD}
                  @@@@@@@
                 @@@@@@@@              
                  @@@@@@                
                    @@                  
                                                                                """)
        logging.info(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            self.handle_client(client_socket)

    def authenticate(self, client_socket):
        """
        Méthode pour l'authentification des clients.
        """
        password_attempt = client_socket.recv(1024).strip()  # Recevoir le mot de passe entré par le client
        if str(password_attempt).lstrip("b'").rstrip("'") == self.hashed_password:
            client_socket.sendall(b"Authentication successful")
            logging.info(f"Authentication successful")
            return True
        else:
            client_socket.sendall(b"Authentication failed")
            logging.error("wrong hashed password :"+self.hashed_password)
            return False

        
    def handle_client(self, client_socket):
        try:
            if not self.authenticate(client_socket):
                logging.error("Authentication failed. Closing connection.")
                return
            else:
                while True:

                    encrypted_data = client_socket.recv(1024)  # Receive encrypted data from client
                    decrypted_data = AES(KEY).decrypt_ctr(encrypted_data, IV)  # Decrypt the received data
                    decoded_data = decrypted_data.decode()  # Decode decrypted data
                    
                    if not decrypted_data:
                        break

                    command, *args = decoded_data.split(" ")

                    if command == "SET":
                        if len(args) != 4:
                            client_socket.sendall(b"Invalid SET command format")
                            logging.info(f"Invalid SET command format: {decoded_data}")
                            continue

                        key, value, data_type, ttl = args[0], args[1], args[2], int(args[3])
                        self.store.set(key, value, data_type, ttl)
                        logging.info(f"SET: Successfully set '{key}' with value '{value}' and TTL {ttl}s")
                        client_socket.sendall(b"OK")

                    elif command == "HSET":
                        if len(args) != 4:
                            client_socket.sendall(b"Invalid HSET command format")
                            logging.info(f"Invalid HSET command format: {decoded_data}")
                            continue

                        key, field, value, ttl = args[0], args[1], args[2], int(args[3])
                        self.store.set_hash(key, field, value, ttl)
                        logging.info(f"HSET: Successfully set '{key}' with field '{field}' and value '{value}' and TTL {ttl}s")
                        client_socket.sendall(b"OK")

                    elif command == "HGET":
                        if len(args) != 2:
                            client_socket.sendall(b"Invalid HGET command format")
                            logging.info(f"Invalid HGET command format: {decoded_data}")
                            continue

                        key, field = args[0], args[1]
                        try:
                            value = self.store.get_hash(key, field)
                            client_socket.sendall(value.encode())
                            logging.info(f"HGET: Retrieved value for '{key}' with field '{field}'")
                        except KeyNotFoundError:
                            client_socket.sendall(b"Key not found")
                            logging.error(f"HGET: Key '{key}' or field '{field}' not found")

                    elif command == "GET":
                        key = args[0]
                        try:
                            value = self.store.get(key)
                            client_socket.sendall(value.encode())
                            logging.info(f"GET: Retrieved value for '{key}'")
                        except KeyNotFoundError:
                            client_socket.sendall(b"Key not found")
                            logging.error(f"GET: Key '{key}' not found")

                    elif command == "DELETE":
                        key = args[0]
                        self.store.delete(key)
                        logging.info(f"DELETE: Deleted key '{key}'")
                        client_socket.sendall(b"OK")

                    elif command == "CONTAINS":
                        key = args[0]
                        result = int(key in self.store)
                        client_socket.sendall(result.to_bytes(1, byteorder="big"))
                        logging.info(f"CONTAINS: Sent presence of key '{key}' in the store")

                    elif command == "ITER":
                        try:
                            
                            keys = [key.encode() for key in self.store]
                            if not keys:
                                keys = [b"None"]
                            client_socket.sendall(b"\n".join(keys))
                            logging.info(f"ITER: Sent keys in the store")
                        except Exception as e:
                            client_socket.sendall(str(e).encode())
                            logging.error(f"ITER: Error sending keys: {e}")

                    elif command == "LEN":
                        try:
                            length = len(self.store)
                            client_socket.sendall(length.to_bytes(4, byteorder="big"))
                            logging.info(f"LEN: Sent number of key-value pairs in the store")
                        except Exception as e:
                            client_socket.sendall(str(e).encode())
                            logging.error(f"LEN: Error sending length: {e}")

                    elif command.lower() == "quit":
                        logging.info(f"Client {client_socket} was disconnected from server.")
                        break
                    else:
                        client_socket.sendall(b"Invalid command")
                        logging.info(f"Invalid command: {decoded_data}")

        except Exception as e:
            logging.error(f"Error handling client: {e}")
            client_socket.close()
        finally:
            client_socket.close()


    def stop(self):
        self.server_socket.close()
        logging.info("Server stopped")
