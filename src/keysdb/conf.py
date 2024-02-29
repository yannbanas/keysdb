from yaml_editor import *
import os

key = os.urandom(16)
iv = os.urandom(16)

# Convertir les octets en chaînes hexadécimales lisibles
key_hex = key.hex()
iv_hex = iv.hex()

data_to_write = {
    'host': 'localhost',
    'port': 4224,
    'data_path': 'D:\\',
    'data_file': 'data.json',
    'key': key_hex,  # Utiliser la représentation hexadécimale de la clé
    'iv': iv_hex     # Utiliser la représentation hexadécimale de l'IV
}
file_path = '../examples/keys.yaml'
write_yaml(data_to_write, file_path)