from keysdb.aes import AES
from keysdb.yaml_editor import load_yaml, write_yaml
import os

yamlpath = './keys.yaml'

key = bytes.fromhex(load_yaml(yamlpath)['key'])
iv = bytes.fromhex(load_yaml(yamlpath)['iv'])

print(key)
print(iv)

# Utilisez la clé et l'IV pour le chiffrement et le déchiffrement
encrypted = AES(key).encrypt_ctr(b'Attack at dawn', iv)
print(encrypted)
print(AES(key).decrypt_ctr(encrypted, iv))
