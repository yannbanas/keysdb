import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

# Les tables de substitution S-Box et inverse S-Box
s_box = (
    # Une table de substitution pour la substitution byte dans l'opération SubBytes
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    # La table de substitution inverse pour l'opération InvSubBytes
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# La fonction SubBytes remplace chaque octet de l'état par sa valeur dans la table de substitution S-Box
def sub_bytes(s):
    # Pour chaque octet de l'état
        # Remplacer l'octet par sa valeur correspondante dans la table de substitution S-Box
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

# La fonction InvSubBytes est similaire à SubBytes, mais utilise la table de substitution inverse InvS-Box
def inv_sub_bytes(s):
    # Pour chaque octet de l'état
        # Remplacer l'octet par sa valeur correspondante dans la table de substitution inverse InvS-Box
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]

# La fonction ShiftRows décale les lignes de l'état
def shift_rows(s):
    # Décaler la deuxième ligne de l'état de 1 vers la gauche
    # Décaler la troisième ligne de l'état de 2 vers la gauche
    # Décaler la quatrième ligne de l'état de 3 vers la gauche
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

# La fonction InvShiftRows est l'inverse de ShiftRows, elle décale les lignes dans l'autre sens
def inv_shift_rows(s):
    # Décaler la deuxième ligne de l'état de 1 vers la droite
    # Décaler la troisième ligne de l'état de 2 vers la droite
    # Décaler la quatrième ligne de l'état de 3 vers la droite
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

# La fonction AddRoundKey effectue une opération XOR entre l'état et la clé de tour
def add_round_key(s, k):
    # Pour chaque octet de l'état et de la clé de tour
        # Effectuer une opération XOR entre l'octet de l'état et l'octet correspondant de la clé de tour
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

# La fonction mix_single_column effectue une opération de mélange sur une colonne unique de l'état
def mix_single_column(a):
    # Calculer une série d'opérations XOR et de rotations sur les octets de la colonne
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

# La fonction mix_columns effectue une opération de mélange sur toutes les colonnes de l'état
def mix_columns(s):
     # Pour chaque colonne de l'état
        # Appeler mix_single_column sur la colonne
    for i in range(4):
        mix_single_column(s[i])

# La fonction inv_mix_columns est l'inverse de mix_columns, elle effectue l'opération de mélange inverse
def inv_mix_columns(s):
    # Pour chaque colonne de l'état
        # Calculer une série d'opérations XOR et de rotations inverses sur les octets de la colonne
        # Appeler mix_single_column sur la colonne
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

# La table de rondes R-CON pour générer les constantes de rondes
r_con = (
    # Une table de rondes utilisée pour générer les constantes de rondes
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

# La fonction bytes2matrix convertit un tableau de 16 octets en une matrice 4x4
def bytes2matrix(text):
    # Diviser le texte en blocs de 4 octets et les organiser en une matrice 4x4
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

# La fonction matrix2bytes fait l'inverse de bytes2matrix, elle convertit une matrice 4x4 en un tableau de 16 octets
def matrix2bytes(matrix):
    # Aplatir la matrice en une liste et la convertir en un tableau de 16 octets
    return bytes(sum(matrix, []))

# La fonction xor_bytes effectue une opération XOR entre deux tableaux d'octets
def xor_bytes(a, b):
    # Pour chaque octet dans les deux tableaux
        # Effectuer une opération XOR entre les octets correspondants
    return bytes(i^j for i, j in zip(a, b))

# La fonction inc_bytes incrémente la valeur d'un tableau d'octets de 1
def inc_bytes(a):
    # Pour chaque octet dans le tableau, commençant par le dernier
        # Si l'octet est égal à 0xFF, le remplacer par 0 et passer à l'octet précédent
        # Sinon, l'incrémenter de 1 et arrêter
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

# La fonction pad ajoute un padding PKCS#7 à un texte pour le rendre un multiple de 16 octets
def pad(plaintext):
    # Calculer la quantité de padding nécessaire pour que la longueur du texte soit un multiple de 16
    # Ajouter le padding à la fin du texte
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

# La fonction unpad supprime le padding PKCS#7 d'un texte
def unpad(plaintext):
    # Vérifier que le dernier octet correspond à la quantité de padding
    # Retirer le padding du texte
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

# La fonction split_blocks divise un texte en blocs de 16 octets
def split_blocks(message, block_size=16, require_padding=True):
    # Diviser le texte en blocs de la taille spécifiée
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+16] for i in range(0, len(message), block_size)]

# La classe AES implémente le chiffrement AES-128 avec différents modes de fonctionnement
class AES:
    # Le nombre de tours dépend de la taille de la clé
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        # Initialiser l'objet avec une clé principale
        # Calculer le nombre de tours en fonction de la taille de la clé
        # Étendre la clé principale en une série de matrices de clés pour chaque tour
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        # Étendre et renvoyer une liste de matrices de clés pour la clé principale donnée
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        # Chiffrer un seul bloc de texte de 16 octets
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        # Déchiffrer un seul bloc de texte chiffré de 16 octets
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        # Chiffrer un texte en utilisant le mode de chiffrement CBC
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        # Déchiffrer un texte chiffré en utilisant le mode de chiffrement CBC
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext, iv):
        # Chiffrer un texte en utilisant le mode de chiffrement PCBC
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in split_blocks(plaintext):
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.encrypt_block(xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext, iv):
        # Déchiffrer un texte chiffré en utilisant le mode de chiffrement PCBC
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext, iv):
        # Chiffrer un texte en utilisant le mode de chiffrement CFB
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext, iv):
        # Déchiffrer un texte chiffré en utilisant le mode de chiffrement CFB
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext, iv):
        """
        Cette fonction chiffre le texte en utilisant le mode OFB (Output Feedback). 
        Elle itère à travers chaque bloc de texte et effectue une opération XOR entre le bloc de texte et le chiffrement du bloc précédent. 
        Cela crée un flux de chiffrement qui est ensuite combiné avec le texte brut pour produire le texte chiffré.
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext, iv):
        """
        C'est l'inverse de encrypt_ofb, elle déchiffre le texte chiffré en effectuant une opération XOR entre chaque bloc de texte 
        chiffré et le chiffrement du bloc précédent.
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

    def encrypt_ctr(self, plaintext, iv):
        """
        Cette fonction chiffre le texte en utilisant le mode CTR (Counter). 
        Elle utilise un compteur initialisé avec le vecteur d'initialisation, et pour chaque bloc de texte, 
        elle effectue une opération XOR entre le bloc de texte et le chiffrement du compteur.
        Le compteur est ensuite incrémenté pour le bloc suivant.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        C'est l'inverse de encrypt_ctr, elle déchiffre le texte chiffré en utilisant le même processus que encrypt_ctr
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 16
IV_SIZE = 16

SALT_SIZE = 16
HMAC_SIZE = 32

def get_key_iv(password, salt, workload=100000):
    """
    Cette fonction prend un mot de passe et un sel (salt) comme entrées, et utilise PBKDF2 pour dériver les clés AES, HMAC 
    et le vecteur d'initialisation à partir du mot de passe et du sel.
    """
    stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv


def encrypt(key, plaintext, workload=100000):
    """
    Cette fonction chiffre le texte en utilisant AES-128 en mode CBC (Cipher Block Chaining), 
    puis ajoute un HMAC pour vérifier l'intégrité du texte chiffré. Elle utilise la fonction 
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    salt = os.urandom(SALT_SIZE)
    #get_key_iv pour dériver les clés et le vecteur d'initialisation à partir du mot de passe fourni.
    key, hmac_key, iv = get_key_iv(key, salt, workload)
    ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    return hmac + salt + ciphertext


def decrypt(key, ciphertext, workload=100000):
    """
    C'est l'inverse de encrypt, elle déchiffre le texte chiffré en vérifiant d'abord l'intégrité à l'aide du HMAC, 
    puis en utilisant AES-128 en mode CBC pour déchiffrer le texte.
    """

    assert len(ciphertext) % 16 == 0, "Le texte chiffré doit être composé de blocs complets de 16 octets."

    assert len(ciphertext) >= 32, """
    Le texte chiffré doit avoir une longueur minimale de 32 octets (16 octets de sel + 16 octets de bloc). Pour
    chiffrer ou déchiffrer des blocs individuels, utilisez `AES(key).decrypt_block(ciphertext)`.
    """

    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert compare_digest(hmac, expected_hmac), 'Le texte chiffré est corrompu ou altéré.'

    return AES(key).decrypt_cbc(ciphertext, iv)