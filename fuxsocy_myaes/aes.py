import configparser
import numpy as np
import os

CONFIG = {}

def read_config(filename):

    if os.path.isfile(filename):

        # global CONFIG

        # Reading configuration file
        config = configparser.ConfigParser()
        config.read(filename)

        CONFIG["global"] = {
            "s_box": config.get("SBOX","s_box"),
            "r_con": config.get("RCON", "r_con"),
            "exp1": config.get("E_TABLE", "exp1"),
            "exp2": config.get("E_TABLE", "exp2")
        }

        return True

    else:
        print("Configuration file " + filename + " not found!")
        sys.exit("Exiting.")

        return False

def sub_bytes(s):
    s_box = CONFIG["global"]["s_box"].split(',')
    s_box = [int(x, 16) for x in s_box]
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def shift(tbl, count):
    lst = tbl[:]
    for i in range(count):
        sft = lst[1:]
        sft.append(lst[0])
        lst[:] = sft[:]
    return lst

def shift_rows(s):
  count = 1
  for i in range(0,3):
    s[i] = shift(s[i], count)
    count +=1
  return s

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_columns(state):
    exp1 = CONFIG["global"]["exp1"].split(',')
    exp2 = CONFIG["global"]["exp2"].split(',')
    exp1 = [int(x, 16) for x in exp1]
    exp2 = [int(x, 16) for x in exp2]
    Nb = len(state)
    n = [word[:] for word in state]

    for i in range(Nb):
        n[i][0] = (exp1[state[i][0]] ^ exp2[state[i][1]]
                   ^ state[i][2] ^ state[i][3])
        n[i][1] = (state[i][0] ^ exp1[state[i][1]]
                   ^ exp2[state[i][2]] ^ state[i][3])
        n[i][2] = (state[i][0] ^ state[i][1]
                   ^ exp1[state[i][2]] ^ exp2[state[i][3]])
        n[i][3] = (exp2[state[i][0]] ^ state[i][1]
                   ^ state[i][2] ^ exp1[state[i][3]])

    return n

def textTomatrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrixTotext(matrix):
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(plaintext):
    
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def split_blocks(message, block_size=16):
        assert len(message) % block_size == 0
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        s_box = CONFIG["global"]["s_box"].split(',')
        s_box = [int(x, 16) for x in s_box]
        r_con = CONFIG["global"]["r_con"].split(',')
        r_con = [int(x, 16) for x in r_con]
        
        key_columns = textTomatrix(master_key)
        iteration_size = len(master_key) // 4

        columns_per_iteration = len(key_columns)
        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:
                
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1

            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[1][b] for b in word]

            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
       
        assert len(plaintext) == 16

        plain_state = textTomatrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrixTotext(plain_state)

    def cbc(self, plaintext, iv):
        
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):

            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

read_config("aes.cfg")
