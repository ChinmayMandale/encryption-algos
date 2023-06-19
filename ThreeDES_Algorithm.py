import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt3DES(ipFile, key, opFile):
    with open(ipFile, 'rb') as fin, open(opFile, 'wb') as fout:
        init_vect = fin.read(algorithms.TripleDES.block_size // 8)
        crypt = Cipher(algorithms.TripleDES(key), modes.CFB(init_vect), backend=default_backend())
        decoder = crypt.decryptor()
        while True:
            data = fin.read(4096)
            if not data:
                break
            decodedData = decoder.update(data)
            fout.write(decodedData)


def encrypt3DES(ipFile, key, opFile):
    init_vect = os.urandom(algorithms.TripleDES.block_size // 8)
    crypt = Cipher(algorithms.TripleDES(key), modes.CFB(init_vect), backend=default_backend())
    with open(ipFile, 'rb') as fin, open(opFile, 'wb') as fout:
        fout.write(init_vect)
        encoder = crypt.encryptor()
        while True:
            data = fin.read(4096)
            if not data:
                break
            encodedData = encoder.update(data)
            fout.write(encodedData)
