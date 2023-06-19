from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



def decryptAES256(key, ipFile, opFile):
    init_vect = b"abcdefghijklmnop"
    crypt = Cipher(algorithms.AES(key), modes.CBC(init_vect), backend=default_backend())
    decoder = crypt.decryptor()
    with open(ipFile, "rb") as ipFile:
        ipData = ipFile.read()
    decodedData = decoder.update(ipData) + decoder.finalize()
    strippedData = unpadData(decodedData)
    with open(opFile, "wb") as output_file:
        output_file.write(strippedData)



def encryptAES256(ipFile, opFile):
    init_vect = b"abcdefghijklmnop"
    fernetKey = Fernet.generate_key()[:32]
    crypt = Cipher(algorithms.AES(fernetKey), modes.CBC(init_vect), backend=default_backend())
    encoder = crypt.encryptor()
    with open(ipFile, "rb") as ipFile:
        ipData = ipFile.read()
    padData = padInputData(ipData)
    encodedData = encoder.update(padData) + encoder.finalize()
    with open(opFile, "wb") as opFile:
        opFile.write(encodedData)
    return fernetKey



def decryptAES128(key, ipFile, opFile):
    fernetKey = Fernet(key)
    with open(ipFile, "rb") as ipFile:
        ipData = ipFile.read()
    decodedData = fernetKey.decrypt(ipData)
    strippedData = unpadData(decodedData)
    with open(opFile, "wb") as opFile:
        opFile.write(strippedData)

def encryptAES128(ipFile, opFile):
    key = Fernet.generate_key()[:44]
    fernetKey = Fernet(key)
    with open(ipFile, "rb") as ipFile:
        ipData = ipFile.read()
    paddedData = padInputData(ipData)
    encryptData = fernetKey.encrypt(paddedData)
    with open(opFile, "wb") as opFile:
        opFile.write(encryptData)
    return key

def unpadData(text):
    padSize = text[-1]
    return text[:-padSize]

def padInputData(inputData):
    block = 16
    padSize = block - len(inputData) % block
    padding = bytes([padSize] * padSize)
    return inputData + padding

