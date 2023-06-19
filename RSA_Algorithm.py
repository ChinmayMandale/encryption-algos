from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def decryptRSA(pvtKey, fileToDecode, decodedFile):
    pvtKey = serialization.load_pem_private_key(
        pvtKey,
        password=None,
    )
    with open(fileToDecode, 'rb') as f:
        encodedText = f.read()

    plain = pvtKey.decrypt(
        encodedText,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(decodedFile, 'wb') as f:
        f.write(plain)



def encryptRSA(pubKey, fileToEncode, encodedFile):
    with open(fileToEncode, 'rb') as f:
        plain = f.read()
    pubKey = serialization.load_pem_public_key(
        pubKey,
    )
    encodedText = pubKey.encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(encodedFile, 'wb') as f:
        f.write(encodedText)


def pairKeyGen(uploadFolder):
    pvtKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pubKey = pvtKey.public_key()

    with open(uploadFolder + 'keys/pvtKey.pem', 'wb') as f:
        f.write(pvtKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(uploadFolder + 'keys/pubKey.pem', 'wb') as f:
        f.write(pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
