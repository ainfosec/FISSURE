from fastecdsa import keys, curve, ecdsa
from fastecdsa.keys import import_key, export_key
from hashlib import sha256
import os

if __name__ == "__main__":
    
    publicKeyPathRoot = os.getcwd() + "/keys/"
    privateKeyPathRoot = os.getcwd() + "/keys/"
    
    for i in range(0,10):
        privateKey, publicKey = keys.gen_keypair(curve.P256)
    
        privateKeyPath = privateKeyPathRoot + "/" + str(i) + "/p256.key"
        publicKeyPath = publicKeyPathRoot + "/" + str(i) + "/p256.pub"
    
        export_key(privateKey, curve=curve.P256, filepath=privateKeyPath)
        export_key(publicKey, curve=curve.P256, filepath=publicKeyPath)
