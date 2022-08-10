from fastecdsa import ecdsa, keys
from hashlib import sha256


def ecdsa_sign_message(message, private_key):
    r, s = ecdsa.sign(message, private_key, hashfunc=sha256)
    return r, s


def ecdsa_verify_signature(self, r, s, message, public_key):
    return ecdsa.verify((r, s), message, public_key)
