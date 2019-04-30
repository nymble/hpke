""" aead.py
    
    Loosely based on draft-barnes-cfrg-hpke-01
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CHACHAPOLY


class AEAD:
    """ Base class for AEAD encryption instances [RFC5116]
        Has attributes:
            key_length - The length in octets of a key for this algorithm
            nonce_length - The length in octets of a nonce for this algorithm
    """
    
    def seal(self, nonce, aad, pt):
        """ Encrypt and authenticate plaintext "pt" with associated
            data "aad" using secret key "key" and nonce "nonce",
            yielding ciphertext and tag "ct"
            """
        return self.aead.encrypt(nonce, pt, aad)
    
    def open(self, nonce, aad, ct):
        """ Decrypt ciphertext "ct" using associated data "aad" with
            secret key "key" and nonce "nonce", returning plaintext
            message "pt" or the error value "OpenError"
            """
        return self.aead.decrypt(nonce, ct, aad)
    
    def __init__(self, key):
        """ Initialize instance with key """
        if len(key) != self.key_length:
            raise ValueError("Expected {} bytes for AEAD key was given ()".format(len(key), self.key_length))
        self.aead = self.AEAD_Alg(key)


class AES_GCM_128(AEAD):
    """ AES GCM 128 bits. """
    key_length = 16
    nonce_length = 12
    strength = 128
    AEAD_Alg = AESGCM


class AES_GCM_256(AEAD):
    """ AES GCM 128 bits. """
    key_length = 32
    nonce_length = 12
    strength = 256
    AEAD_Alg = AESGCM


class ChaCha20Poly1305(AEAD):
    """ AES GCM 128 bits. """
    key_length = 32
    nonce_length = 12
    strength = 256
    AEAD_Alg = CHACHAPOLY


supported_aead_algs = [AES_GCM_128, AES_GCM_256, ChaCha20Poly1305]








