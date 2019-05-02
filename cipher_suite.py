""" cipher_suite.py

    Class definitions for Cipher Suites.
    
    Loosely based on draft-barnes-cfrg-hpke-01
"""
from dh_group import P_256, P_521, Curve25519, Curve448
from aead import AES_GCM_128, AES_GCM_256, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA512, SHA256
from hpke import HPKE_draft_01ish
from kdf import HKDF
class DHKEM: pass # stubbed for now ...


class Cipher_Suite:
    """ Base class for the following variations in cryptographic algorithms:
    +--------+-------+------------+--------+------+------------------+
    | csi    | KEM   | DH_Group   | Hash   |  KDF | AEAD             |
    +--------+--------------------+--------+------+------------------+
    | 0x0001 | DHKEM | P_256      | SHA256 | HKDF | AES_GCM_128      |
    | 0x0002 | DHKEM | P_256      | SHA256 | HKDF | ChaCha20Poly1305 |
    | 0x0003 | DHKEM | Curve25519 | SHA256 | HKDF | AES_GCM_128      |
    | 0x0004 | DHKEM | Curve25519 | SHA256 | HKDF | ChaCha20Poly1305 |
    | 0x0005 | DHKEM | P_521      | SHA512 | HKDF | AES_GCM_128      |
    | 0x0006 | DHKEM | P_521      | SHA512 | HKDF | ChaCha20Poly1305 |
    | 0x0007 | DHKEM | Curve448   | SHA512 | HKDF | AES_GCM_128      |
    | 0x0008 | DHKEM | Curve448   | SHA512 | HKDF | ChaCha20Poly1305 |
    +--------+--------------------+--------+------+------------------+
    """
    @classmethod
    def generateKeyPair(cls):
        """ Use the DH_Group to generate a key pair. """
        return cls.DH_Group().generateKeyPair()
    
    @classmethod
    def derive_csi(cls, mask=None):
        """ Derive a csi based on the description of the cipher suite and an optional mask. """
        return self.KDF( self.__doc__, mask )

    @classmethod
    def all_supported_suites(cls):
        """ Return all supported cipher suites. """


class HPKE_Cipher_Suite(Cipher_Suite):
    """ HPKE uses DH to generate an ephemeral secret that is shared between
        the sender and the receiver, then uses this secret to generate one or
        more (key, nonce) pairs for use with an AEAD algorithm using HKDF.
    """
    KEM = DHKEM               # not used/necessary ....
    HPKE = HPKE_draft_01ish   # use same wrap/unwrap for all these suites
    sci_size = 4      # four byte security context identifier
                      # small change from draft_01 to make fields word aligned


class HPKE_P256_AES_GCM_128(HPKE_Cipher_Suite):
    """ | 0x0001 | DHKEM | P_256      | SHA256 | HKDF | AES_GCM_128      | """
    csi = b'\x00\x01'     #  0x0001
    DH_Group = P_256
    Hash = SHA256
    AEAD = AES_GCM_128
    KDF = HKDF(Hash)


class HPKE_P256_ChaCha20Poly1305(HPKE_Cipher_Suite):
    """ | 0x0002 | DHKEM | P_256      | SHA256 | HKDF | ChaCha20Poly1305 | """
    csi = b'\x00\x02'     #  0x0002
    DH_Group = P_256
    Hash = SHA256
    AEAD = ChaCha20Poly1305
    KDF = HKDF(Hash)
    

class HPKE_Curve25519_AES_GCM_128(HPKE_Cipher_Suite):
    """ | 0x0003 | DHKEM | Curve25519 | SHA256 | HKDF | AES_GCM_128      | """
    csi = b'\x00\x03'     #  0x0003
    DH_Group = Curve25519
    Hash = SHA256
    AEAD = AES_GCM_128
    KDF = HKDF(Hash)


class HPKE_Curve25519_ChaCha20Poly1305(HPKE_Cipher_Suite):
    """ | 0x0004 | DHKEM | Curve25519 | SHA256 | HKDF | ChaCha20Poly1305 | """
    csi = b'\x00\x04'     #  0x0004
    DH_Group = Curve25519
    Hash = SHA256
    AEAD = ChaCha20Poly1305
    KDF = HKDF(Hash)


class HPKE_P521_AES_GCM_256(HPKE_Cipher_Suite):
    """ | 0x0005 | DHKEM | P_521      | SHA512 | HKDF | AES_GCM_256      | """
    csi = b'\x00\x05'     #  0x0005
    DH_Group = P_521
    Hash = SHA512
    AEAD = AES_GCM_256
    KDF = HKDF(Hash)


class HPKE_P521_ChaCha20Poly1305(HPKE_Cipher_Suite):
    """ | 0x0006 | DHKEM | P_521      | SHA512 | HKDF | ChaCha20Poly1305 | """
    csi = b'\x00\x06'     #  0x0006
    DH_Group = P_521
    Hash = SHA512
    AEAD = ChaCha20Poly1305
    KDF = HKDF(Hash)


class HPKE_C448_AES_GCM_256(HPKE_Cipher_Suite):
    """ | 0x0007 | DHKEM | Curve448   | SHA512 | HKDF | AES_GCM_256      | """
    csi = b'\x00\x07'     #  0x0007
    DH_Group = Curve448
    Hash = SHA512
    AEAD = AES_GCM_256
    KDF = HKDF(Hash)


class HPKE_C448_ChaCha20Poly1305(HPKE_Cipher_Suite):
    """ | 0x0008 | DHKEM | Curve448   | SHA512 | HKDF | ChaCha20Poly1305 | """
    csi = b'\x00\x08'     #  0x0008
    DH_Group = Curve448
    Hash = SHA512
    AEAD = ChaCha20Poly1305
    KDF = HKDF(Hash)


# --- Collect all Cipher Suites in this module into a list ---
supported_cipher_suites = [HPKE_P256_AES_GCM_128,
                           HPKE_P256_ChaCha20Poly1305,
                           HPKE_Curve25519_AES_GCM_128,
                           HPKE_Curve25519_ChaCha20Poly1305,
                           HPKE_P521_AES_GCM_256,
                           HPKE_P521_ChaCha20Poly1305,
                           HPKE_C448_AES_GCM_256,
                           HPKE_C448_ChaCha20Poly1305]

""" Automated collection of cipher suites into list:

import inspect, sys

supported_cipher_suites = []

all_classes = inspect.getmembers( sys.modules[__name__],
              lambda member: inspect.isclass(member) and member.__module__ == __name__)

for name, C in all_classes:
    if C.__bases__[0].__name__ == 'HPKE_Cipher_Suite':
        supported_cipher_suites.append( C )
    else:
        pass # ignore other subclassed curves
"""

