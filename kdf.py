""" kdf.py
    
    Loosely based on draft-barnes-cfrg-hpke-01
"""
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDF_hazmat
from cryptography.hazmat.backends import default_backend
backend = default_backend()


class Key_Derivation_Function:
    """  """

class HKDF(Key_Derivation_Function):
    """ Base class for HMAC-based Key Derivation Function defined in RFC 5869.
    """
    def __init__(self, Hash):
        """ HKDF instance is based on the provided hash function. """
        self.Hash = Hash

    def extract(self, salt, ikm):
        """ Extract a pseudorandom key of fixed length from input
            keying material "ikm" and an optional octet string "salt"
        """
        hash_len = self.Hash.digest_size
        hkdf = HKDF_hazmat(algorithm=self.Hash(),
                           length=hash_len,
                           salt=salt,
                           info=None,
                           backend=backend)
        return hkdf.derive( ikm )
    
    def expand(self, prk, info, L, salt=None):
        """ Expand a pseudorandom key 'prk'' using
            optional string "info" into "L" bytes of output keying material.
        """
        hkdf = HKDF_hazmat(algorithm=self.Hash(),
                           length=L,
                           salt=salt,
                           info=info,
                           backend=backend)
        return hkdf.derive( prk )
