""" dh_groups.py
    
    An implementation of DH_Groups using the Python 'cryptography' library.
    
    Loosely based on draft-barnes-cfrg-hpke-01
"""
from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

class DH_Group:
    """ Abstract class used to wrap asymetric cryptographic operations.
    """
    @classmethod
    def generateKeyPair(cls):
        """ Factory method for key pairs of this group type. """
    
    @classmethod
    def marshal(cls, public_key):
        """ Produce an encoding of the 'public_key' object. """
    
    @classmethod
    def unmarshal(cls, public_key_bytes):
        """ Parse a fixed-length octet string to recover a public key. """
    
    @classmethod
    def dh(cls, key_pair, public_key ):
        """ Diffie-Hellman key exchange. """


class Key_Pair:
    """ Key pairs are created by DH_Groups using the generateKeyPair() class method. """
    def __init__(self, DH_Group, private_key, public_key):
        self.DH_Group = DH_Group
        self.private_key = private_key   # not a great security design ... but done for readability in hpke module
        self.public_key = public_key
        self.public_key_bytes = DH_Group.marshal(public_key)   # validates public_key


class ECC_DH_Group(DH_Group):
    """ An implementation of DH_Groups using the Python 'cryptography' library.
        The library used for the ECC groups are slightly different from the Edwards curves.
    """
    PublicKey = EllipticCurvePublicKey
    
    @classmethod
    def generateKeyPair(cls):
        """ Factory method for key pairs of this group type. """
        private_key = generate_private_key( cls.Curve, default_backend() )
        public_key = private_key.public_key()
        return Key_Pair( cls, private_key, public_key )
    
    @classmethod
    def marshal(cls, public_key):
        """ Produce an encoding of the 'public_key' object. """
        public_key_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
        return public_key_bytes  # raw uncompressed without X9.62 type byte!
    
    @classmethod
    def unmarshal(cls, public_key_bytes):
        """ Parse a fixed-length octet string to recover a public key. """
        public_key_bytes = b'\x04' + public_key_bytes # prepend ANSI X9.16 type byte as required by library
        public_key = cls.PublicKey.from_encoded_point( cls.Curve(), public_key_bytes )
        return public_key

    @classmethod
    def dh(cls, key_pair, public_key ):
        """ Diffie-Hellman key exchange.
        """
        shared_key = key_pair.private_key.exchange( ec.ECDH(), public_key )
        return shared_key


class X_DH_Group(DH_Group):
    """ An implementation of DH_Groups using the Python 'cryptography' library.
        Support for Curve25519 and Curve448 is sligthly different from ECC curves.
    """
    @classmethod
    def generateKeyPair(cls):
        """ Factory class for key pairs of this group type. """
        private_key = cls.PrivateKey.generate()
        public_key = private_key.public_key()
        return Key_Pair( cls, private_key, public_key )

    @classmethod
    def marshal(cls, public_key):
        """ Produce an encoding of the 'public_key' object. """
        public_key_bytes = public_key.public_bytes( encoding=Encoding.Raw, format=PublicFormat.Raw )
        return public_key_bytes  # raw

    @classmethod
    def unmarshal(cls, public_key_bytes):
        """ Parse a fixed-length octet string to recover a public key. """
        public_key = cls.PublicKey.from_public_bytes( public_key_bytes )
        return public_key

    @classmethod
    def dh(cls, key_pair, public_key):
        """ Diffie-Hellman key exchange. """
        shared_key = key_pair.private_key.exchange(public_key)
        return shared_key


class P_256(ECC_DH_Group):
    """  """
    Curve = SECP256R1


class P_521(ECC_DH_Group):
    """  """
    Curve = SECP521R1


class Curve25519(X_DH_Group):
    """  """
    PrivateKey = x25519.X25519PrivateKey
    PublicKey = x25519.X25519PublicKey
    

class Curve448(X_DH_Group):
    """  """
    PrivateKey = x448.X448PrivateKey
    PublicKey = x448.X448PublicKey

