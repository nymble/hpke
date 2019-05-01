""" hpke.py
    
    Loosely based on draft-barnes-cfrg-hpke-01
    
Hybrid Public Key Encryption

   Hybrid Public Key Encryption (HPKE) encrypts plain text infomation, 'pt', to a
   peer public key 'pkP'. The encryption uses an asymetric algorithm to provide
   keys that are used by a symetric cryptographic AEAD alorithm to encrypt plain
   text 'pt' into cipher text 'ct.

   Encryption follows a two-step calling sequence:
   
   1.  Set up an encryption context that is shared between the sender
       and the recipient:
   
       hpke = HPKE(cipher_suite, recipient_public_key, my_key_pair=my_key_pair)
   
   2.  Use that context to encrypt or decrypt content:
   
       ct = hpke.wrap( pt_to_send )   # encrypt to peer
   
       pt_from_peer = hpke.unwrap( recieved_ct )
   
   A HPKE context encodes the AEAD algorithm and key in use, and manages
   the nonces used so that the same nonce is not used with multiple
   plaintexts.
   
   Three modes of encapsulation are defined:

+---------+---------+
| Mode    |  Value  |
+---------+---------+  """
MODE_BASE = b'\x00'  # Ephemeral initiator to 'peer_pk', no sender authentication
MODE_PSK  = b'\x01'  # Preshared key -> not implemented!
MODE_AUTH = b'\x02'  # Authenticated encryption using 'my_key_pair' to 'peer_pk'


from struct import pack, unpack


class HPKE:
    """ Base class holding context for Hybrid Public Key Encryption (HKPE).
    """
    def __init__(self, cipher_suite, peer_key_bytes, my_key_pair=None, info=b'', salt=None):
        """ Set initial state of instance.
            'my_key_pair' is required for any unwrap operation, but may be None when using
            the unauthenticate base mode 'MODE_BASE'.
        """
        self.cipher_suite = cipher_suite
        self.peer_key     = cipher_suite.DH_Group.unmarshal( peer_key_bytes ) # validates the key
        self.my_key_pair  = my_key_pair
        self.info         = info
        self.salt         = salt

        self.snd_seq = 0                # sequence counters maintained for each direction
        self.rcv_seq = 0


class HPKE_draft_01ish(HPKE):
    """ Loosely based on draft-barnes-cfrg-hpke-01.
        Changed 'I' and 'R' notation to 'my' and 'peer'.
        Combined send and recieve into same instance.
        Added snd and rcv sequence counters, nonces and secrets.
    """
    def wrap(self, pt, aad=None, auth=True):
        """ Encrypt using AEAD the plain text 'pt' to the 'peer_pk'
            and return cipher text 'ct'.
        """
        ephemeral_key_pair = self.cipher_suite.DH_Group.generateKeyPair()    # generate the ephemeral key pair

        # definitions for for readability ...
        cs = self.cipher_suite
        marshal = cs.DH_Group.marshal
        hash_length = cs.Hash.digest_size
        info = self.info
        csi = cs.csi # octets
        pkP = self.peer_key
        skE = ephemeral_key_pair    # key pair object used in API rather than private key
        pkE = ephemeral_key_pair.public_key
        skM = self.my_key_pair      #  'M' for secret key of My key pair
        pkM = self.my_key_pair.public_key
        DH  = cs.DH_Group.dh
        KDF = cs.KDF
        Nk = cs.AEAD.key_length
        Nn = cs.AEAD.nonce_length
        
        salt = hash_length * b'\x00'  # all zero octet string
        enc = marshal( pkE )
        
        if auth:                        # authenticated
            mode = MODE_AUTH
            shared_secret = KDF.extract( salt, DH(skE, pkP) + DH(skM, pkP) )
            kemContext = enc + marshal( pkP ) + marshal( pkM )
            sci = KDF.extract( salt, csi + mode + marshal( pkP ) + marshal( pkM ) )
        else:                           # unauthenticated
            mode = MODE_BASE
            shared_secret = KDF.extract( salt, DH(skE, peer_pk) )
            kemContext = enc + marshal( pkP )
            sci = KDF.extract( salt, csi + mode + marshal( pkP ) )
        
        context = csi + mode + blen(kemContext) + kemContext + blen(info) + info

        snd_secret = KDF.expand(shared_secret, b'hpke key'   + context, Nk)
        snd_nonce  = KDF.expand(shared_secret, b'hpke nonce' + context, Nn)
        
        aead = cs.AEAD( snd_secret )
        
        snd_seq_bytes = pack( '<L', self.snd_seq )   # little-endian to simplify zero padding by bxor
        
        nonce = bxor( snd_nonce, snd_seq_bytes )
        
        ct = csi + mode + b'\00' + enc + aead.seal(nonce, aad, pt)       #

        # State changes that will impact subsequent wrap usage
        self.snd_seq += 1
        
        return ct

    def unwrap(self, ct, aad=None):
        """ Decrypt using AEAD the cipher text 'ct' sent to public key
            of 'my_key_pair' and return plain text 'pt'
        """
        # The first 'sci_size' bytes determine the required processing.
        sci_size = self.cipher_suite.sci_size
        sci = ct[ : self.cipher_suite.sci_size ]
        
        # hpke draft 01
        csi_in_ct = sci[0:2]
        assert csi_in_ct == self.cipher_suite.csi, "Cipher suite does not match expected cipher suite for peer_pk."
        mode = bytes(sci[2:3])

        # rename for for readability ....
        cs = self.cipher_suite
        marshal = cs.DH_Group.marshal
        unmarshal = cs.DH_Group.unmarshal
        pkM = self.my_key_pair.public_key   # My public key
        pkP = self.peer_key
        csi = cs.csi
        info = self.info
        skM = self.my_key_pair      #  My secret key (actually key pair, since API uses pair)
        DH  = cs.DH_Group.dh
        KDF = cs.KDF.extract
        enc_size = len( self.my_key_pair.public_key_bytes )
        hash_length = cs.Hash.digest_size
        DH  = cs.DH_Group.dh
        KDF = cs.KDF
        Nk = cs.AEAD.key_length
        Nn = cs.AEAD.nonce_length
        
        salt = hash_length * b'\x00'  # all zero octet string
        enc = ct[ sci_size : sci_size + enc_size ]
        
        pkEP = unmarshal( enc ) # ephemeral public key from peer
    
        if mode == MODE_AUTH:
            kemContext = marshal( pkEP ) + marshal( pkM ) + marshal( pkP )
            shared_secret = KDF.extract( salt, DH(skM, pkEP) + DH(skM, pkP) )
        
        elif mode == MODE_BASE:
            kemContext = marshal( pkEP ) + marshal( pkP )
            shared_secret = KDF.extract( salt, DH(skM, pkEP) )
    
        elif mode == MODE_PSK:
            raise NotImplementedError("MODE_PSK not implemented")
        else:
            raise NotImplementedError("Cipher text mode value: {} not implemented.".format(mode))

        context = csi + mode + blen(kemContext) + kemContext + blen(info) + info
        
        rcv_secret = KDF.expand(shared_secret, b'hpke key'   + context, Nk)
        rcv_nonce  = KDF.expand(shared_secret, b'hpke nonce' + context, Nn)
        
        aead = cs.AEAD( rcv_secret )
        
        rcv_seq_bytes = pack( '<L', self.rcv_seq )   #
        
        nonce = bxor( rcv_nonce, rcv_seq_bytes )
        
        pt = aead.open(nonce, aad, ct[ sci_size+enc_size: ])       #
        
        # State changes that will impact subsequent unwrap usage
        self.rcv_seq += 1

        return pt   # later need to return auth=True or False ... or pkP or None


def bxor(b1, b2):
    """ Binary XOR, appends zeros to shorter value. """
    
    # pad the shorter of the two strings on the right
    if  len(b1) > len(b2):
        b2 = b2 + (len(b1) - len(b2)) * b'\x00'
    elif len(b2) > len(b1):
        b1 = b1 + (len(b2) - len(b1)) * b'\x00'
    else:
        pass # same length byte strings

    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)

    return result

def blen( byte_string ):
    """ Convert the length of a byte string into a four byte little-endian representation.
    """
    if byte_string == None:
        return pack( '<I', 0 )
    else:
        return pack( '<I', len(byte_string) ) # pack to 4 byte unsigned integer
