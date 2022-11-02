""" persona.py
    
"""
class Persona:
    """ The Persona models a key pair and it's relationships to other keys.
    """
    def __init__(self, C_suite, initial_context=None):
        """ Each new Persona represents a single 'owned' key pair. The persona
            serves as a handle for all cryptographic secrets supported by the
            cipher suite.
        """
        self.cipher_suite = C_suite() # instance of Cipher_Suite
        self.key_pair = self.cipher_suite.generateKeyPair() # secret and public-key for DH_Group
        self.context = initial_context
        self.public_key = self.key_pair.public_key          # pk as opaque octet string
        self.public_key_bytes = self.key_pair.public_key_bytes
        
        self.peers = {}   # peers indexed by public key
        
        # add self to known keys
        self.addPeer(self.key_pair.public_key_bytes, name='self', intro_context=b'self' )

    def wrap(self, peer_name, plain_text, aad=None, auth=True):
        """ Use HPKE to protect data to peer by 'name' """
        assert peer_name in self.peers
        hpke = self.peers[ peer_name ].hpke
        return hpke.wrap( plain_text, aad=aad, auth=auth )     # ......... aad ..............

    def unwrap(self, peer_name, cipher_text, aad=None):
        """ Use HPKE to unwrap data from a peer."""
        hpke = self.peers[ peer_name ].hpke       # lookup hpke instance
        return hpke.unwrap(cipher_text)

    def addPeer(self, peer_key_bytes, name=None, intro_context=b''):
        """ Create a new relationship with a peer.
            The 'peer_pk' should be from a persona created with a compatible cipher suite.
            The 'name' is an optional human readable string.
            The 'intro_context' is optional information about the key and/or introduction process.
            """
        if name == None:        # local name of peer
            # defaults to readable hash(pk)
            name = self.cipher_suite.readable_pk_id( peer_pk )
        
        peer = Peer( self.cipher_suite, peer_key_bytes, self.key_pair, name=name, intro_context=intro_context )
                             
        self.peers[ name ] = peer


class Peer:
    """ The state associated with a single peer persona. This is a form of
        'security association' as it includes cryptographic state and other
        trusted attributions.
    """
    def __init__(self, cipher_suite, peer_key_bytes, my_key_pair, name=None, intro_context=b''):
        """ Create a new association based on the cipher suite.
        """
        self.cipher_suite = cipher_suite
        self.peer_key = cipher_suite.DH_Group.unmarshal(peer_key_bytes) # validates key
        self.my_key_pair = my_key_pair
        self.name = name
        self.intro_context = intro_context

        # create a new instance of HPKE protocol
        self.hpke = cipher_suite.HPKE( cipher_suite, peer_key_bytes, my_key_pair=my_key_pair, info=intro_context )

