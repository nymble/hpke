""" test_hpke.py
    
"""
import os
import unittest

from aead import supported_aead_algs
from cipher_suite import supported_cipher_suites
from persona import Persona
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption


class Test_AEAD(unittest.TestCase):
    """ Test each supported AEAD algorithm. """
    def testEncryptDecryptBasic(self):
        """ Validate that:    open(seal(nonce, aad, pt)) == pt """
        for Alg in supported_aead_algs:
            
            # Example of basic AEAD usage -------------------------------------
            key = os.urandom( Alg.key_length )  # random symmetric key
            aead = Alg(key)
            aad = b'aad'
            pt = b'testing 123'
            nonce = os.urandom( aead.nonce_length )
            
            ct = aead.seal(nonce, aad, pt)
            pt2 = aead.open(nonce, aad, ct)
            
            self.assertEqual( pt, pt2 )

    def testEncryptDecryptPtLen(self):
        """ Validate encryption/decryption of various sizes of pt including null length. """
        for Alg in supported_aead_algs:
            for pt_len in range( 2*Alg.key_length ):
                key = os.urandom( Alg.key_length )
                aead = Alg(key)
                aad = b'aad'
                pt = pt_len*b'X'  # string of 'X'
                nonce = os.urandom( aead.nonce_length )

                ct = aead.seal(nonce, aad, pt)
                pt2 = aead.open(nonce, aad, ct)
                
                self.assertEqual( pt, pt2 )


class Test_Cipher_Suite(unittest.TestCase):
    """ Test every Cipher_Suite implementation. """
    def testCsEncryptDecrypt(self):
        """ Test Cipher Suite AEAD usage. """
        for Cs in supported_cipher_suites:
            
            Alg = Cs.AEAD           # ...
            
            key = os.urandom( Alg.key_length )
            aead = Alg(key)
            aad = b'aad'
            pt = b'testing 123'
            nonce = os.urandom( aead.nonce_length )
            
            ct = aead.seal(nonce, aad, pt)
            pt2 = aead.open(nonce, aad, ct)
            
            self.assertEqual( pt, pt2 )

    def testCsDH_GroupGenerateKeyPair(self):
        """ Test DH_Group method for key pair generation """
        for Cs in supported_cipher_suites:
            Dhg = Cs.DH_Group

            key_pair = Dhg.generateKeyPair()
            
            self.assertNotEqual( key_pair, None )
            
            key_pair2 = Dhg.generateKeyPair()
            self.assertNotEqual( key_pair, key_pair2 )

    def testCsGenerateKeyPair(self):
        """ Test Cs method for generateKeyPair """
        for Cs in supported_cipher_suites:
            
            key_pair =Cs.generateKeyPair()
            
            self.assertNotEqual( key_pair, None )
            
            key_pair2 = Cs.generateKeyPair()
            self.assertNotEqual( key_pair, key_pair2 )

    def testCsDH_GroupMarshaling(self):
        """ Test DH_Group marshal/unmarshal. """
        for Cs in supported_cipher_suites:
            Dhg = Cs.DH_Group
            
            key_pair = Dhg.generateKeyPair() # Generate a key pair
            key_pair2 = Dhg.generateKeyPair()
            self.assertNotEqual( key_pair, key_pair2 )

            # marshal the public key
            public_key_bytes = Dhg.marshal( key_pair.public_key )
            
            # unmarshal
            public_key_mu = Dhg.unmarshal( public_key_bytes )
            
            # re-marshal to test ...
            public_key_bytes_mum = Dhg.marshal( public_key_mu )
            
            # compare original octets to mum octets
            self.assertEqual( public_key_bytes, public_key_bytes_mum )

    def testCs_DH_Group_DH(self):
        """ Test DH_Group DH method. """
        for Cs in supported_cipher_suites:
            Dhg = Cs.DH_Group

            key_pair_1 = Dhg.generateKeyPair()
            key_pair_2 = Dhg.generateKeyPair()

            dh_secret_12 = Cs.DH_Group.dh( key_pair_1, key_pair_2.public_key )
            dh_secret_21 = Cs.DH_Group.dh( key_pair_2, key_pair_1.public_key )

            self.assertEqual( dh_secret_12, dh_secret_21 )

    def testCs_HPKE(self):
        """ Test HPKE methoda. """
        for Cs in supported_cipher_suites:
            
            my_key_pair = Cs.DH_Group.generateKeyPair()
            peer_key_pair = Cs.DH_Group.generateKeyPair()
            
            # instantiate two instances
            my_hpke = Cs.HPKE( Cs, peer_key_pair.public_key_bytes, my_key_pair )
            peer_hpke = Cs.HPKE( Cs, my_key_pair.public_key_bytes, peer_key_pair )
    
            pt = b'testing 1234'
            ct = my_hpke.wrap( pt )
            
            # ... send to peer and unwrap
            ptwu = peer_hpke.unwrap( ct )
            self.assertEqual( pt, ptwu )
            
            # two encryptions of sam message never the same ct
            ct2 = my_hpke.wrap( pt )
            self.assertNotEqual( ct, ct2 )

            # but still decrypt to pt
            pt2 = peer_hpke.unwrap( ct2 )
            self.assertEqual( pt, pt2 )

    def testCs_KDF(self):
        """ Test KDF methoda. """
        for Cs in supported_cipher_suites:
            kdf = Cs.KDF
            key1 = kdf.extract(b'salt',b'ikm')
            key2 = kdf.expand(b'asdasd',b'qweqweq', 47)
            self.assertEqual( len(key2), 47 )

    def test_Cs_HPKE_Expansion(self):
        """ Print out size expansion for each suite. """
        print("\n-------------------------------------------------------")
        print("Size expansion of HPKE encryption suites")
        print("Cipher Suite                     Key Size     Expansion")
        print("-------------------------------------------------------")
        for Cs in supported_cipher_suites:
            my_key_pair = Cs.DH_Group.generateKeyPair()
            peer_key_pair = Cs.DH_Group.generateKeyPair()
            
            # instantiate two instances
            my_hpke = Cs.HPKE( Cs, peer_key_pair.public_key_bytes, my_key_pair )
            peer_hpke = Cs.HPKE( Cs, my_key_pair.public_key_bytes, peer_key_pair )
            
            pt = b'testing 1234'
            ct = my_hpke.wrap( pt )
            print("{:34s}  {:2d}        {:5d} ".format( Cs.__name__, Cs.AEAD.key_length, len(ct)-len(pt)))
        print("-------------------------------------------------------")

class Test_Vectors(unittest.TestCase):
    def xtest_Vectors_Basic(self):
        """ Generate basic test vectors. """
        print("\n-------------------------------------------------------")
        print("\nTest Vectors")
        print("-------------------------------------------------------")
        for Cs in supported_cipher_suites:
            my_key_pair = Cs.DH_Group.generateKeyPair()
            peer_key_pair = Cs.DH_Group.generateKeyPair()
            
            # instantiate two instances
            my_hpke = Cs.HPKE( Cs, peer_key_pair.public_key_bytes, my_key_pair )
            peer_hpke = Cs.HPKE( Cs, my_key_pair.public_key_bytes, peer_key_pair )
            
            pt = b'testing 1234'
            ct = my_hpke.wrap( pt )
            print("Cipher Suite: {:s}".format( Cs.__name__ ))
            print("csi: {}".format( Cs.csi.hex() ))
            print("pkM: {}".format( my_key_pair.public_key_bytes.hex() ))
            skM = my_key_pair.private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
            print("skM: \n{}".format( skM.decode('utf8') ))
            print("pkP: {}".format( peer_key_pair.public_key_bytes.hex() ))
            print("skP: \n{}".format(peer_key_pair.private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()).decode('utf8')))
            print("pt: {}".format( pt.decode('utf8') ))
            print("ct: {}".format( ct.hex() ))
            print("-----------------------")
        print("-------------------------------------------------------")

class Test_Persona(unittest.TestCase):
    """ Test Persona class.
    """
    def testPersonaBasic(self):
        """ Basic usage tested for every cipher suite. """
        for Cs in supported_cipher_suites:
            
            alice = Persona(Cs)
            bob   = Persona(Cs)
            carol = Persona(Cs)
            
            # simple key introduction of peers
            alice.addPeer( bob.public_key_bytes, name='bob' )
            alice.addPeer( carol.public_key_bytes, name='carol' )
            
            pt  = b'Testing encryption to peers'
            ctb1  = alice.wrap('bob', pt)
            ctb2  = alice.wrap('bob', pt)
            
            self.assertNotEqual( ctb1, ctb2 )  # each ephemerally encrypted

            bob.addPeer( alice.public_key_bytes, name='alice1' )
            ptb1 = bob.unwrap( 'alice1', ctb1 )
            ptb2 = bob.unwrap( 'alice1', ctb2 )
            self.assertEqual( pt, ptb1 )
            self.assertEqual( pt, ptb2 )

            # error case
            bob.addPeer( alice.public_key_bytes, name='a' )
            try:
                pt3 = carol.unwrap( 'a', ct )         # should fail
                # assert goes here ... 
            except:
                pass

                                                                          
# Make this test module runnable from the command prompt
if __name__ == "__main__":
    unittest.main()




