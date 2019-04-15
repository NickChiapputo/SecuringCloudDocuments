import os
import binascii
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

### ENCRYPTION ###
cipherKey = os.urandom( 32 )						# Random 32 byte (256 bit) key
nonce = os.urandom( 16 )					# Create a nonce for the counter

cipher = Cipher( algorithms.AES( cipherKey ), modes.CTR( nonce ), default_backend() )	# Create the Cipher
encryptor = cipher.encryptor()													# Encrypt 
ct = encryptor.update( b"A secret message" ) + encryptor.finalize()

print( f'Cipher Text: {ct}' )

##################


###    MAC     ###
macKey = os.urandom( 32 )
h = hmac.HMAC( macKey, hashes.SHA256(), default_backend() )
h.update( ct )
finalCipher = h.finalize()

print( f'MAC\'d Cipher Text: {finalCipher}' )
##################


###   UNMAC    ###

##################


### DECRYPTION ###

decipher = Cipher( algorithms.AES( cipherKey ), modes.CTR( nonce ), default_backend() )	# Create the Cipher
decryptor = decipher.decryptor()
mt = decryptor.update( ct ) + decryptor.finalize()

print( f'Decrypted Text: {mt.decode()}' )

##################