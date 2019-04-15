import os
import binascii
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


# Create 32 byte (256 bit) cipherKey to use when encrypting and decrypting message/cipher
cipherKey = os.urandom( 32 )

# Create 32 byte (256 bit) macKey to use when creating and verifying MAC during MAC and authentication stages
macKey = os.urandom( 32 )

# Create 16 byte (128 bit) nonce to use when setting CTR mode for AES in encryption/decryption stage
nonce = os.urandom( 16 )

### ENCRYPTION ###

cipher = Cipher( algorithms.AES( cipherKey ), modes.CTR( nonce ), default_backend() )	# Create the Cipher object and set the algorithm to AES-CTR
encryptor = cipher.encryptor()															# Create encryptor 
ct = encryptor.update( b"A secret message" ) + encryptor.finalize()						# Encrypt on message and finalize
ctLen = len( ct )																		# Store known length of cipher text for decryption

print( f'Cipher Text:           { b64encode( ct ).decode() }' )							# Print cipher text

##################


###    MAC     ###

h = hmac.HMAC( macKey, hashes.SHA256(), default_backend() )								# Create an HMAC object using the macKey and SHA256 hash algorithm
h.update( ct )																			# Create MAC over cipher
mac = h.finalize()																		# Finalize MAC
macLen = len( mac ) 																	# Store known length of MAC for authentication

finalCT = ct + mac 																		# Create final message by appending MAC to end of cipher text

print( f'MAC:                   { b64encode( mac ).decode() }' )						# Print MAC
print( f'Cipher Text and MAC:   { b64encode( finalCT ).decode() }' )					# Print ( ct || MAC )

##################


### VERIFY MAC ###

vh = hmac.HMAC( macKey, hashes.SHA256(), default_backend() )							# Create HMAC object using macKey and SHA256 hash algorithm
vh.update( finalCT[:ctLen] )															# Create MAC over cipher
vh.verify( finalCT[ctLen:] )															# Check if previously created MAC matches given 'mac' value

##################


### DECRYPTION ###

decipher = Cipher( algorithms.AES( cipherKey ), modes.CTR( nonce ), default_backend() )	# Create the Cipher object using AES-CTR mode
decryptor = decipher.decryptor()														# Create decryptor
mt = decryptor.update( ct ) + decryptor.finalize()										# Decrypt cipher text and finalize

print( f'\nDecrypted Text:        {mt.decode()}' )										# Print deciphered text

##################