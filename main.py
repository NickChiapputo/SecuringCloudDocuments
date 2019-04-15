import os
import binascii
import traceback
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# # #
# Parameters:
#	key - 32 byte (256 bit) cipher key used to encrypt and decrypt messages in AES256
#	nonce - 16 byte (128 bit) nonce used for CTR mode in AES256
#	data - Payload to encrypt
#
# This function simply uses the Cipher and algorithm functions from the 
# cryptography package to encrypt the given data using AES256 with the 
# key and nonce given as parameters. It returns the cipher text resulting
# from the encryption.
#
# Return value:
#	ct - CipherText output from AES256 encryption
# # #
def AES256encrypt( key, nonce, data ):
	cipher = Cipher( algorithms.AES( key ), modes.CTR( nonce ), default_backend() )	# Create the Cipher object and set the algorithm to AES-CTR
	encryptor = cipher.encryptor()													# Create encryptor 
	ct = encryptor.update( data ) + encryptor.finalize()							# Encrypt on data and finalize
	return ct 																		# Return cipherText

# # #
# Parameters:
#	key - 32 byte (256 bit) cipher key used to encrypt and decrypt messages in AES256
#	nonce - 16 byte (128 bit) nonce used for CTR mode in AES256
#	ct - CipherText to decrypt
#
# This function simply uses the Cipher and algorithm functions from the cryptography
# package to decrypt the given cipher text using AES256 in CTR mode with the key and
# nonce given as parameters. It returns the decrypted message.
#
# Return value:
#	message - Decrypted message from cipher text
# # #
def AES256decrypt( key, nonce, ct ):
	cipher = Cipher( algorithms.AES( key ), modes.CTR( nonce ), default_backend() )	# Create the Cipher object using AES-CTR mode
	decryptor = cipher.decryptor()													# Create decryptor
	message = decryptor.update( ct ) + decryptor.finalize()							# Decrypt cipher text and finalize
	return message 																	# Return decrypted message

# # #
# Parameters:
#	key - The key used in SHA256
# 	ct - The cipher text used as data for the hash
#
# This function uses the HMAC functionality of the cryptography package to perform
# an HMAC over the given cipher text using the given key to create the return value,
# the resulting MAC of the cipher text.
#
# Return value:
#	mac - The resulting MAC over the ciphertext
# # #
def HMAC_SHA256( key, ct ):
	h = hmac.HMAC( key, hashes.SHA256(), default_backend() ) 						# Create an HMAC object using the key and SHA256 hash algorithm
	h.update( ct ) 																	# Create MAC over cipher
	mac = h.finalize() 																# Finalize MAC
	return mac 																		# Return MAC

# # #
# Parameters:
#	key - 
#	ct - 
# 	mac - 
#
# This functions takes in a MAC key for a SHA256 hash, a cipher text, and a MAC signature.
# It calculates the MAC over the cipher text using the given key and verifies it using
# the given MAC. Return 0 if bad MAC and 1 if good MAC.
#
# Return value:
#	0 if MAC does not match and 1 if MAC matches
# # #
def HMAC_SHA256_verify( key, ct, mac ):
	verified = 1																	# By default set return value to 1 (valid MAC signature)
	try:
		vh = hmac.HMAC( key, hashes.SHA256(), default_backend() )					# Create an HMAC object using the key and SHA256 hash algorithm
		vh.update( ct )																# Create MAC over cipher text
		vh.verify( mac )															# Verify that created MAC matches given MAC
	except: 																		# Catch exception in the event that the MAC does not match
		verified = 0																# Set return value to 0 (invalid MAC signature)

	return verified																	# Return verification value



while( 1 ):
	# Show menu
	print( 	'Menu:\n' + 
			'    Encrypt\n' +
			'    Decrypt\n' +
			'    Exit\n   ' )

	userInput = input( '>> ' )

	if userInput.lower() == 'encrypt':
		cipherKey = os.urandom( 32 )												# Create 32 byte (256 bit) cipherKey to use when encrypting and decrypting message/cipher
		macKey = os.urandom( 32 )													# Create 32 byte (256 bit) macKey to use when creating and verifying MAC during MAC and authentication stages
		nonce = os.urandom( 16 )													# Create 16 byte (128 bit) nonce to use when setting CTR mode for AES in encryption/decryption stage

		# Get data from file 'thefile'
		with open( 'thefile', 'rb' ) as f:
			data = f.read()


		ct = AES256encrypt( cipherKey, nonce, data ) 								# Create cipher text from data
		ctLen = len( ct ) 															# Get length of cipher text
		#print( f'\nCipher Text:           { b64encode( ct ).decode() }' )			# Print cipher text


		mac = HMAC_SHA256( macKey, ct )												# Create MAC over cipher

		finalCT = ct + mac 															# Create final message by appending MAC to end of cipher text

		#print( f'\nMAC:                   { b64encode( mac ).decode() }' )			# Print MAC
		#print( f'\nCipher Text and MAC:   { b64encode( finalCT ).decode() }' )		# Print ( ct || MAC )


		try:
			# Write data to file
			with open( 'thefile', 'wb' ) as f:
				f.write( finalCT )

			# Store cipher key
			with open( 'ck', 'wb' ) as f:
				f.write( cipherKey )

			# Store macKey
			with open( 'mk', 'wb' ) as f:
				f.write( macKey )

			# Store nonce
			with open( 'nonce', 'wb' ) as f:
				f.write( nonce )
		except:
			print( '\n\033[1;31mUnable to write to files. \033[0mData may be corrupted.\n' )
	elif userInput.lower() == 'decrypt':
		decrypt = 1																	# By default, decryption will proceed

		try:																		# Attempt to read from files. Catch exception if unable to read
			# Read cipher text and mac from file
			with open( 'thefile', 'rb' ) as f:
				finalCT = f.read()

			# Read cipher key
			with open( 'ck', 'rb' ) as f:
				cipherKey = f.read()

			# Read MAC key
			with open( 'mk', 'rb' ) as f:
				macKey = f.read()

			# Read nonce
			with open( 'nonce', 'rb' ) as f:
				nonce = f.read()
		except:
			print( '\n\033[1;31mUnable to read from files.\033[0m\n' )					# Tell user program was unable to read from files
			decrypt = 0																# Set decrypt so that decryption does not proceed

		if decrypt:
			ctLen = len( finalCT ) - len( macKey ) 										# Calculate the length of the cipher text as the total length minus the length of the appended MAC signature

			verify = HMAC_SHA256_verify( macKey, finalCT[ :ctLen ], finalCT[ ctLen: ] )	# Verify the MAC signature using the MAC key, cipher text, and MAC signature

			if verify:
				mt = AES256decrypt( cipherKey, nonce, finalCT[ :ctLen ] )				# Decrypt the cipher text using AES256 in CTR mode

				# Write the deciphered text to the file
				with open( 'thefile', 'w' ) as f:
					f.write( mt.decode() )
				#print( f'\nDecrypted Text:        {mt.decode()}' )						# Print deciphered text					
			else:
				print( '\n\033[1;31mInvalid MAC signature\033[0m\n' )						# Tell the user the MAC signature is bad
	elif userInput.lower() == 'exit':
		exit()
	else:
		print( '\n\033[93mBad Input\033[0m\n' )
	print( '' )