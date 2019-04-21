import os
import io
import pickle
import os.path
import binascii
import traceback

from base64 import b64encode
from base64 import b64decode

from apiclient.http import MediaFileUpload
from apiclient.http import MediaIoBaseDownload

from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ERROR = '\033[1;31m'																	# Set   ANSI color code to error color (reddish)
RESET = '\033[0m'																		# Reset ANSI color code to default color
	

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
	cipher = Cipher( algorithms.AES( key ), modes.CTR( nonce ), default_backend() )		# Create the Cipher object and set the algorithm to AES-CTR
	encryptor = cipher.encryptor()														# Create encryptor 
	ct = encryptor.update( data ) + encryptor.finalize()								# Encrypt on data and finalize
	return ct 																			# Return cipherText

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
	cipher = Cipher( algorithms.AES( key ), modes.CTR( nonce ), default_backend() )		# Create the Cipher object using AES-CTR mode
	decryptor = cipher.decryptor()														# Create decryptor
	message = decryptor.update( ct ) + decryptor.finalize()								# Decrypt cipher text and finalize
	return message 																		# Return decrypted message

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
	h = hmac.HMAC( key, hashes.SHA256(), default_backend() ) 							# Create an HMAC object using the key and SHA256 hash algorithm
	h.update( ct ) 																		# Create MAC over cipher
	mac = h.finalize() 																	# Finalize MAC
	return mac 																			# Return MAC

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
	verified = 1																		# By default set return value to 1 (valid MAC signature)
	try:
		vh = hmac.HMAC( key, hashes.SHA256(), default_backend() )						# Create an HMAC object using the key and SHA256 hash algorithm
		vh.update( ct )																	# Create MAC over cipher text
		vh.verify( mac )																# Verify that created MAC matches given MAC
	except: 																			# Catch exception in the event that the MAC does not match
		verified = 0																	# Set return value to 0 (invalid MAC signature)

	return verified																		# Return verification value


# # #
# Parameters:
#	salt - Applied slat for password based key derivation
# 	length - Length of key to generate
#
# This function returns a PBKDF value that will produce a random key of given length.
# The derive function will be called from the return value in the callee location
# using a password to generate a cryptographic key.
#
# Return value:
#	A password based key derivation function (PBKDF) suitable for generating a cryptographic key
#		of the given length
#
# # #
def generatePBK( salt, length ):
	return PBKDF2HMAC( 																	# Create PBKDF2HMAC key derivation function for cipher key
				algorithm = hashes.SHA256(),											# Use SHA256 algorithm to generate key
				length = length,														# Generate length 32 key
				salt = salt,															# Use constant salt 
				iterations = 100000,													# Use 100 000 iterations to generate key
				backend = default_backend() )											# Use default backend

# # #
# This function encrypts a local file. It then uploads the file to the user's google drive as 
# a plain text file under the same name. The file is encrypted using three user passwords for the
# cipher and nonce for AES in CTR mode and the MAC key for SH256 HMAC generation. 
# # #
def encrypt():
	filename = input( 'File to encrypt: ' ) 											# Get file name from user
	salt = ( filename + "saltsaltsaltsalt" ).encode()									# Generate unique salt by appending salt to useranme. Not incredibly secure, but more secure than a constant salt and significantly better than no salt


	try:
		# Get data from file 'thefile'
		with open( filename, 'rb' ) as f:
			data = f.read()
	except:
		print( ERROR + 'Unable to read from file ' + RESET + filename + '.' )
		return


	cKey  = generatePBK( salt, 32 ).derive( input( 'Cipher Key Password: ' ).encode() )	# Create cipher key derivation function then derive key using user given password
	mKey  = generatePBK( salt, 32 ).derive( input( 'MAC Key Password   : ' ).encode() )	# Create MAC key    derivation function then derive key using user given password
	nonce = generatePBK( salt, 16 ).derive( input( 'Nonce Password     : ' ).encode() )	# Create nonce key  derivation function then derive key using user given password


	ct = AES256encrypt( cKey, nonce, data ) 											# Create cipher text from data
	#print( f'\nCipher Text:           { b64encode( ct ).decode() }' )					# Print cipher text


	mac = HMAC_SHA256( mKey, ct )														# Create MAC over cipher


	finalCT = ct + mac 																	# Create final message by appending MAC to end of cipher text

	#print( f'\nMAC:                   { b64encode( mac ).decode() }' )					# Print MAC
	#print( f'\nCipher Text and MAC:   { b64encode( finalCT ).decode() }' )				# Print ( ct || MAC )


	try:
		# Write data to file
		with open( 'thefile', 'wb' ) as f:
			f.write( finalCT )
	except:
		print( '\n\033[1;31mUnable to write to files. '
				'\033[0mData may be corrupted.\n' )
	return


def decrypt():
	filename = input( 'File to encrypt: ' ) 											# Get file name from user
	salt = ( filename + "saltsaltsaltsalt" ).encode()									# Generate unique salt by appending salt to useranme. Not incredibly secure, but more secure than a constant salt and significantly better than no salt

	cKey  = generatePBK( salt, 32 ).derive( input( 'Cipher Key Password: ' ).encode() )	# Create cipher key derivation function then derive key using user given password
	mKey  = generatePBK( salt, 32 ).derive( input( 'MAC Key Password   : ' ).encode() )	# Create MAC key    derivation function then derive key using user given password
	nonce = generatePBK( salt, 16 ).derive( input( 'Nonce Password     : ' ).encode() )	# Create nonce key  derivation function then derive key using user given password


	try:																				# Attempt to read from files. Catch exception if unable to read
		# Read cipher text and mac from file
		with open( filename, 'rb' ) as f:
			finalCT = f.read()
	except:
		print( '\n\033[1;31mUnable to read encrypted file.\033[0m\n' )					# Tell user program was unable to read from files
		return


	ctLen = len( finalCT ) - 32 														# Calculate the length of the cipher text as the total length minus the length of the appended MAC signature

	verify = HMAC_SHA256_verify( mKey, finalCT[ :ctLen ], finalCT[ ctLen: ] )			# Verify the MAC signature using the MAC key, cipher text, and MAC signature

	if not verify:
		print( ERROR + '\nInvalid MAC signature or password' + RESET + '.' )			# Tell the user the MAC signature is bad
		return

	mt = AES256decrypt( cKey, nonce, finalCT[ :ctLen ] )								# Decrypt the cipher text using AES256 in CTR mode

	# Write the deciphered text to the file
	with open( 'thefile', 'w' ) as f:
		f.write( mt.decode() )
	
	#print( f'\nDecrypted Text:\n{ mt.decode() }' )										# Print deciphered text					
		

# # #
# This is the main function of the program. It first requests access to the user's Google Drive account
# through an automatically opening browser window. If access is granted, the main loop will commence.
#
# Inside the loop, the user is given the main menu with options to encrypt, decrypt, or exit. Encrypt will 
# send the user to the encrypt() function where a local file is chosen to be encrypted and uploaded to the 
# user's Drive account. Decrypt will send the user to the decrypt() function where a file from Drive is chosen
# to be downloaded and decrypted. Exit will simply terminate the program.
# # #
def main():


	while( 1 ):
		# Show menu
		print( 	'Menu:\n' + 
				'    Encrypt\n' +
				'    Decrypt\n' +
				'    Exit\n   ' )

		userInput = input( '>> ' )														# Prompt for user input

		if userInput.lower() == 'encrypt':
			encrypt() 																	# Encrypt the thing
		elif userInput.lower() == 'decrypt':
			decrypt()																	# Decrypt the thing
		elif userInput.lower() == 'exit':
			exit()																		# Leave this thing
		else:
			print( ERROR + 'Bad Input' + RESET + '.\n' )								# Tell user bad thing
		print( '' )																		# Print newline (thing)


# If run from console, start main method
if __name__ == '__main__':
	main()