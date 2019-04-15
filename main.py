import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

key = os.urandom( 32 )
nonce = os.urandom( 16 )

cipher = Cipher( algorithms.AES( key ), modes.CTR( nonce ), backend=backend )
encryptor = cipher.encryptor()
ct = encryptor.update( b"A secret message" ) + encryptor.finalize()
ct = ct.decode( 'UTF-8' )

print( f'Cipher Text: {ct}' )

decryptor = cipher.decryptor()
decryptor.update( ct ) + decryptor.finalize()