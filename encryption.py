from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256

from env import PRIVATE_KEYS_PATH, PUBLIC_KEYS_PATH
import os.path

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def pwd_to_hash(pwd: str) -> bytes:
  pwd_hash = sha256(pwd.encode())
  local_key = pwd_hash.digest()
  return local_key

def load_encrypted_private_key(name: str) -> bytes:
  key_path = os.path.join(PRIVATE_KEYS_PATH, name)
  with open(key_path, 'r') as pk_file:
    return b64decode(pk_file.read())
  
def load_public_key(name: str) -> RSA.RsaKey:
  key_path = os.path.join(PUBLIC_KEYS_PATH, name)
  with open(key_path, 'r') as pk_path:
    return RSA.import_key(pk_path.read())

def decrypt_private_key(pwd: str) -> RSA.RsaKey:
  '''
  Attempts to decrypt the private key with a given password.
  
  Returns:
    - RsaKey if password was correct
    - None if password was incorrect
  '''

  pwd_hash = pwd_to_hash(pwd)
  encrypted_private_key = load_encrypted_private_key('A.key')

  init_vector = encrypted_private_key[:AES.block_size]
  data = encrypted_private_key[AES.block_size:]

  LOG.info('Decrypting the private key with AES block cipher in CBC mode')
  cipher = AES.new(pwd_hash, AES.MODE_CBC, init_vector)
  decrypted_bytes = cipher.decrypt(data)

  try:
    unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
    private_key = RSA.import_key(unpadded_bytes)
    LOG.info('Successfully decrypted the private key')
    return private_key
  except:
    LOG.error('Private key decryption failed')
    return None


