from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256
from messages import Message, MessageType, AesMode
import random
import string

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

def decrypt_private_key(pwd: str, key_name: str) -> RSA.RsaKey:
  '''
  Attempts to decrypt the private key with a given password.
  
  Returns:
    - RsaKey if password was correct
    - None if password was incorrect
  '''
  pwd_hash = pwd_to_hash(pwd)
  LOG.debug(f'Decrypting key: "{key_name}"')
  encrypted_private_key = load_encrypted_private_key(key_name)

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

def generate_session_key(length: int) -> str:
  possible_characters = string.ascii_letters + string.digits
  random_characters_list = [random.choice(possible_characters) for _ in range(length)]
  return ''.join(random_characters_list)

def encrypt_session_key(session_key: str, public_key: RSA.RsaKey) -> bytes:
  LOG.info('Using public key to encrypt the session key')
  cipher = PKCS1_OAEP.new(public_key)
  return cipher.encrypt(session_key.encode())

def decrypt_session_key(encrypted_session_key: bytes, private_key: RSA.RsaKey) -> str:
  cipher = PKCS1_OAEP.new(private_key)
  decrypted_session_key = cipher.decrypt(encrypted_session_key)
  return decrypted_session_key.decode()

def encrypt_message_data(data: bytes, session_key: str, mode: AesMode) -> bytes:
  if mode.value == AesMode.CBC.value:
    return encrypt_message_data_cbc(data, session_key)
  else:
    return encrypt_message_data_ecb(data, session_key)

def encrypt_message_data_cbc(data: bytes, session_key: str) -> bytes:
  init_vector = get_random_bytes(AES.block_size)
  cipher = AES.new(session_key.encode(), AES.MODE_CBC, init_vector)
  encrypted_bytes = cipher.encrypt(init_vector + pad(data, AES.block_size))
  return encrypted_bytes

def encrypt_message_data_ecb(data: bytes, session_key: str) -> bytes:
  cipher = AES.new(session_key.encode(), AES.MODE_ECB)
  encrypted_bytes = cipher.encrypt(pad(data, AES.block_size))
  return encrypted_bytes

def decrypt_message_data(message: Message, session_key: str) -> bytes:
  if message.mode.value == AesMode.CBC.value:
    return decrypt_message_data_cbc(message, session_key)
  else:
    return decrypt_message_data_ecb(message, session_key)

def decrypt_message_data_cbc(message: Message, session_key: str) -> bytes:
  LOG.info('Decrypting message in CBC mode.')
  init_vector = message.data[:AES.block_size]
  data = message.data[AES.block_size:]
  try:
    cipher = AES.new(session_key.encode(), AES.MODE_CBC, init_vector)
    decrypted_bytes = cipher.decrypt(data)
    unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
    return unpadded_bytes
  except:
    LOG.error('Message decryption failed (CBC)')
    return None

def decrypt_message_data_ecb(message: Message, session_key: str) -> bytes:
  LOG.info('Decrypting message in ECB mode.')
  try:
    cipher = AES.new(session_key.encode(), AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(message.data)
    unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
    return unpadded_bytes
  except:
    LOG.error('Message decryption failed (ECB)')
    return None
