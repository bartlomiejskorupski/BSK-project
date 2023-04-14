from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import sha256

def generate(local_key: bytes, private_path: str, public_path: str):
  print('Generating key pair')
  key = RSA.generate(2048)

  print('Encrypting private key with AES block cipher operating in CBC mode using local key')
  init_vector = get_random_bytes(AES.block_size)
  cipher = AES.new(local_key, AES.MODE_CBC, init_vector)
  encrypted_bytes = cipher.encrypt(init_vector + pad(key.export_key('PEM'), AES.block_size))

  ciphertext = b64encode(encrypted_bytes).decode('utf-8')
  
  print(f'Saving encrypted private key to "{private_path}"')
  with open(private_path, 'w') as private_key_file:
    private_key_file.write(ciphertext)

  print(f'Saving public key to "{public_path}"')
  public_key = key.public_key()
  with open(public_path, 'w') as public_key_file:
    public_key_file.write(public_key.export_key('PEM').decode('utf-8'))

def main():
  password = input('Enter password: ')

  print('Generating password hash')
  pwd_hash = sha256(password.encode('utf-8'))
  local_key = pwd_hash.digest()

  generate(local_key, './keys/private/A.key', './keys/public/A.pub')
  generate(local_key, './keys/private/B.key', './keys/public/B.pub')


if __name__ == '__main__':
  main()