
PRIVATE_KEYS_PATH = './keys/private/'
PUBLIC_KEYS_PATH = './keys/public'

APP_INSTANCES = {
  'A': {
    'name': 'A',
    'other': 'B',
    'address': 'localhost',
    'port': 1337,
    'send_address': 'localhost',
    'send_port': 2137,
    'private_name': 'A.key',
    'public_name': 'A.pub'
  },
  'B': {
    'name': 'B',
    'other': 'A',
    'address': 'localhost',
    'port': 2137,
    'send_address': 'localhost',
    'send_port': 1337,
    'private_name': 'B.key',
    'public_name': 'B.pub'
  }
}
