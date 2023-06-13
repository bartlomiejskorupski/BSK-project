from enum import Enum

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

class MessageType(Enum):
  PUBLIC_KEY = 'p'
  SESSION_KEY = 's'
  MESSAGE = 'm'

class AesMode(Enum):
  NONE = 0
  ECB = 1
  CBC = 2

class Message:
  def __init__(self, type: MessageType, mode: AesMode, size: int, data: bytes):
    self.type = type
    self.mode = mode
    self.size = size
    self.data = data

  def __str__(self):
    return f'Message({self.type.name}, mode={self.mode.name}, size={self.size}, data={self.data})'

def data_to_messages(recv_data: bytes) -> list[Message]:
  if not len(recv_data):
    raise ValueError('No data')
  
  recv_data_size = len(recv_data)
  data_counter = 0

  messages: list[Message] = []
  while data_counter < recv_data_size:
    type = recv_data[data_counter:data_counter+1].decode()
    mode = recv_data[data_counter+1]
    size = decode_unsigned_number(recv_data[data_counter+2:data_counter+4])
    data = recv_data[data_counter+4:data_counter+4+size]

    messages.append(Message(MessageType(type), AesMode(mode), size, data))
    data_counter += 4+size
    LOG.debug(f'{data_counter} / {recv_data_size}')

  return messages


def encode_unsigned_number(number: int) -> bytes:
    # Ensure the number is within the valid range for 2 bytes (0 to 65535)
    if 0 < number or number > 0xFFFF:
        raise ValueError('Number is out of range for 2 bytes encoding')

    # Encode the number into 2 bytes (big-endian)
    byte1 = (number >> 8) & 0xFF
    byte2 = number & 0xFF

    # Return the encoded bytes as bytes
    return bytes([byte1, byte2])


def decode_unsigned_number(byte_data: bytes) -> int:
    # Ensure the bytes object has exactly 2 bytes
    if len(byte_data) != 2:
        raise ValueError('Invalid bytes length. Expected 2 bytes')

    # Decode the 2 bytes back into an unsigned number (big-endian)
    number = (byte_data[0] << 8) | byte_data[1]

    return number

def test_data_to_messages():
  t_data = b'p\x01\x00\x04abcdm\x01\x00\x08abcd1919'
  msgs = data_to_messages(t_data)
  for msg in msgs:
    LOG.info(msg)

