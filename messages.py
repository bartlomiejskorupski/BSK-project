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
  def __init__(self, mode: AesMode, type: MessageType, data: bytes):
    self.mode = mode
    self.type = type
    self.size = len(data)
    self.data = data

  def __str__(self):
    return f'Message(mode={self.mode.name}, {self.type.name},  size={self.size}, data={self.data})'
  
  def to_bytes(self) -> bytes:
    mode = self.mode.value.to_bytes(1, 'big')
    type = self.type.value.encode()
    size = encode_unsigned_number(self.size)
    
    return mode + type + size + self.data

# Message is made of:
# 1 byte AESMODE
# 1 byte TYPE
# 2 bytes data size in bytes
# n bytes DATA

def data_to_messages(recv_data: bytes) -> list[Message]:
  if not len(recv_data):
    raise ValueError('No data')
  
  recv_data_size = len(recv_data)
  data_counter = 0

  messages: list[Message] = []
  while data_counter < recv_data_size:
    mode = recv_data[data_counter]
    type = recv_data[data_counter+1:data_counter+2].decode()
    size = decode_unsigned_number(recv_data[data_counter+2:data_counter+4])
    data = recv_data[data_counter+4:data_counter+4+size]

    messages.append(Message(AesMode(mode), MessageType(type), data))
    data_counter += 4+size
    LOG.debug(f'{data_counter} / {recv_data_size}')

  return messages


def encode_unsigned_number(number: int) -> bytes:
    # Ensure the number is within the valid range for 2 bytes (0 to 65535)
    if number < 0 or number > 0xFFFF:
      raise ValueError('Number is out of range for 2 bytes encoding')

    # Encode the number into 2 bytes
    byte1 = (number >> 8) & 0xFF
    byte2 = number & 0xFF

    # Return the encoded bytes as bytes
    return bytes([byte1, byte2])


def decode_unsigned_number(byte_data: bytes) -> int:
    # Ensure the bytes object has exactly 2 bytes
    if len(byte_data) != 2:
        raise ValueError('Invalid bytes length. Expected 2 bytes')

    # Decode the 2 bytes back into an unsigned number
    number = (byte_data[0] << 8) | byte_data[1]

    return number


t_data = b'\x01p\x00\x04abcd\x02m\x00\x08abcd1919\x00s\x00\x101234567890123456'
msgs = data_to_messages(t_data)
for msg in msgs:
  LOG.info(msg)
  LOG.info(msg.to_bytes())

