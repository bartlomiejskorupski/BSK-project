from enum import Enum

class MessageType(Enum):
  PUBLIC_KEY = 'p'
  SESSION_KEY = 's'
  MESSAGE = 'm'

class AesMode(Enum):
  NONE = 0
  ECB = 1
  CBC = 2

class Message:
  def __init__(self, type: MessageType, size: int, mode: AesMode, data: bytes):
    self.type = type
    self.size = size
    self.mode = mode
    self.data = data
  

def data_to_messages(data: bytes) -> list[Message]:
  pass

