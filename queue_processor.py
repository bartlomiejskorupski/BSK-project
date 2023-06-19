from pathlib import Path
import threading
import queue
from encryption import decrypt_message_data, decrypt_session_key
from messages import Message, data_to_messages, MessageType, AesMode
from random import randint

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class QueueProcessor(threading.Thread):

  def __init__(self, receive_queue: queue.Queue, ui_queue: queue.Queue):
    super().__init__()
    self.running = True
    self.int_event = threading.Event()
    self.receive_queue = receive_queue
    self.ui_queue = ui_queue

  def set_private_key(self, private_key):
    self.private_key = private_key

  def set_session_key(self, session_key: str):
    self.session_key = session_key

  def __del__(self):
    LOG.debug('Queue processor thread stopped')

  def run(self):
    LOG.debug('Queue processor thread started')
    incomplete_data = bytes()
    while self.running:
      try:
        data: bytes = self.receive_queue.get_nowait()

        messages, incomplete_data = data_to_messages(incomplete_data + data)
        for message in messages:
          self.process_message(message)
      except queue.Empty:
        self.int_event.wait(0.2)
        pass
      

  def stop(self):
    self.running = False
    self.int_event.set()

  def process_message(self, message: Message):
    if message.type.value == MessageType.PUBLIC_KEY.value:
      LOG.info('Received PUBLIC_KEY message')
      self.ui_queue.put_nowait(message)

    if message.type.value == MessageType.SESSION_KEY.value:
      LOG.debug('Received SESSION_KEY message')
      self.session_key = decrypt_session_key(message.data, self.private_key)
      ui_msg = Message(AesMode.NONE, MessageType.SESSION_KEY, self.session_key.encode())
      self.ui_queue.put_nowait(ui_msg)

    if message.type.value == MessageType.MESSAGE.value:
      LOG.debug('Received MESSAGE')
      decrypted_message = decrypt_message_data(message, self.session_key).decode()
      if decrypted_message:
        ui_msg = Message(AesMode.NONE, MessageType.MESSAGE, decrypted_message.encode())
        self.ui_queue.put_nowait(ui_msg)

    if message.type.value == MessageType.FILE_BEGIN.value:
      LOG.debug('Received FILE_BEGIN message')
      decrypted_text = decrypt_message_data(message, self.session_key).decode()
      if not decrypted_text:
        return
      try:
        split_text = decrypted_text.split(',')
        self.received_filename = split_text[0]
        self.received_file_total_size = int(split_text[1])
        self.received_file_current_size = 0
        ui_msg = Message(AesMode.NONE, MessageType.FILE_BEGIN, decrypted_text.encode())
        self.ui_queue.put_nowait(ui_msg)

        download_path = Path('./download')
        download_path.mkdir(exist_ok=True)
        self.file_path = download_path/self.received_filename
        if self.file_path.is_file():
          random_numbers = ''.join([str(randint(0, 9)) for _ in range(10)])
          p = Path(self.received_filename)
          altered_filename = f'{p.stem}_{random_numbers}{p.suffix}'
          self.file_path = download_path/altered_filename
      except:
        LOG.error('File begin message is incorrect')

    if message.type.value == MessageType.FILE_CHUNK.value:
      # LOG.debug('Received FILE_CHUNK message')
      decrypted_chunk = decrypt_message_data(message, self.session_key)
      if not decrypted_chunk:
        return
      size_str = str(len(decrypted_chunk))
      ui_msg = Message(AesMode.NONE, MessageType.FILE_CHUNK, size_str.encode())
      self.ui_queue.put_nowait(ui_msg)

      with open(self.file_path, 'ab') as file:
        file.write(decrypted_chunk)

      if self.received_file_current_size >= self.received_file_total_size:
        LOG.info(f'Received all file bytes')
      

