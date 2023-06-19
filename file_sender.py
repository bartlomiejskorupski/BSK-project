from pathlib import Path
import threading
import queue
from connection.send_socket import SendSocket
from encryption import decrypt_message_data, decrypt_session_key, encrypt_message_data
from messages import Message, data_to_messages, MessageType, AesMode
from random import randint

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class FileSender(threading.Thread):

  def __init__(self, file_queue: queue.Queue, ui_queue: queue.Queue, send_queue: queue.Queue):
    super().__init__()
    self.running = True
    self.int_event = threading.Event()
    self.file_queue = file_queue
    self.ui_queue = ui_queue
    self.send_queue = send_queue

  def set_session_key(self, session_key: str):
    self.session_key = session_key

  def __del__(self):
    LOG.debug('File sender thread stopped')

  def run(self):
    LOG.debug('File sender thread started')
    while self.running:
      try:
        file_path, mode = self.file_queue.get_nowait()
        self.send_file(file_path, mode)
      except queue.Empty:
        self.int_event.wait(0.2)
        pass

  def stop(self):
    self.running = False
    self.int_event.set()

  def send_file(self, path: Path, mode: AesMode):
    with open(path, 'rb') as file:
      content = file.read()
      LOG.info(f'Sending file: {path.name}, size: {len(content)} bytes')

      begin_msg = Message(AesMode.NONE, MessageType.UI_FILE_BEGIN, path.name.encode())
      self.ui_queue.put_nowait(begin_msg)

      file_info = f'{path.name},{len(content)}'
      encrypted_file_info = encrypt_message_data(file_info.encode(), self.session_key, mode)
      file_begin_msg = Message(mode, MessageType.FILE_BEGIN, encrypted_file_info)
      LOG.debug(f'Sending file begin message')
      self.send_queue.put_nowait(file_begin_msg.to_bytes())

      max_chunk_size = 4096
      file_size = len(content)
      sent_data_size = 0

      while sent_data_size < file_size:
        chunk = content[sent_data_size:sent_data_size+max_chunk_size]
        encrypted_chunk = encrypt_message_data(chunk, self.session_key, mode)
        file_chunk_msg = Message(mode, MessageType.FILE_CHUNK, encrypted_chunk)
        self.send_queue.put_nowait(file_chunk_msg.to_bytes())
        # LOG.debug(f'Sending file chunk. Encrypted chunk size: {len(encrypted_chunk)} bytes')

        sent_data_size += max_chunk_size

        percent_str = str(min(100, int(sent_data_size*100.0/file_size)))
        ui_chunk_msg = Message(AesMode.NONE, MessageType.UI_FILE_CHUNK, percent_str.encode())
        self.ui_queue.put_nowait(ui_chunk_msg)

