from threading import Event, Thread
import socket as sock

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class ReceiveSocket(Thread):

  def __init__(self, address: str, port: int):
    Thread.__init__(self)
    self.address = address
    self.port = port
    self.int_event = Event()
    self.running = True

  def run(self):
    LOG.info('Receive socket thread started')
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as s:
      s.bind((self.address, self.port))
      s.listen()
      while self.running:
        conn, addr = s.accept()
        self.establish_connection(conn, addr[0], addr[1])

  def establish_connection(self, conn: sock.socket, address, port):
    with conn:
      LOG.info(f'Incoming connection from {address}:{port}')
      while self.running:
        data = conn.recv(1024)
        if not data:
          LOG.info('Connection terminated')
          break
        LOG.debug(f'Received data: {data.decode()}')
  
  def stop(self):
    self.running = False
    self.int_event.set()
    
