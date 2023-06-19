from queue import Queue
from threading import Event, Thread
import socket as sock
import select

import logging
logging.basicConfig()
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class ReceiveSocket(Thread):

  def __init__(self, instance, queue: Queue):
    Thread.__init__(self)
    self.address = instance['address']
    self.port = instance['port']
    self.int_event = Event()
    self.running = True
    self.message_q = queue

  def __del__(self):
    LOG.debug('Receive socket thread stopped')

  def run(self):
    LOG.info('Receive socket thread started')

    server = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    server.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
    server.setblocking(False)
    server.bind((self.address, self.port))
    server.listen(1)
    inputs = [server]
    outputs = []

    while inputs and self.running:
      readable, writable, exceptional = select.select(inputs, outputs, inputs, 0.5)
      for s in readable:
        if s is server:
          connection, client_address = s.accept()
          LOG.info(f'new connection from {client_address}')
          connection.setblocking(False)
          inputs.append(connection)
        else:
          data: bytes = s.recv(8192)
          if data:
            self.message_q.put(data)
            LOG.debug(f'Received data size: {len(data)} bytes')
            # Add output channel for response
            if s not in outputs:
              outputs.append(s)
          else:
            if s in outputs:
              outputs.remove(s)
            inputs.remove(s)
            s.close()
      for s in exceptional:
        inputs.remove(s)
        if s in outputs:
            outputs.remove(s)
        s.close()
  
  def stop(self):
    self.running = False
    self.int_event.set()
    
