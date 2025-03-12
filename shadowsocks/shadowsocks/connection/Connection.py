import socket
import Crypto.Random
import time

from typing import Tuple, Union, Type, Optional

from ..cipher.CipherParamerters import supported_cipher_parameters
from ..message.MessageBase import MessageBase
from ..message.AEAD import *
from ..utils.ByteBuffer import ByteBuffer
from ..utils.socks_addr import determine_addr_type

Timeout = Union[None, int]

class Connection:
    def __init__(self, 
                 SS_addr: str, 
                 SS_port: int,
                 password: str,
                 cipher_name: str,
                 target_addr: str, 
                 target_port: int,
                 ):
        
        if cipher_name not in supported_cipher_parameters: 
            raise ValueError(f'cipher_name "{cipher_name}" not supported, should be one of {list(supported_cipher_parameters.keys())}')
        
        self.cipher_parameters = supported_cipher_parameters[cipher_name]
        self.password = password
        
        self.recv_buffer = ByteBuffer()
        self.decryted_buffer = ByteBuffer()
        self.eof = False

        self.uplink_cipher = self.cipher_parameters.cipher(self.cipher_parameters)
        self.downlink_cipher = self.cipher_parameters.cipher(self.cipher_parameters)

        self._init_socket(SS_addr, SS_port)
        self._init_uplink_cipher()
        self._send_target_addr(target_addr, target_port)
        
        
    def _init_socket(self, SS_addr: str, SS_port: int):
        self.connection = socket.create_connection((SS_addr, SS_port))
        self.connection.setblocking(False)

    def _init_uplink_cipher(self, salt: bytes = None):
        uplink_salt = salt or Crypto.Random.get_random_bytes(self.cipher_parameters.salt_size)
        self.uplink_cipher.init_key(self.password, uplink_salt)
        self._send_message(AEAD_SaltMessage(self.cipher_parameters, uplink_salt))

    def _init_downlink_cipher(self, salt: bytes):
        self.downlink_cipher.init_key(self.password, salt)

    def _send_target_addr(self, target_addr: str, target_port: int):
        addr_type = determine_addr_type(target_addr)

        self._send_message(AEAD_AddressMessage(self.cipher_parameters, 
                                               addr_type,
                                               target_addr,
                                               target_port))

    def _send_message(self, message: MessageBase):
        '''Encrypt and write `message` to socket.'''
        message.encrypt(self.uplink_cipher)
        self.connection.send(message.serialize_encrypted())

    def _recv_message(self, message_type: Type[MessageBase], blocking: bool = True) -> Optional[MessageBase]:
        '''Read and decrypt message from socket

        Arguments:
            message_type -- Type of message to receive, data are loaded into it.

        Keyword Arguments:
            blocking -- block until message received complete or socket EOF. (default: {True})

        Returns:
            An `message_type` instance if loaded successfully.
        '''
        while True:
            if not self.eof: self._recv()

            max_payload_size = (2 + self.cipher_parameters.chunk_size + 
                                self.cipher_parameters.tag_size * 2)
            payload_bytes = self.recv_buffer.as_bytes(max_payload_size)
            message, n_consumed_bytes = message_type.try_load(self.downlink_cipher,
                                                              self.cipher_parameters, 
                                                              payload_bytes)
            
            if message:
                if not (message_type is AEAD_SaltMessage):
                    message.decrypt(self.downlink_cipher)
                
                self.recv_buffer.read(n_consumed_bytes)
                return message
            elif not blocking or self.eof:
                return None

    def _recv(self):
        '''Read all available data from OS buffer'''
        while True:
            try:
                received = self.connection.recv(1024)
                
                if len(received) == 0: 
                    self.eof = True
                    return
                
                self.recv_buffer.write(received)

            except BlockingIOError:
                # No currently available data in OS buffer
                break

    def send(self, data: bytes):
        '''Send plaintext data.'''

        chunk_size = self.cipher_parameters.chunk_size
        for chunk_start_idx in range(0, len(data), chunk_size):
            chunk = data[chunk_start_idx: chunk_start_idx + chunk_size]
            self._send_message(AEAD_PayloadMessage(
                self.cipher_parameters,
                chunk
            ))

    def recv(self, length: int, timeout: Timeout = None) -> bytes:
        '''Receive decrypted message.

        Note that in non-blocking mode, to return data as soon as possible, at most one extra chunk is received and decrypted.

        Arguments:
            length -- the length of message to read

        Keyword Arguments:
            timeout -- receive timeout (default: {None})
                * None: block until receive enough length or connection closed.
                * 0: non-blocking.
                * Non-negative float: receive duration in seconds.

        Returns:
            Decrypted message.
        '''        

        blocking = timeout is None
        timeout_expired = False
        start_time = time.time()

        while len(self.decryted_buffer) < length and not timeout_expired:

            message_type = (AEAD_PayloadMessage 
                            if self.downlink_cipher.key_initiated
                            else AEAD_SaltMessage)
            message = self._recv_message(message_type, blocking=blocking)

            if isinstance(message, AEAD_PayloadMessage):
                self.decryted_buffer.write(message.chunk)
            elif isinstance(message, AEAD_SaltMessage):
                self._init_downlink_cipher(message.salt)
                
            if not blocking:
                timeout_expired = (time.time() - start_time) > timeout
            
            # No message in buffer and EOF.
            if self.eof: break
        
        return self.decryted_buffer.read(length)
            
    def close(self):
        self.connection.close()