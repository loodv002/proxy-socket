import socket
import Crypto.Random
import time

from typing import Tuple, Union, Type, Optional

from ..cipher.CipherParamerters import supported_cipher_parameters
from ..message.MessageBase import MessageBase
from ..message.AEAD import *
from ..utils.ByteBuffer import ByteBuffer
from ..utils.socks_addr import determine_addr_type
from ..utils.TimeoutChecker import TimeoutChecker, Timeout


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
        self.timeout = 0

        self.uplink_cipher = self.cipher_parameters.cipher(self.cipher_parameters)
        self.downlink_cipher = self.cipher_parameters.cipher(self.cipher_parameters)

        self._init_socket(SS_addr, SS_port)
        self._init_uplink_cipher()
        self._send_target_addr(target_addr, target_port)
        
        
    def _init_socket(self, SS_addr: str, SS_port: int):
        self.connection = socket.create_connection((SS_addr, SS_port))
        self.connection.setblocking(False)

    def _init_uplink_cipher(self, salt: Optional[bytes] = None):
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
    
    def _try_init_downlink_cipher(self, timeout_checker: TimeoutChecker) -> bool:
        '''Try receive salt message and init downlink cipher.

        Arguments:
            timeout -- Receive salt timeout.

        Raises:
            socket.timeout -- If timeout expired.

        Returns:
            Whether cipher initiated successfully.
        '''

        blocking = self.timeout != 0
            
        while True:
            message = self._recv_message(AEAD_SaltMessage, blocking=False)
            if isinstance(message, AEAD_SaltMessage):
                self._init_downlink_cipher(message.salt)
                return True
            
            if not blocking:
                return False
            elif timeout_checker.timeout_expired():
                raise socket.timeout
    
    def settimeout(self, timeout: Timeout):
        '''Set socket timeout.

        Arguments:
            timeout -- 0 for non-blocking, non-negtive numeric for timeout in seconds.
        '''

        self.timeout = timeout
    
    def recv(self, buffer_size: int) -> bytes:
        '''Receive data for at most `buffer_size` bytes.

        Arguments:
            buffer_size -- Maximum received data length.

        Returns:
            The received data.
        '''

        timeout_checker = TimeoutChecker(self.timeout)
        blocking = self.timeout != 0

        if (not self.downlink_cipher.key_initiated 
            and not self._try_init_downlink_cipher(timeout_checker)):
            # Non-blocking mode and salt not received.
            return b''

        while not self.decryted_buffer and not self.eof:
            if timeout_checker.timeout_expired():
                raise socket.timeout()

            message = self._recv_message(AEAD_PayloadMessage, blocking=False)
            if isinstance(message, AEAD_PayloadMessage): 
                self.decryted_buffer.write(message.chunk)
            if not blocking: break

        return self.decryted_buffer.read(buffer_size)
            
    def close(self):
        self.connection.close()