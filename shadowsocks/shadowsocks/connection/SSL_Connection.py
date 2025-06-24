from .Connection import Connection, Timeout
from ..utils.ByteBuffer import ByteBuffer

import ssl
import time

from typing import Optional, Callable, Dict, Any, TypeVar

SSL_Fn_Return_Type = TypeVar('SSL_Fn_Return_Type')

class SSL_Connection:
    def __init__(self, 
                 connection: Connection, 
                 target_hostname: str, 
                 ssl_context: Optional[ssl.SSLContext] = None):
        
        self.eof = False

        self.connection = connection
        self.connection.settimeout(0)

        self.downlink_buffer = ssl.MemoryBIO() # conn -> ssl_obj
        self.uplink_buffer = ssl.MemoryBIO() # ssl_obj -> conn
        self.recv_buffer = ByteBuffer() # ssl_obj -> user_app

        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True

        self.ssl_object = ssl_context.wrap_bio(
            incoming=self.downlink_buffer,
            outgoing=self.uplink_buffer,
            server_hostname=target_hostname,
        )

        self._ssl_io_wrapper(None, self.ssl_object.do_handshake)

    def _ssl_io_wrapper(self, 
                        timeout: Optional[Timeout],
                        func: Callable[..., SSL_Fn_Return_Type], 
                        *args: Any,
                        **kwargs: Any) -> Optional[SSL_Fn_Return_Type]:
        
        
        blocking = timeout is None
        timeout_expired = False
        start_time = time.time()

        while not timeout_expired:
            try:
                return func(*args, **kwargs)
            
            except ssl.SSLWantReadError: # conn -> ssl_obj
                if self.connection.eof: break
         
                downlink_data = self.connection.recv(1024)
                self.downlink_buffer.write(downlink_data)

                if self.connection.eof: self.eof = True

            except ssl.SSLWantWriteError: # ssl_obj -> conn
                # caused by uplink_buffer is full
                pass

            uplink_data = self.uplink_buffer.read()
            self.connection.send(uplink_data)
            
            if not blocking:
                timeout_expired = (time.time() - start_time) > timeout
                
    def send(self, data: bytes):
        '''Send plaintext data.'''
        self._ssl_io_wrapper(None, self.ssl_object.write, data)

    def recv(self, length: int, timeout: Optional[Timeout] = None) -> bytes:
        '''Receive SS and SSL decrypted message.

        Note that in non-blocking mode, to return data as soon as possible, at most one unit of SSL data is decrypted.

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
        received = self._ssl_io_wrapper(timeout, 
                                        self.ssl_object.read, 
                                        length, None)
        
        return received if received else b''

    def close(self):
        self.connection.close()