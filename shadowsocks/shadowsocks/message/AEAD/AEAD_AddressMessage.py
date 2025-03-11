import struct
from typing import Optional, Tuple

from .AEAD_MessageBase import AEAD_MessageBase
from ...cipher.AEAD.AEAD_CipherBase import AEAD_CipherBase
from ...cipher.CipherParamerters import CipherParamerters
from ...utils.socks_addr import *

class AEAD_AddressMessage(AEAD_MessageBase):
    def __init__(self, 
                 cipher_parameters: CipherParamerters,

                 # From plaintext
                 addr_type: SOCKS5_ADDR_TYPE = SOCKS5_ADDR_TYPE.UNKNOWN, 
                 ip_or_domain: str = '', 
                 port: int = -1,

                 # From ciphertext
                 encrypted: bytes = b''):
        
        super(AEAD_AddressMessage, self).__init__(cipher_parameters)

        self.addr_type = addr_type
        self.host = ip_or_domain
        self.port = port

        self.encrypted = encrypted

    def encrypt(self, cipher: AEAD_CipherBase):
        raw_payload = to_socks5_addr(self.addr_type, self.host, self.port)

        self.encrypted = cipher.encrypt_chunk(raw_payload)

    def decrypt(self, cipher: AEAD_CipherBase):
        raise NotImplementedError('This method should not be invoked')

    def serialize_encrypted(self) -> bytes:
        return self.encrypted
    
    @classmethod
    def try_load(cls, 
                 cipher: AEAD_CipherBase,
                 cipher_parameters: CipherParamerters, 
                 payload: bytes) -> Tuple[Optional['AEAD_AddressMessage'], int]:
        
        raise NotImplementedError('This method should not be invoked.')
