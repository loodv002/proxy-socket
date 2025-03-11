from .CipherBase import CipherBase
from .AEAD.AEAD_AES_GCM import AEAD_AES_GCM

from typing import Type
from enum import Enum

class CIPHER_TYPE(Enum):
    STREAM = 0
    AEAD = 1

class CipherParamerters:
    def __init__(self, 
                 cipher_type: CIPHER_TYPE,
                 cipher: Type[CipherBase],
                 
                 # AEAD
                 key_size: int = -1,
                 tag_size: int = -1,
                 salt_size: int = -1,
                 nonce_size: int = -1,
                 chunk_size: int = -1,
                 
                 ):

        self.cipher_type = cipher_type
        self.cipher = cipher

        # AEAD
        self.key_size = key_size
        self.tag_size = tag_size
        self.salt_size = salt_size
        self.nonce_size = nonce_size
        self.chunk_size = chunk_size


supported_cipher_parameters = {
    'AEAD_AES_128_GCM': CipherParamerters(
        cipher_type     = CIPHER_TYPE.AEAD,
        cipher          = AEAD_AES_GCM,
        key_size        = 16,
        tag_size        = 16,
        salt_size       = 16,
        nonce_size      = 12,
        chunk_size      = 0x3fff
    ),
    'AEAD_AES_256_GCM': CipherParamerters(
        cipher_type     = CIPHER_TYPE.AEAD,
        cipher          = AEAD_AES_GCM,
        key_size        = 32,
        tag_size        = 16,
        salt_size       = 32,
        nonce_size      = 12,
        chunk_size      = 0x3fff
    ),
    # 'AEAD_CHACHA20_POLY1305': CipherParamerters(
    #     cipher_type     = CIPHER_TYPE.AEAD,
    #     cipher          = AEAD_CHACHA20_POLY1305,
    #     key_size        = 32,
    #     tag_size        = 16,
    #     salt_size       = 32,
    #     nonce_size      = 12,
    #     chunk_size      = 0x3fff
    # ),
}