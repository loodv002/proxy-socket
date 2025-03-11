from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    # Avoid cyclic imports caused by importing type
    from ..CipherParamerters import CipherParamerters

import struct
from abc import ABC, abstractmethod
from hashlib import md5

from ..key_gen import *


class AEAD_CipherBase(ABC):
    def __init__(self, cipher_parameters: CipherParamerters):
        self.cipher_parameters = cipher_parameters

        self.key: bytes = None
        self.key_initiated = False
        self._nonce = bytearray(cipher_parameters.nonce_size)

    def init_key(self, password: str, session_salt: bytes):
        mainKey, _ = EVP_BytesToKey(
            data = password,
            salt = b'',
            round = 1,
            hash_func = md5,
            key_length = self.cipher_parameters.key_size,
            iv_length = 0
        )
        self.key = HKDF_SHA1(
            ikm = mainKey, 
            salt = session_salt,
            info = b'ss-subkey',
            key_length = self.cipher_parameters.key_size
        )
        self.key_initiated = True

    @property
    def nonce(self):
        return bytes(self._nonce)

    def increase_nonce(self):
        for i, v in enumerate(self._nonce):
            self._nonce[i] = (v + 1) & 0xff
            if self._nonce[i]: break

    def encrypt_chunk(self, chunk: bytes) -> bytes:
        if len(chunk) > self.cipher_parameters.chunk_size: 
            raise ValueError('The given chunk is too large.')
        
        payload = bytearray()
        chunk_size_bytes = struct.pack('!H', len(chunk))
        
        payload += self._encrypt(chunk_size_bytes)
        self.increase_nonce()
        payload += self._encrypt(chunk)
        self.increase_nonce()

        return payload
    
    def decrypt_chunk(self, payload: bytes) -> bytes:
        chunk_size_bytes = payload[: 2 + self.cipher_parameters.tag_size]
        chunk_size = self.decrypt_chunk_size(chunk_size_bytes)
        
        if len(payload) != (2 + 2 * self.cipher_parameters.tag_size + chunk_size):
            raise ValueError('The given payload size mismatch.')

        self.increase_nonce()

        chunk_bytes = payload[2 + self.cipher_parameters.tag_size:]
        chunk = self._decrypt(chunk_bytes)
        self.increase_nonce()

        return chunk
        
    def decrypt_chunk_size(self, chunk_size_bytes: bytes) -> int:
        if len(chunk_size_bytes) != (2 + self.cipher_parameters.tag_size):
            raise ValueError('The given `chunk_size` segment size mismatch.')
        return struct.unpack('!H', self._decrypt(chunk_size_bytes))[0]

    @abstractmethod
    def _encrypt(self, data: bytes) -> bytes:
        '''Encrypt `data` and generate authenticate tag'''
        pass

    @abstractmethod
    def _decrypt(self, data_and_auth_tag: bytes) -> bytes:
        '''Decrypt `data` and verify authenticate tag'''
        pass