from abc import ABC, abstractmethod

from typing import Optional, Tuple

from ..cipher.AEAD import AEAD_CipherBase
from ..cipher.CipherParamerters import CipherParamerters
from ..cipher.CipherBase import CipherBase

class MessageBase(ABC):
    def __init__(self, cipher_parameters: CipherParamerters):
        self.cipher_parameters = cipher_parameters

    @abstractmethod
    def encrypt(self, cipher: CipherBase):
        '''Encrypt attributes into payload'''
        pass

    @abstractmethod
    def decrypt(self, cipher: CipherBase):
        '''Decrypt attributes from payload bytes'''
        pass

    @abstractmethod
    def serialize_encrypted(self) -> bytes:
        '''Return serialized encrypted attributes.'''
        pass
    
    @classmethod
    @abstractmethod
    def try_load(cls, 
                 cipher: CipherBase,
                 cipher_parameters: CipherParamerters, 
                 payload: bytes) -> Tuple[Optional['MessageBase'], int]:
        '''Try to construct message from bytes. 

        Arguments:
            cipher_parameters -- cipher_parameters for constructing message.
            payload -- raw bytes of message.

        Returns:
            (message_instance, n_consumed_bytes)
            * `message_instance`: is a message instance if loaded successfully, None, otherwise.
            * `n_consumed_bytes`: number of bytes consumed in this message.
        '''        

        '''Try to construct message from bytes. 
        
        Return an instance if loaded successfully.'''
        pass