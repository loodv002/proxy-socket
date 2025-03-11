from typing import Optional, Tuple

from .AEAD_MessageBase import AEAD_MessageBase
from ...cipher.AEAD.AEAD_CipherBase import AEAD_CipherBase
from ...cipher.CipherParamerters import CipherParamerters

class AEAD_PayloadMessage(AEAD_MessageBase):
    def __init__(self, 
                 cipher_parameters: CipherParamerters,

                 # From plaintext
                 chunk: bytes = b'', 

                 # From ciphertext
                 encrypted: bytes = b''):
        
        '''Constructor
        Arguments:
            cipher_parameters -- (Required)

        Keyword Arguments:
            chunk: plaintext chunk.
            encrypted: ciphertext of the whole payload.
        '''                

        super(AEAD_PayloadMessage, self).__init__(cipher_parameters)
        
        self.chunk = chunk

        self.encrypted = encrypted

    def encrypt(self, cipher: AEAD_CipherBase):
        self.encrypted = cipher.encrypt_chunk(self.chunk)

    def decrypt(self, cipher: AEAD_CipherBase):
        self.chunk = cipher.decrypt_chunk(self.encrypted)

    def serialize_encrypted(self) -> bytes:
        return self.encrypted
    
    @classmethod
    def try_load(cls, 
                 cipher: AEAD_CipherBase,
                 cipher_parameters: CipherParamerters, 
                 payload: bytes) -> Tuple[Optional['AEAD_PayloadMessage'], int]:
        
        if len(payload) < 2 + cipher_parameters.tag_size: 
            # The given payload is not long enough.
            return (None, 0)
        
        chunk_size = cipher.decrypt_chunk_size(payload[: 2 + cipher_parameters.tag_size])
        payload_size = (2 + chunk_size + cipher_parameters.tag_size * 2)

        if len(payload) < payload_size: return (None, 0)

        encrypted = payload[:payload_size]
        return (
            cls(cipher_parameters, encrypted=encrypted),
            payload_size
        )