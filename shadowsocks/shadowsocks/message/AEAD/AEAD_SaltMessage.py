from typing import Optional, Tuple

from .AEAD_MessageBase import AEAD_MessageBase
from ...cipher.AEAD.AEAD_CipherBase import AEAD_CipherBase
from ...cipher.CipherParamerters import CipherParamerters

class AEAD_SaltMessage(AEAD_MessageBase):
    def __init__(self, 
                 cipher_parameters: CipherParamerters, 
                 salt: bytes = b''):
        super(AEAD_SaltMessage, self).__init__(cipher_parameters)

        self.salt = salt

    def encrypt(self, cipher: AEAD_CipherBase):
        pass

    def decrypt(self, cipher: AEAD_CipherBase):
        pass

    def serialize_encrypted(self) -> bytes:
        return self.salt

    @classmethod    
    def try_load(cls, 
                 cipher: AEAD_CipherBase,
                 cipher_parameters: CipherParamerters, 
                 payload: bytes) -> Tuple[Optional['AEAD_SaltMessage'], int]:
        
        if len(payload) >= cipher_parameters.salt_size:
            salt = payload[:cipher_parameters.salt_size]
            return (
                cls(cipher_parameters, salt),
                cipher_parameters.salt_size
            )
        
        return (None, 0)