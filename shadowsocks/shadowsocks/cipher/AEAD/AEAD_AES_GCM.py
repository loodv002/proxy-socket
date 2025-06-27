from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    # Avoid cyclic imports caused by importing type
    from ..CipherParamerters import CipherParamerters

from Crypto.Cipher import AES

from .AEAD_CipherBase import AEAD_CipherBase

class AEAD_AES_GCM(AEAD_CipherBase):
    def __init__(self, cipher_parameters: CipherParamerters):
        super(AEAD_AES_GCM, self).__init__(cipher_parameters)

        self.cipher_parameters = cipher_parameters

    def _encrypt(self, data: bytes) -> bytes:
        assert self.key is not None

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        ciphertext, auth_tag = cipher.encrypt_and_digest(data)
        return ciphertext + auth_tag
    
    def _decrypt(self, encrypted: bytes) -> bytes:
        assert self.key is not None

        tag_size = self.cipher_parameters.tag_size

        ciphertext, auth_tag = encrypted[:-tag_size], encrypted[-tag_size:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce, mac_len=self.cipher_parameters.tag_size)

        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)

        # TODO: ValueError: MAC check failed
        return plaintext