from typing import List

from ..MessageBase import MessageBase
from ...cipher.CipherParamerters import CipherParamerters
from ...cipher.AEAD.AEAD_CipherBase import AEAD_CipherBase

class AEAD_MessageBase(MessageBase):
    def __init__(self, cipher_parameters: CipherParamerters):
        super(AEAD_MessageBase, self).__init__(cipher_parameters)