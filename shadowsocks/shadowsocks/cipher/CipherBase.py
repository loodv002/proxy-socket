from .AEAD.AEAD_CipherBase import AEAD_CipherBase
from typing import Union

CipherBase = Union[AEAD_CipherBase] # TODO: | Stream_CipherBase