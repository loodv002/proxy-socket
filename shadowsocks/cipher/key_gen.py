import warnings
import hmac
import hashlib
from typing import Callable, Tuple

def EVP_BytesToKey(data: bytes,
                   salt: bytes,
                   key_length: int,
                   iv_length: int,
                   round: int,
                   hash_func: Callable[[bytes], bytes]) -> Tuple[bytes, bytes]:

    # https://linux.die.net/man/3/evp_bytestokey

    if len(salt) not in (0, 8):
        warnings.warn(f"EVP_BytesToKey standard salt length should be either 0 or 8, a length of {len(salt)} is given")

    def hash_rounds(data: bytes, round: int) -> bytes:
        if round == 1:
            return hash_func(data).digest()
        return hash_rounds(hash_func(data).digest(), round-1)

    D = [b'']
    length = 0
    while length < key_length + iv_length:
        D_i = hash_rounds(D[-1] + data + salt, round)
        length += len(D_i)
        D.append(D_i)

    D_concat = b''.join(D)
    key = D_concat[:key_length]
    iv = D_concat[key_length: key_length+iv_length]
    return key, iv

def HKDF_extract(ikm: bytes, 
                 hash_func: Callable[[bytes], bytes], 
                 salt: bytes = b''):
    # https://datatracker.ietf.org/doc/html/rfc5869#section-2.2

    hash_length = hash_func().digest_size
    if len(salt) == 0: salt = b'0' * hash_length
    return hmac.new(salt, ikm, hash_func).digest()


def HKDF_expand(key: bytes, 
                key_length: int, 
                hash_func: Callable[[bytes], bytes], 
                info: bytes = b'') -> bytes:
    # https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
    
    hash_length = hash_func().digest_size
    N = (key_length - 1) // hash_length + 1
    T = [b'']
    for i in range(1, N+1):
        T.append(hmac.new(key, T[-1] + info + i.to_bytes(1, 'big'), hash_func).digest())

    T_concat = b''.join(T)
    return T_concat[:key_length]

def HKDF_SHA1(ikm: bytes, key_length: int, salt: bytes, info: bytes) -> bytes:
    prk = HKDF_extract(ikm, hashlib.sha1, salt)
    return HKDF_expand(prk, key_length, hashlib.sha1, info)