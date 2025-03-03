import unittest
import hashlib

from shadowsocks.cipher.key_gen import EVP_BytesToKey, HKDF_SHA1

class TestCipherKeyGen(unittest.TestCase):
    def test_EVP_BytesToKey_general(self):
        key, iv = EVP_BytesToKey(b'password', b'', 16, 16, 1, hashlib.md5)
        self.assertEqual(
            key,
            b"_M\xcc;Z\xa7e\xd6\x1d\x83'\xde\xb8\x82\xcf\x99"
        )
        self.assertEqual(
            iv,
            b'+\x95\x99\n\x91Q7J\xbd\x8f\xf8\xc5\xa7\xa0\xfe\x08'
        )

    def test_EVP_BytesToKey_with_salt(self):
        key, iv = EVP_BytesToKey(b'shadowsocks', b'saltsalt', 16, 16, 1, hashlib.md5)
        self.assertEqual(
            key,
            b'\xa5@\x88&\xc7V\xf9EF\xd6Ubn\x83\xe3\xf7'
        )
        self.assertEqual(
            iv,
            b'\xa2$\xf1v>\xefp4()\xc6 \xb1\x15"\x87'
        )

    def test_EVP_BytesToKey_with_salt_rounded(self):
        key, iv = EVP_BytesToKey(b'data', b'saltsalt', 16, 16, 3, hashlib.md5)
        self.assertEqual(
            key,
            b'\xff/ \xff\xfc\x1d\x9a\xe2\x98o}u=\xf0\x91\x1a'
        )
        self.assertEqual(
            iv,
            b'\x16 \\z)\xf7\tgMw\xa23]\x13\xefi'
        )

    def test_HKDF_SHA1_general1(self):
        key = HKDF_SHA1(b'password', 16, b'random-salt', b'ss-subkey')
        self.assertEqual(
            key,
            b'd\xa3\x01\x07O\x05"\x07C\xfd\xfe\xb5\x84\xaa\x12\x16'
        )

    def test_HKDF_SHA1_general2(self):
        key = HKDF_SHA1(b'shadowsocks', 32, b'saltsalt', b'infoinfo')
        self.assertEqual(
            key,
            b"\x99\xa8\x8dZ,\xe1\x8a\xe4_\x1f\xf4J\xab\x96@_\xa9\xea\x92,\xa0\xb3$\x949\x94'\xfa\x1a\x16\xf8y"
        )