import unittest

from shadowsocks.utils import socks_addr

class TestUtilsSocksAddr(unittest.TestCase):
    def test_ipv4(self):
        addr = socks_addr.to_socks5_addr(
            socks_addr.SOCKS5_ADDR_TYPE.IPV4,
            '123.45.67.89',
            12345
        )
        self.assertEqual(addr, b'\x01{-CY09')
        
    def test_domain(self):
        addr = socks_addr.to_socks5_addr(
            socks_addr.SOCKS5_ADDR_TYPE.DOMAIN,
            'example.com',
            123
        )
        self.assertEqual(addr, b'\x03\x0bexample.com\x00{')

    def test_ipv6(self):
        addr = socks_addr.to_socks5_addr(
            socks_addr.SOCKS5_ADDR_TYPE.IPV6,
            '2001:0db8:85a3:08d3:1319:8a2e:0370:7344',
            256
        )
        self.assertEqual(
            addr, 
            b'\x04 \x01\r\xb8\x85\xa3\x08\xd3\x13\x19\x8a.\x03psD\x01\x00'
        )