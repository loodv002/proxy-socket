import struct
import socket

class SOCKS5_ADDR_TYPE:
    IPV4   = 0x01
    DOMAIN = 0x03
    IPV6   = 0x04

    UNKNOWN = 0xff

def to_socks5_addr(addr_type: SOCKS5_ADDR_TYPE, 
                   ip_or_domain: str,
                   port: int) -> bytes:
    
    addr = struct.pack('B', addr_type)
    
    if addr_type == SOCKS5_ADDR_TYPE.IPV4:
        addr += socket.inet_aton(ip_or_domain)
    elif addr_type == SOCKS5_ADDR_TYPE.DOMAIN:
        addr += struct.pack('B', len(ip_or_domain)) + ip_or_domain.encode()
    elif addr_type == SOCKS5_ADDR_TYPE.IPV6:
        addr += socket.inet_pton(socket.AF_INET6, ip_or_domain)

    addr += struct.pack('!H', port)
    
    return addr
    