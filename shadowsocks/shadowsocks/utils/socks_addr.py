import struct
import socket
import ipaddress
import re

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
    
def determine_addr_type(ip_or_domain: str) -> SOCKS5_ADDR_TYPE:
    domain_pattern = r'^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$'
    if (re.match(domain_pattern, ip_or_domain) is not None and
        len(ip_or_domain) <= 255):
        
        return SOCKS5_ADDR_TYPE.DOMAIN

    try:
        ip_addr = ipaddress.ip_address(ip_or_domain)
        
        if isinstance(ip_addr, ipaddress.IPv4Address):
            return SOCKS5_ADDR_TYPE.IPV4
        elif isinstance(ip_addr, ipaddress.IPv6Address):
            return SOCKS5_ADDR_TYPE.IPV6
        
    except ValueError:
        pass

    return SOCKS5_ADDR_TYPE.UNKNOWN