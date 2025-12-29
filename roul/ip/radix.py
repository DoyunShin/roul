import roul.ip
import socket
import struct
import ipaddress

class RadixNode:
    __slots__ = ('right', 'left', 'data')
    def __init__(self):
        self.right: RadixNode | None = None
        self.left: RadixNode | None = None
        self.data: int = -1

class RadixTree:
    def __init__(self, bit_length: int):
        self.root = RadixNode()
        self.bit_length = bit_length

    def add(self, cidr: str, asn: int):
        bit_length = self.bit_length
        if '/' in cidr:
            ip_str, prefix_str = cidr.split('/', 1)
            prefixlen = int(prefix_str)
        else:
            ip_str = cidr
            prefixlen = bit_length

        if bit_length == 32:
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            except OSError:
                 ip_int = int(ipaddress.IPv4Address(ip_str))
            bits = bin(ip_int)[2:].zfill(32)
        else:
            try:
                ip_int = int.from_bytes(socket.inet_pton(socket.AF_INET6, ip_str), "big")
            except OSError:
                 ip_int = int(ipaddress.IPv6Address(ip_str))
            bits = bin(ip_int)[2:].zfill(128)
        
        node = self.root
        NodeClass = RadixNode
        
        for bit in bits[:prefixlen]:
            if bit == '1':
                if not node.right:
                    node.right = NodeClass()
                node = node.right
            else:
                if not node.left:
                    node.left = NodeClass()
                node = node.left
        
        node.data = asn

    def search_best(self, ip_addr: str) -> int:
        ip_int = int(ipaddress.ip_address(ip_addr))
        
        node = self.root
        last_match = None
        
        if self.root.data != -1:
            last_match = self.root.data

        for i in range(self.bit_length):
            bit = (ip_int >> (self.bit_length - 1 - i)) & 1
            
            if bit == 1:
                node = node.right
            else:
                node = node.left
            
            if not node:
                break
            
            if node.data != -1:
                last_match = node.data
        
        if last_match is None:
            raise ValueError("No match found")
        
        return last_match