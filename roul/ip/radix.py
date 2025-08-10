import roul.ip

import ipaddress

class RadixNode:
    def __init__(self):
        self.right: RadixNode | None = None
        self.left: RadixNode | None = None
        self.data: int = -1

class RadixTree:
    def __init__(self, bit_length: int):
        self.root = RadixNode()
        self.bit_length = bit_length

    def add(self, cidr: str, asn: int):
        ip_int = roul.ip.to_int(roul.ip.network_to_address(cidr))
        prefixlen = roul.ip.prefixlen(cidr)
        
        node = self.root
        
        for i in range(prefixlen):
            bit = (ip_int >> (self.bit_length - 1 - i)) & 1
            
            if bit == 1:
                if not node.right:
                    node.right = RadixNode()
                node = node.right
            else:
                if not node.left:
                    node.left = RadixNode()
                node = node.left
        
        node.data = asn

    def search_best(self, ip_addr: str) -> int:
        ip_int = int(ipaddress.ip_address(ip_addr))
        
        node = self.root
        last_match = None
        
        if self.root.data:
            last_match = self.root.data

        for i in range(self.bit_length):
            bit = (ip_int >> (self.bit_length - 1 - i)) & 1
            
            if bit == 1:
                node = node.right
            else:
                node = node.left
            
            if not node:
                break
            
            if node.data:
                last_match = node.data
        
        if last_match == None:
            raise ValueError("No match found")
        
        return last_match