from .bgptools import update, search_asn_name, search_asn_as_ip
import roul.ip.radix

import ipaddress

ASNS: dict[int, str] = {}
TABLE_IPV4: roul.ip.radix.RadixTree = roul.ip.radix.RadixTree(bit_length=32)
TABLE_IPV6: roul.ip.radix.RadixTree = roul.ip.radix.RadixTree(bit_length=128)
UPDATED_AT: float = 0