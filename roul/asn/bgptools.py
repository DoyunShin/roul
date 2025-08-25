import roul
import roul.ip
import roul.ip.radix
import roul.asn

from requests import get
import ipaddress
import json
import time
import csv


BGP_TOOLS_ASN_URL = "https://bgp.tools/asns.csv"
BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.jsonl"
UA = "ORGID orgdomain.net - orgmail@orgdomain.net"
_ORIGINAL_UA = "ORGID orgdomain.net - orgmail@orgdomain.net"

def update():
    if UA == _ORIGINAL_UA:
        raise ValueError("User-Agent has not been set. Please set it to a valid value before calling update()")

    asns = get(BGP_TOOLS_ASN_URL, headers={"User-Agent": UA}).text.splitlines()[1:]
    tables = get(BGP_TOOLS_TABLE_URL, headers={"User-Agent": UA}).text.splitlines()

    new_asns: dict[int, str] = {}
    new_table_ipv4 = roul.ip.radix.RadixTree(bit_length=32)
    new_table_ipv6 = roul.ip.radix.RadixTree(bit_length=128)

    reader = csv.reader(asns[1:])
    for row in reader:
        try:
            new_asns[int(row[0][2:])] = row[1].replace("\n", "")
        except Exception as e:
            print(f"Warning: Skipping invalid ASN line -> {row} ({e})")

    for row in tables:
        try:
            record = json.loads(row)
            cidr: str = record['CIDR']
            asn: int = record['ASN']

            if roul.ip.is_ipv4(cidr):
                new_table_ipv4.add(cidr, asn)
            elif roul.ip.is_ipv6(cidr):
                new_table_ipv6.add(cidr, asn)
            else:
                raise TypeError("Network is neither IPv4 nor IPv6")
            
        # except (json.JSONDecodeError, KeyError, ValueError) as e:
        #     print(f"Warning: Skipping invalid line -> {row} ({e})")
        except Exception as e:
            print(f"Warning: Skipping invalid line -> {row} ({e})")
            raise e


    roul.asn.ASNS = new_asns
    roul.asn.TABLE_IPV4 = new_table_ipv4
    roul.asn.TABLE_IPV6 = new_table_ipv6
    roul.asn.UPDATED_AT = time.time()

    del asns, tables

def search_asn_as_ip(ipaddr) -> int:
    """
    Find the ASN of the given IP address.

    Args:
        ipaddr (str): The IP address to find the ASN of.

    Return:
        int: The ASN of the given IP address.
    """
    if not roul.ip.is_valid(ipaddr):
        raise ValueError("Invalid IP address")
    
    ipaddr_ipnw = ipaddress.ip_address(ipaddr)

    if roul.ip.is_ipv4(ipaddr_ipnw):
        return roul.asn.TABLE_IPV4.search_best(ipaddr)
    elif roul.ip.is_ipv6(ipaddr_ipnw):
        return roul.asn.TABLE_IPV6.search_best(ipaddr)
    else:
        raise ValueError("IP address is neither IPv4 nor IPv6")

def search_asn_name(asn: int) -> str:
    """
    Search the name of the given ASN.
    """

    if asn not in roul.asn.ASNS:
        raise ValueError(f"ASN {asn} not found. It may need to update()")

    return roul.asn.ASNS[asn]
