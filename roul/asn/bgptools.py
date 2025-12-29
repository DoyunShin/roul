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
_ORIGINAL_UA = "ORGID orgdomain.net - orgmail@orgdomain.net"

def update():
    if not roul.DEBUG and roul.asn.UA == _ORIGINAL_UA:
        raise ValueError("User-Agent has not been set. Please set it to a valid value before calling update()")

    new_asns: dict[int, str] = {}
    new_table_ipv4 = roul.ip.radix.RadixTree(bit_length=32)
    new_table_ipv6 = roul.ip.radix.RadixTree(bit_length=128)

    if roul.DEBUG:
        try:
            print("DEBUG: Local data loaded.")
            with open("asns.csv", "r") as f:
                _process_asn_data(f, new_asns)
            
            with open("table.jsonl", "r") as f:
                _process_table_data(f, new_table_ipv4, new_table_ipv6)
        except FileNotFoundError as e:
            print(f"DEBUG: File not found: {e}")
            raise
    else:
        with get(BGP_TOOLS_ASN_URL, headers={"User-Agent": roul.asn.UA}, stream=True) as r:
            _process_asn_data(r.iter_lines(decode_unicode=True), new_asns)

        with get(BGP_TOOLS_TABLE_URL, headers={"User-Agent": roul.asn.UA}, stream=True) as r:
            _process_table_data(r.iter_lines(decode_unicode=True), new_table_ipv4, new_table_ipv6)

    roul.asn.ASNS = new_asns
    roul.asn.TABLE_IPV4 = new_table_ipv4
    roul.asn.TABLE_IPV6 = new_table_ipv6
    roul.asn.UPDATED_AT = time.time()

def _process_asn_data(iterator, asns_dict):
    iterator = iter(iterator)
    try:
        next(iterator) # Skip header
    except StopIteration:
        return

    reader = csv.reader(iterator)
    for row in reader:
        if not row: continue
        try:
            asns_dict[int(row[0][2:])] = row[1].replace("\n", "")
        except Exception as e:
            print(f"Warning: Skipping invalid ASN line -> {row} ({e})")

def _process_table_data(iterator, table_v4, table_v6):
    for row in iterator:
        if not row: continue
        try:
            # Optimize: Manual string parsing is much faster than json.loads for simple fixed formats
            # Format expected: {"CIDR":"1.2.3.4/24","ASN":12345}
            # We look for "CIDR":" and ","ASN":
            try:
                # Fast path
                cidr_start = row.find('"CIDR":"') + 8
                cidr_end = row.find('","ASN":', cidr_start)
                if cidr_start == 7 and cidr_end != -1:
                    cidr = row[cidr_start:cidr_end]
                    # Parse ASN: from end of separator to closing brace
                    asn_str = row[cidr_end + 8:-1]
                    asn = int(asn_str)
                else:
                    raise ValueError("Pattern not matched")
            except (ValueError, IndexError):
                # Fallback
                record = json.loads(row)
                cidr = record['CIDR']
                asn = record['ASN']

            if ":" in cidr:
                table_v6.add(cidr, asn)
            else:
                table_v4.add(cidr, asn)
            
        except Exception as e:
            print(f"Warning: Skipping invalid line -> {row} ({e})")
            raise e

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
