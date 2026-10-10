import csv
import ipaddress
import json
import threading
import time
from functools import partial
from types import MappingProxyType
from typing import Iterable, Iterator

from requests import Response, get

import roul
import roul.asn
import roul.ip.radix


BGP_TOOLS_ASN_URL = "https://bgp.tools/asns.csv"
BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.jsonl"
_ORIGINAL_UA = "ORGID orgdomain.net - orgmail@orgdomain.net"
_CHUNK_BYTES = 64 * 1024
_LINE_LIMIT_BYTES = 64 * 1024
_ASN_LIMIT_BYTES = 32 * 1024 * 1024
_TABLE_LIMIT_BYTES = 256 * 1024 * 1024
_ASN_RECORD_LIMIT = 250_000
_TABLE_RECORD_LIMIT = 4_000_000
_update_lock = threading.Lock()


def _iter_data_lines(chunks: Iterable[bytes], max_bytes: int, max_lines: int) -> Iterator[str]:
    total_bytes = 0
    line_count = 0
    pending = b""
    for chunk in chunks:
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise ValueError("Data exceeds the byte limit")
        lines = (pending + chunk).split(b"\n")
        pending = lines.pop()
        for line in lines:
            line_count += 1
            if line_count > max_lines:
                raise ValueError("Data exceeds the line limit")
            if len(line) > _LINE_LIMIT_BYTES:
                raise ValueError("Data exceeds the per-line byte limit")
            yield line.rstrip(b"\r").decode("utf-8")
        if len(pending) > _LINE_LIMIT_BYTES:
            raise ValueError("Data exceeds the per-line byte limit")
    if pending:
        if line_count >= max_lines:
            raise ValueError("Data exceeds the line limit")
        yield pending.rstrip(b"\r").decode("utf-8")


def _iter_file_lines(path: str, max_bytes: int, max_lines: int) -> Iterator[str]:
    with open(path, "rb") as data_file:
        yield from _iter_data_lines(iter(partial(data_file.read, _CHUNK_BYTES), b""), max_bytes, max_lines)


def _iter_response_lines(response: Response, max_bytes: int, max_lines: int) -> Iterator[str]:
    response.raise_for_status()
    yield from _iter_data_lines(response.iter_content(chunk_size=_CHUNK_BYTES), max_bytes, max_lines)


def _process_asn_data(iterator: Iterable[str], asns_dict: dict[int, str]) -> int:
    reader = csv.reader(iterator, strict=True)
    header = next(reader, None)
    if header is None or header[:2] != ["asn", "name"]:
        raise ValueError("Invalid or missing ASN CSV header")
    count = 0
    for row in reader:
        if not row:
            continue
        try:
            if len(row) < 2 or not row[0].startswith("AS"):
                raise ValueError("Expected an AS-prefixed number and name")
            asn = int(row[0][2:])
            if not 0 <= asn <= 0xFFFFFFFF:
                raise ValueError("ASN is outside the 32-bit range")
            asns_dict[asn] = row[1].replace("\n", "")
        except ValueError as error:
            raise ValueError(f"Invalid ASN record at CSV line {reader.line_num}") from error
        count += 1
    return count


def _process_table_data(iterator: Iterable[str], table_v4: roul.ip.radix.RadixTree, table_v6: roul.ip.radix.RadixTree) -> int:
    count = 0
    for line_number, row in enumerate(iterator, 1):
        if not row.strip():
            continue
        try:
            record = json.loads(row)
            cidr = record["CIDR"]
            asn = record["ASN"]
            if not isinstance(cidr, str) or type(asn) is not int or not 0 <= asn <= 0xFFFFFFFF:
                raise ValueError("Expected a CIDR string and 32-bit ASN")
            table = table_v6 if ":" in cidr else table_v4
            table.add(cidr, asn)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError(f"Invalid routing record at line {line_number}") from error
        count += 1
    return count


def update() -> None:
    """Load and validate BGP data, then publish one complete snapshot.

    Returns:
        None. Failed loads leave the previous snapshot unchanged.
    """
    user_agent = roul.asn.UA
    if not roul.DEBUG and user_agent == _ORIGINAL_UA:
        raise ValueError("User-Agent has not been set. Please set it to a valid value before calling update()")

    with _update_lock:
        new_asns: dict[int, str] = {}
        new_table_ipv4 = roul.ip.radix.RadixTree(bit_length=32)
        new_table_ipv6 = roul.ip.radix.RadixTree(bit_length=128)

        if roul.DEBUG:
            asn_count = _process_asn_data(
                _iter_file_lines("asns.csv", _ASN_LIMIT_BYTES, _ASN_RECORD_LIMIT + 1),
                new_asns,
            )
            route_count = _process_table_data(
                _iter_file_lines("table.jsonl", _TABLE_LIMIT_BYTES, _TABLE_RECORD_LIMIT),
                new_table_ipv4,
                new_table_ipv6,
            )
        else:
            with get(BGP_TOOLS_ASN_URL, headers={"User-Agent": user_agent}, stream=True, timeout=(5, 30)) as response:
                asn_count = _process_asn_data(
                    _iter_response_lines(response, _ASN_LIMIT_BYTES, _ASN_RECORD_LIMIT + 1),
                    new_asns,
                )
            with get(BGP_TOOLS_TABLE_URL, headers={"User-Agent": user_agent}, stream=True, timeout=(5, 30)) as response:
                route_count = _process_table_data(
                    _iter_response_lines(response, _TABLE_LIMIT_BYTES, _TABLE_RECORD_LIMIT),
                    new_table_ipv4,
                    new_table_ipv6,
                )

        if not asn_count or not route_count:
            raise ValueError("ASN and routing data must not be empty")

        new_table_ipv4._prepare()
        new_table_ipv6._prepare()
        roul.asn._snapshot = roul.asn._Snapshot(MappingProxyType(new_asns), new_table_ipv4, new_table_ipv6, time.time())


def search_asn_as_ip(ipaddr: str) -> int:
    """Find the ASN of an IP address in one snapshot.

    Args:
        ipaddr: The IPv4 or IPv6 address to look up.

    Returns:
        The ASN associated with the longest matching prefix.
    """
    snapshot = roul.asn._snapshot
    try:
        address = ipaddress.ip_address(ipaddr)
    except ValueError as error:
        raise ValueError("Invalid IP address") from error
    table = snapshot.table_ipv4 if address.version == 4 else snapshot.table_ipv6
    return table._search_address(address)


def search_asn_name(asn: int) -> str:
    """Find the name of an ASN in one snapshot.

    Args:
        asn: The ASN to look up.

    Returns:
        The name associated with the ASN.
    """
    snapshot = roul.asn._snapshot
    try:
        return snapshot.asns[asn]
    except KeyError as error:
        raise ValueError(f"ASN {asn} not found. It may need to update()") from error
