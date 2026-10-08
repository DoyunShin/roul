from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

import roul.ip.radix


__all__ = ["update", "search_asn_name", "search_asn_as_ip", "ASNS", "TABLE_IPV4", "TABLE_IPV6", "UPDATED_AT", "UA"]


@dataclass(frozen=True)
class _Snapshot:
    asns: Mapping[int, str]
    table_ipv4: roul.ip.radix.RadixTree
    table_ipv6: roul.ip.radix.RadixTree
    updated_at: float


_snapshot = _Snapshot(MappingProxyType({}), roul.ip.radix.RadixTree(bit_length=32), roul.ip.radix.RadixTree(bit_length=128), 0)
UA = "ORGID orgdomain.net - orgmail@orgdomain.net"


def __getattr__(name: str) -> Mapping[int, str] | roul.ip.radix.RadixTree | float:
    """Read a legacy data attribute from the current snapshot.

    Args:
        name: The legacy attribute name.

    Returns:
        The corresponding value from the current snapshot.
    """
    snapshot = _snapshot
    attributes = {"ASNS": snapshot.asns, "TABLE_IPV4": snapshot.table_ipv4, "TABLE_IPV6": snapshot.table_ipv6, "UPDATED_AT": snapshot.updated_at}
    if name not in attributes:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return attributes[name]


# Initialize the snapshot before loading helpers that import this module.
from .bgptools import update, search_asn_name, search_asn_as_ip
