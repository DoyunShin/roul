
import ipaddress

def is_valid(ipaddr: str):
    """Check if the IP address is valid."""

    try:
        if "/" in ipaddr:
            ipaddress.ip_network(ipaddr)
        else:
            ipaddress.ip_address(ipaddr)
        return True
    except ValueError:
        return False

def is_ipv4(ipaddr: str | ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network):
    """Check if the IP address is IPv4."""

    if isinstance(ipaddr, str) and is_valid(ipaddr):
        if "/" in ipaddr:
            ipaddr = ipaddress.ip_network(ipaddr)
        else:
            ipaddr = ipaddress.ip_address(ipaddr)

    try:
        return isinstance(ipaddr, ipaddress.IPv4Address) or isinstance(ipaddr, ipaddress.IPv4Network)
    except ValueError:
        return False

def is_ipv6(ipaddr: str | ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network):
    """Check if the IP address is IPv6."""

    if isinstance(ipaddr, str) and is_valid(ipaddr):
        if "/" in ipaddr:
            ipaddr = ipaddress.ip_network(ipaddr)
        else:
            ipaddr = ipaddress.ip_address(ipaddr)

    try:
        return isinstance(ipaddr, ipaddress.IPv6Address) or isinstance(ipaddr, ipaddress.IPv6Network)
    except ValueError:
        return False

def is_private(cidr: str | ipaddress.IPv4Address | ipaddress.IPv6Address):
    """
    Check if the IP address is private.

    Args:
        cidr: The IP address to check.

    Returns:
        bool: True if the IP address is private, False otherwise.
    """
    return ipaddress.ip_address(cidr).is_private

def to_int(ipaddr: str | ipaddress.IPv4Address | ipaddress.IPv6Address):
    return int(ipaddress.ip_address(ipaddr))

def to_str(ipaddr: int | ipaddress.IPv4Address | ipaddress.IPv6Address):
    return str(ipaddress.ip_address(ipaddr))

def is_in_network(ipaddr: str | int, network: str | int):
    """
    Check if the IP address is in the given network.

    Args:
        ipaddr (str | int): The IP address to check. (e.g. "1.1.1.1"))
        network (str | int): The network to check against. (e.g. "1.1.1.0/24")

    Returns:
        bool: True if the IP address is in the network, False otherwise.
    """
    return ipaddress.ip_address(ipaddr) in ipaddress.ip_network(network)

def prefixlen(cidr: str | ipaddress.IPv4Network | ipaddress.IPv6Network):
    """
    Get the prefix length of the given IP address.

    Args:
        cidr: The IP address to get the prefix length of.

    Returns:
        int: The prefix length of the given IP address.
    """
    return ipaddress.ip_network(cidr).prefixlen

def network_to_address(cidr: str | ipaddress.IPv4Network | ipaddress.IPv6Network):
    return ipaddress.ip_network(cidr).network_address
