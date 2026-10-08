import bisect
import ipaddress
import threading


_MISSING = object()


class RadixTree:
    """Store IP prefixes and perform longest-prefix matching."""

    def __init__(self, bit_length: int) -> None:
        """Create a prefix lookup table for one IP address family.

        Args:
            bit_length: Address width. Use 32 for IPv4 or 128 for IPv6.

        Returns:
            None.

        Raises:
            ValueError: If bit_length is not exactly 32 or 128.
        """
        if type(bit_length) is not int or bit_length not in (32, 128):
            raise ValueError("bit_length must be 32 or 128")

        self.bit_length = bit_length
        self._version = 4 if bit_length == 32 else 6
        self._routes_by_prefix: dict[int, dict[int, int]] = {}
        self._index: tuple | None = None
        self._prepare_lock = threading.Lock()

    def add(self, cidr: str, asn: int) -> None:
        """Add or replace an IP prefix.

        Host bits are discarded. Adding the same canonical prefix again replaces
        its previous ASN.

        Args:
            cidr: IP address or CIDR prefix belonging to this table's family.
            asn: ASN returned when this prefix is the best match.

        Returns:
            None.

        Raises:
            ValueError: If cidr is invalid or belongs to another address family.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except (TypeError, ValueError) as error:
            raise ValueError(f"Invalid CIDR: {cidr}") from error

        if network.version != self._version:
            raise ValueError(f"Expected an IPv{self._version} network")

        prefix = network.prefixlen
        network_number = int(network.network_address) >> (self.bit_length - prefix)
        with self._prepare_lock:
            routes = self._routes_by_prefix.setdefault(prefix, {})
            routes[network_number] = asn
            self._index = None

    def _prepare(self) -> tuple:
        """Build and return the lookup index if the route set has changed."""
        index = self._index
        if index is not None:
            return index

        with self._prepare_lock:
            index = self._index
            if index is not None:
                return index

            if self.bit_length == 32:
                index = self._build_hash_index()
            else:
                index = self._build_interval_index()
            self._index = index
            return index

    def _build_hash_index(self) -> tuple[tuple[int, dict[int, int]], ...]:
        """Build a longest-prefix-first hash index."""
        return tuple(
            (prefix, self._routes_by_prefix[prefix].copy())
            for prefix in sorted(self._routes_by_prefix, reverse=True)
        )

    def _build_interval_index(self) -> tuple[list[int], list[int], list[int]]:
        """Compile nested CIDR routes into disjoint result intervals."""
        routes = [
            (
                network_number << (self.bit_length - prefix),
                ((network_number + 1) << (self.bit_length - prefix)) - 1,
                prefix,
                asn,
            )
            for prefix, networks in self._routes_by_prefix.items()
            for network_number, asn in networks.items()
        ]
        routes.sort(key=lambda route: (route[0], route[2]))

        starts: list[int] = []
        ends: list[int] = []
        values: list[int] = []
        stack: list[tuple[int, int, int, int]] = []

        def add_interval(start: int, end: int, asn: int) -> None:
            if start > end:
                return
            if values and values[-1] == asn and ends[-1] + 1 == start:
                ends[-1] = end
                return
            starts.append(start)
            ends.append(end)
            values.append(asn)

        def finish_route() -> None:
            _, end, cursor, asn = stack.pop()
            add_interval(cursor, end, asn)

        # CIDR ranges are either nested or disjoint. Emit the parent gaps around
        # each child while walking the routes in network and prefix order.
        for start, end, _, asn in routes:
            while stack and start > stack[-1][1]:
                finish_route()

            if stack:
                parent_start, parent_end, parent_cursor, parent_asn = stack[-1]
                add_interval(parent_cursor, start - 1, parent_asn)
                stack[-1] = (parent_start, parent_end, end + 1, parent_asn)

            stack.append((start, end, start, asn))

        while stack:
            finish_route()

        return starts, ends, values

    def _search_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
        """Find the ASN for an already parsed IP address."""
        if address.version != self._version:
            raise ValueError(f"Expected an IPv{self._version} address")

        index = self._prepare()
        address_number = int(address)

        if self.bit_length == 32:
            for prefix, routes in index:
                asn = routes.get(address_number >> (self.bit_length - prefix), _MISSING)
                if asn is not _MISSING:
                    return asn
        else:
            starts, ends, values = index
            position = bisect.bisect_right(starts, address_number) - 1
            if position >= 0 and address_number <= ends[position]:
                return values[position]

        raise ValueError("No match found")

    def search_best(self, ip_addr: str) -> int:
        """Find the ASN of the longest prefix matching an IP address.

        Args:
            ip_addr: IPv4 or IPv6 address belonging to this table's family.

        Returns:
            ASN stored for the longest matching prefix.

        Raises:
            ValueError: If the address is invalid, belongs to another family, or
                has no matching prefix.
        """
        try:
            address = ipaddress.ip_address(ip_addr)
        except (TypeError, ValueError) as error:
            raise ValueError(f"Invalid IP address: {ip_addr}") from error
        return self._search_address(address)
