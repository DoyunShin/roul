import ipaddress
import random
import unittest

from roul.ip.radix import RadixTree


class RadixTreeTest(unittest.TestCase):
    def test_constructor_rejects_invalid_bit_lengths(self) -> None:
        for bit_length in (0, 31, 64, 129, True, 32.0, "32"):
            with self.subTest(bit_length=bit_length):
                with self.assertRaisesRegex(ValueError, "bit_length must be 32 or 128"):
                    RadixTree(bit_length)

    def test_ipv4_longest_prefix_and_duplicate_replacement(self) -> None:
        table = RadixTree(32)
        table.add("0.0.0.0/0", 1)
        table.add("192.0.2.129/24", 2)
        table.add("192.0.2.128/25", 3)
        table.add("192.0.2.255/25", 4)

        self.assertEqual(table.search_best("198.51.100.1"), 1)
        self.assertEqual(table.search_best("192.0.2.1"), 2)
        self.assertEqual(table.search_best("192.0.2.200"), 4)

    def test_ipv6_longest_prefix_and_duplicate_replacement(self) -> None:
        table = RadixTree(128)
        table.add("::/0", 1)
        table.add("2001:db8::1/32", 2)
        table.add("2001:db8:1::/48", 3)
        table.add("2001:db8:1:ffff::/48", 4)

        self.assertEqual(table.search_best("2001:4860::1"), 1)
        self.assertEqual(table.search_best("2001:db8:2::1"), 2)
        self.assertEqual(table.search_best("2001:db8:1::1"), 4)

    def test_add_after_search_rebuilds_the_index(self) -> None:
        for bit_length, broad, narrow, address in (
            (32, "10.0.0.0/8", "10.1.0.0/16", "10.1.2.3"),
            (128, "2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1"),
        ):
            with self.subTest(bit_length=bit_length):
                table = RadixTree(bit_length)
                table.add(broad, 1)
                self.assertEqual(table.search_best(address), 1)
                table.add(narrow, 2)
                self.assertEqual(table.search_best(address), 2)

    def test_search_keeps_the_prepared_index_if_add_replaces_a_route(self) -> None:
        for bit_length, route, address in (
            (32, "10.0.0.0/8", ipaddress.IPv4Address("10.1.2.3")),
            (128, "2001:db8::/32", ipaddress.IPv6Address("2001:db8:1::1")),
        ):
            with self.subTest(bit_length=bit_length):
                table = RadixTree(bit_length)
                table.add(route, 1)
                original_prepare = table._prepare

                def prepare_then_add() -> tuple:
                    index = original_prepare()
                    table.add(route, 2)
                    return index

                table._prepare = prepare_then_add
                self.assertEqual(table._search_address(address), 1)
                table._prepare = original_prepare
                self.assertEqual(table._search_address(address), 2)

    def test_exact_routes_adjacent_intervals_and_gaps(self) -> None:
        ipv4 = RadixTree(32)
        ipv4.add("192.0.2.1/32", 1)
        self.assertEqual(ipv4.search_best("192.0.2.1"), 1)
        with self.assertRaisesRegex(ValueError, "No match found"):
            ipv4.search_best("192.0.2.2")

        ipv6 = RadixTree(128)
        ipv6.add("2001:db8::/127", 2)
        ipv6.add("2001:db8::2/127", 2)
        ipv6.add("2001:db8::4/128", 3)
        for address in ("2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"):
            self.assertEqual(ipv6.search_best(address), 2)
        self.assertEqual(ipv6.search_best("2001:db8::4"), 3)
        with self.assertRaisesRegex(ValueError, "No match found"):
            ipv6.search_best("2001:db8::5")

    def test_invalid_prefix_does_not_change_existing_routes(self) -> None:
        for bit_length, route, address, invalid_routes in (
            (32, "192.0.2.0/24", "192.0.2.1", ("192.0.2.0/33", "192.0.2.0/-1", "invalid")),
            (128, "2001:db8::/32", "2001:db8::1", ("2001:db8::/129", "2001:db8::/-1", "invalid")),
        ):
            with self.subTest(bit_length=bit_length):
                table = RadixTree(bit_length)
                table.add(route, 1)
                for invalid_route in invalid_routes:
                    with self.assertRaises(ValueError):
                        table.add(invalid_route, 2)
                self.assertEqual(table.search_best(address), 1)

    def test_rejects_address_family_mismatches(self) -> None:
        ipv4 = RadixTree(32)
        ipv6 = RadixTree(128)

        with self.assertRaisesRegex(ValueError, "Expected an IPv4 network"):
            ipv4.add("2001:db8::/32", 1)
        with self.assertRaisesRegex(ValueError, "Expected an IPv6 network"):
            ipv6.add("192.0.2.0/24", 1)
        with self.assertRaisesRegex(ValueError, "Expected an IPv4 address"):
            ipv4.search_best("2001:db8::1")
        with self.assertRaisesRegex(ValueError, "Expected an IPv6 address"):
            ipv6.search_best("192.0.2.1")
        with self.assertRaisesRegex(ValueError, "Invalid IP address"):
            ipv4.search_best("invalid")

    def test_raises_when_no_route_matches(self) -> None:
        for bit_length, route, missing_address in (
            (32, "192.0.2.0/24", "198.51.100.1"),
            (128, "2001:db8::/32", "2001:4860::1"),
        ):
            with self.subTest(bit_length=bit_length):
                table = RadixTree(bit_length)
                table.add(route, 1)
                with self.assertRaisesRegex(ValueError, "No match found"):
                    table.search_best(missing_address)

    def test_generated_routes_match_naive_oracle(self) -> None:
        for bit_length in (32, 128):
            with self.subTest(bit_length=bit_length):
                self._assert_generated_routes_match(bit_length)

    def _assert_generated_routes_match(self, bit_length: int) -> None:
        rng = random.Random(20261005 + bit_length)
        address_type = ipaddress.IPv4Address if bit_length == 32 else ipaddress.IPv6Address
        table = RadixTree(bit_length)
        expected: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, int] = {}

        for asn in range(1, 301):
            prefix = rng.randrange(0, bit_length + 1)
            network = ipaddress.ip_network((rng.getrandbits(bit_length), prefix), strict=False)
            table.add(str(network), asn)
            expected[network] = asn

        table._prepare()
        for _ in range(2_000):
            address = address_type(rng.getrandbits(bit_length))
            matches = [(network.prefixlen, asn) for network, asn in expected.items() if address in network]
            if matches:
                self.assertEqual(table._search_address(address), max(matches)[1])
            else:
                with self.assertRaisesRegex(ValueError, "No match found"):
                    table._search_address(address)


if __name__ == "__main__":
    unittest.main()
