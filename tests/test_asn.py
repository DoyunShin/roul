import ipaddress
import json
import os
import threading
import unittest
from collections.abc import Iterable, Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest import mock

import requests

import roul
import roul.asn
from roul.asn import bgptools


class _FakeResponse:
    def __init__(self, chunks: Iterable[bytes], error: Exception | None = None) -> None:
        self.chunks = list(chunks)
        self.error = error
        self.requested_chunk_size: int | None = None

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: Any) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        self.requested_chunk_size = chunk_size
        yield from self.chunks


class _SearchTable:
    def __init__(self, result: int, replacement: roul.asn._Snapshot | None = None) -> None:
        self.result = result
        self.replacement = replacement
        self.address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None

    def _search_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
        self.address = address
        if self.replacement is not None:
            roul.asn._snapshot = self.replacement
        return self.result


class _ReplacingMapping(dict[int, str]):
    def __init__(self, replacement: roul.asn._Snapshot) -> None:
        super().__init__({64500: "old-name"})
        self.replacement = replacement

    def __getitem__(self, key: int) -> str:
        roul.asn._snapshot = self.replacement
        return super().__getitem__(key)


class _FakeRadixTree:
    instances: list["_FakeRadixTree"] = []
    fail_prepare_for: set[int] = set()

    def __init__(self, bit_length: int) -> None:
        self.bit_length = bit_length
        self.records: list[tuple[str, int]] = []
        self.prepared = False
        self.__class__.instances.append(self)

    def add(self, cidr: str, asn: int) -> None:
        self.records.append((cidr, asn))

    def _prepare(self) -> None:
        if self.bit_length in self.fail_prepare_for:
            raise RuntimeError("prepare failed")
        self.prepared = True

    def _search_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
        del address
        return self.records[0][1]


class _TrackingLock:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.attempts = 0
        self.second_attempted = threading.Event()

    def __enter__(self) -> "_TrackingLock":
        self.attempts += 1
        if self.attempts == 2:
            self.second_attempted.set()
        self.lock.acquire()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: Any) -> None:
        self.lock.release()


class _AsnTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.original_debug = roul.DEBUG
        self.original_user_agent = roul.asn.UA
        self.original_snapshot = roul.asn._snapshot
        self.request_guard = mock.patch("requests.sessions.Session.request", side_effect=AssertionError("network request attempted"))
        self.get_guard = mock.patch.object(bgptools, "get", side_effect=AssertionError("bgptools.get called unexpectedly"))
        self.request_mock = self.request_guard.start()
        self.mock_get = self.get_guard.start()

    def tearDown(self) -> None:
        try:
            self.request_mock.assert_not_called()
        finally:
            self.get_guard.stop()
            self.request_guard.stop()
            roul.DEBUG = self.original_debug
            roul.asn.UA = self.original_user_agent
            roul.asn._snapshot = self.original_snapshot


class AsnTest(_AsnTestCase):

    def set_http_responses(self, *responses: _FakeResponse) -> None:
        self.mock_get.reset_mock(side_effect=True, return_value=True)
        self.mock_get.side_effect = responses
        roul.DEBUG = False
        roul.asn.UA = "TEST example.com - test@example.com"

    def assert_snapshot_retained(self, error: type[BaseException], message: str | None = None) -> None:
        old_snapshot = roul.asn._snapshot
        context = self.assertRaisesRegex(error, message) if message is not None else self.assertRaises(error)
        with context:
            bgptools.update()
        self.assertIs(roul.asn._snapshot, old_snapshot)

    def test_search_asn_name_captures_one_snapshot(self) -> None:
        replacement = roul.asn._Snapshot(MappingProxyType({64500: "new-name"}), _SearchTable(1), _SearchTable(1), 2.0)
        mapping = _ReplacingMapping(replacement)
        original = roul.asn._Snapshot(mapping, _SearchTable(1), _SearchTable(1), 1.0)
        roul.asn._snapshot = original

        self.assertEqual(roul.asn.search_asn_name(64500), "old-name")
        self.assertIs(roul.asn._snapshot, replacement)

    def test_search_asn_as_ip_captures_one_snapshot(self) -> None:
        replacement = roul.asn._Snapshot(MappingProxyType({}), _SearchTable(2), _SearchTable(2), 2.0)
        old_ipv4 = _SearchTable(64500)
        original = roul.asn._Snapshot(MappingProxyType({}), old_ipv4, _SearchTable(64501), 1.0)
        roul.asn._snapshot = original

        def replace_during_parse(ipaddr: str) -> ipaddress.IPv4Address:
            roul.asn._snapshot = replacement
            return ipaddress.IPv4Address(ipaddr)

        with mock.patch.object(bgptools.ipaddress, "ip_address", side_effect=replace_during_parse):
            self.assertEqual(roul.asn.search_asn_as_ip("192.0.2.1"), 64500)

        self.assertEqual(old_ipv4.address, ipaddress.ip_address("192.0.2.1"))
        self.assertIs(roul.asn._snapshot, replacement)

    def test_legacy_attributes_read_current_snapshot(self) -> None:
        snapshot = roul.asn._Snapshot(MappingProxyType({64500: "example"}), _SearchTable(1), _SearchTable(2), 123.0)
        roul.asn._snapshot = snapshot

        self.assertIs(roul.asn.ASNS, snapshot.asns)
        self.assertIs(roul.asn.TABLE_IPV4, snapshot.table_ipv4)
        self.assertIs(roul.asn.TABLE_IPV6, snapshot.table_ipv6)
        self.assertEqual(roul.asn.UPDATED_AT, 123.0)
        with self.assertRaisesRegex(AttributeError, "UNKNOWN"):
            getattr(roul.asn, "UNKNOWN")

    def test_star_import_exports_only_public_interface(self) -> None:
        namespace: dict[str, Any] = {}

        exec("from roul.asn import *", namespace)

        exported_names = set(namespace) - {"__builtins__"}
        self.assertEqual(exported_names, set(roul.asn.__all__))
        self.assertEqual(exported_names, {"update", "search_asn_name", "search_asn_as_ip", "ASNS", "TABLE_IPV4", "TABLE_IPV6", "UPDATED_AT", "UA"})
        self.assertIs(namespace["ASNS"], roul.asn._snapshot.asns)
        self.assertIs(namespace["TABLE_IPV4"], roul.asn._snapshot.table_ipv4)
        self.assertIs(namespace["TABLE_IPV6"], roul.asn._snapshot.table_ipv6)
        self.assertEqual(namespace["UPDATED_AT"], roul.asn._snapshot.updated_at)
        self.assertIs(namespace["update"], roul.asn.update)
        self.assertIs(namespace["search_asn_name"], roul.asn.search_asn_name)
        self.assertIs(namespace["search_asn_as_ip"], roul.asn.search_asn_as_ip)
        self.assertEqual(namespace["UA"], roul.asn.UA)

    def test_http_status_and_timeout_retain_snapshot(self) -> None:
        failures = (
            ([_FakeResponse([], requests.HTTPError("bad status"))], requests.HTTPError),
            ([requests.Timeout("read timed out")], requests.Timeout),
        )

        for side_effect, error in failures:
            with self.subTest(error=error.__name__):
                self.mock_get.reset_mock(side_effect=True, return_value=True)
                self.mock_get.side_effect = side_effect
                roul.DEBUG = False
                roul.asn.UA = "TEST example.com - test@example.com"
                self.assert_snapshot_retained(error)

    def test_empty_and_malformed_data_retain_snapshot(self) -> None:
        cases = (
            (
                _FakeResponse([b"asn,name\n"]),
                _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":64500}\n']),
            ),
            (
                _FakeResponse([b"asn,name\ninvalid,row\n"]),
                None,
            ),
            (
                _FakeResponse([b"asn,name\nAS64500,Example\n"]),
                _FakeResponse([b"{malformed json}\n"]),
            ),
            (
                _FakeResponse([b"asn,name\nAS64500,Example\n"]),
                _FakeResponse([]),
            ),
            (
                _FakeResponse([b"asn,name\nAS64500,Example\n"]),
                _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":-1}\n']),
            ),
            (
                _FakeResponse([b"asn,name\nAS64500,Example\n"]),
                _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":true}\n']),
            ),
        )

        for asn_response, table_response in cases:
            with self.subTest(asn_chunks=asn_response.chunks):
                responses = (asn_response,) if table_response is None else (asn_response, table_response)
                self.set_http_responses(*responses)
                self.assert_snapshot_retained(ValueError)

    def test_stream_limits_use_bytes_and_handle_split_unicode(self) -> None:
        encoded = "A한글B\n".encode("utf-8")
        chunks = (encoded[:2], encoded[2:5], encoded[5:])

        self.assertEqual(list(bgptools._iter_data_lines(chunks, len(encoded), 1)), ["A한글B"])
        with self.assertRaisesRegex(ValueError, "byte limit"):
            list(bgptools._iter_data_lines((encoded,), len(encoded) - 1, 1))
        with mock.patch.object(bgptools, "_LINE_LIMIT_BYTES", len(encoded) - 2):
            with self.assertRaisesRegex(ValueError, "per-line byte limit"):
                list(bgptools._iter_data_lines((encoded,), len(encoded), 1))
        with mock.patch.object(bgptools, "_LINE_LIMIT_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "per-line byte limit"):
                list(bgptools._iter_data_lines((b"four",), 4, 1))
        with self.assertRaisesRegex(ValueError, "line limit"):
            list(bgptools._iter_data_lines((b"one\ntwo\n",), 8, 1))
        with self.assertRaises(UnicodeDecodeError):
            list(bgptools._iter_data_lines((b"valid\n\xff",), 7, 2))

    def test_record_limit_retain_snapshot(self) -> None:
        self.set_http_responses(
            _FakeResponse([b"asn,name\nAS64500,One\nAS64501,Two\n"]),
            _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":64500}\n']),
        )

        with mock.patch.object(bgptools, "_ASN_RECORD_LIMIT", 1):
            self.assert_snapshot_retained(ValueError, "line limit")

    def test_debug_update_reads_cached_lines_and_publishes_snapshot(self) -> None:
        roul.DEBUG = True
        fixtures = {
            "asns.csv": ["asn,name", "AS64500,Example"],
            "table.jsonl": [json.dumps({"CIDR": "192.0.2.0/24", "ASN": 64500})],
        }

        with mock.patch.object(bgptools, "_iter_file_lines", side_effect=lambda path, max_bytes, max_lines: iter(fixtures[path])) as iter_file:
            bgptools.update()

        self.assertEqual(roul.asn.search_asn_name(64500), "Example")
        self.assertEqual(roul.asn.search_asn_as_ip("192.0.2.1"), 64500)
        self.assertEqual([call.args[0] for call in iter_file.call_args_list], ["asns.csv", "table.jsonl"])
        self.mock_get.assert_not_called()

    def test_success_prepares_both_indexes_before_publication(self) -> None:
        self.set_http_responses(
            _FakeResponse([b"asn,name\nAS64500,Example\n"]),
            _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":64500}\n']),
        )
        _FakeRadixTree.instances = []
        _FakeRadixTree.fail_prepare_for = set()

        with mock.patch.object(bgptools.roul.ip.radix, "RadixTree", _FakeRadixTree):
            bgptools.update()

        self.assertEqual([table.prepared for table in _FakeRadixTree.instances], [True, True])
        self.assertIs(roul.asn._snapshot.table_ipv4, _FakeRadixTree.instances[0])
        self.assertIs(roul.asn._snapshot.table_ipv6, _FakeRadixTree.instances[1])
        self.assertEqual(self.mock_get.call_count, 2)
        for call in self.mock_get.call_args_list:
            self.assertTrue(call.kwargs["stream"])
            self.assertEqual(call.kwargs["timeout"], (5, 30))
            self.assertEqual(call.kwargs["headers"], {"User-Agent": roul.asn.UA})
        with self.assertRaises(TypeError):
            roul.asn._snapshot.asns[64501] = "immutable"

    def test_prepare_failure_retains_snapshot(self) -> None:
        self.set_http_responses(
            _FakeResponse([b"asn,name\nAS64500,Example\n"]),
            _FakeResponse([b'{"CIDR":"192.0.2.0/24","ASN":64500}\n']),
        )
        _FakeRadixTree.instances = []
        _FakeRadixTree.fail_prepare_for = {128}

        with mock.patch.object(bgptools.roul.ip.radix, "RadixTree", _FakeRadixTree):
            self.assert_snapshot_retained(RuntimeError, "prepare failed")

        self.assertTrue(_FakeRadixTree.instances[0].prepared)
        self.assertFalse(_FakeRadixTree.instances[1].prepared)

    def test_updates_are_serialized_and_queries_use_old_snapshot(self) -> None:
        old_snapshot = roul.asn._Snapshot(MappingProxyType({64500: "old"}), _SearchTable(64500), _SearchTable(64500), 1.0)
        roul.asn._snapshot = old_snapshot
        roul.DEBUG = True
        tracking_lock = _TrackingLock()
        first_update_entered = threading.Event()
        release_first_update = threading.Event()
        calls_lock = threading.Lock()
        calls = 0

        def iter_file(path: str, max_bytes: int, max_lines: int) -> Iterator[str]:
            del max_bytes, max_lines
            nonlocal calls
            if path == "asns.csv":
                with calls_lock:
                    calls += 1
                    call_number = calls
                if call_number == 1:
                    first_update_entered.set()
                    if not release_first_update.wait(timeout=1):
                        raise AssertionError("first update was not released")
                return iter(("asn,name", "AS64501,new"))
            return iter((json.dumps({"CIDR": "192.0.2.0/24", "ASN": 64501}),))

        errors: list[BaseException] = []

        def run_update() -> None:
            try:
                bgptools.update()
            except BaseException as error:
                errors.append(error)

        with mock.patch.object(bgptools, "_update_lock", tracking_lock):
            with mock.patch.object(bgptools, "_iter_file_lines", side_effect=iter_file):
                first = threading.Thread(target=run_update)
                second = threading.Thread(target=run_update)
                first.start()
                self.assertTrue(first_update_entered.wait(timeout=1))
                second.start()
                self.assertTrue(tracking_lock.second_attempted.wait(timeout=1))

                self.assertEqual(calls, 1)
                self.assertEqual(roul.asn.search_asn_name(64500), "old")
                self.assertEqual(roul.asn.search_asn_as_ip("192.0.2.1"), 64500)
                self.assertIs(roul.asn._snapshot, old_snapshot)

                release_first_update.set()
                first.join(timeout=2)
                second.join(timeout=2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, 2)
        self.assertEqual(roul.asn.search_asn_name(64501), "new")


@unittest.skipUnless(os.environ.get("RUN_CACHED_TESTS") == "1", "NOFETCH: set RUN_CACHED_TESTS=1 to test existing local BGP cache files")
class CachedAsnIntegrationTest(_AsnTestCase):
    def test_cached_debug_update(self) -> None:
        asn_path = Path("asns.csv")
        table_path = Path("table.jsonl")
        if not asn_path.is_file() or not table_path.is_file():
            self.skipTest("NOFETCH: asns.csv and table.jsonl must already exist in the worktree")

        roul.DEBUG = True
        bgptools.update()

        self.assertGreater(len(roul.asn.ASNS), 0)
        self.assertGreater(roul.asn.UPDATED_AT, 0)
        first_asn = next(iter(roul.asn.ASNS))
        self.assertEqual(roul.asn.search_asn_name(first_asn), roul.asn.ASNS[first_asn])
        with table_path.open(encoding="utf-8") as table_file:
            first_record = json.loads(next(line for line in table_file if line.strip()))
        address = str(ipaddress.ip_network(first_record["CIDR"], strict=False).network_address)
        self.assertIsInstance(roul.asn.search_asn_as_ip(address), int)


if __name__ == "__main__":
    unittest.main()
