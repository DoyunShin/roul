# roul

`roul` is a comprehensive collection of various utility tools for Python, including high-performance ASN lookups, IP management, and more.

## Usage

### ASN Lookup

```python
import roul.asn

# Set User-Agent as required by data providers
roul.asn.UA = "YourProject contact@example.com"

# Sync data
roul.asn.update()

# Search
asn = roul.asn.search_asn_as_ip("1.1.1.1")
name = roul.asn.search_asn_name(asn)
print(f"ASN: {asn}, Name: {name}")
```

Each lookup uses one complete data snapshot. Separate lookup calls may use different snapshots if an update finishes between them. Failed updates retain the previous data and update timestamp. The legacy data attributes remain readable; `ASNS` is a read-only mapping.

Downloads use a 5-second connection timeout and a 30-second read timeout, not a total update deadline. Input limits are 32 MiB and 250,000 records for ASN data, 256 MiB and 4,000,000 records for routing data, and 64 KiB per line.

## Testing

Use Python 3.10 or newer with the existing runtime dependencies installed:

```sh
python -m unittest discover -s tests -v
```

Cached integration tests require existing `asns.csv` and `table.jsonl` files in the working directory:

```sh
RUN_CACHED_TESTS=1 python -m unittest discover -s tests -v
```

Cached tests load these files with `roul.DEBUG = True`. Tests never download data; HTTP failure cases use mock responses, and actual network requests are blocked.

## License

Apache License 2.0
