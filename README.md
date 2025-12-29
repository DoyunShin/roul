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

## License

Apache License 2.0
