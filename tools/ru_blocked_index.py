"""DIRECT-prefix membership and domain normalization for ru-blocked probes."""

import bisect
import ipaddress
import re


def normalize_domain(value):
    """Return an ASCII FQDN or raise ValueError; never widen a rule type."""
    value = value.strip().rstrip('.').lower()
    try:
        name = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('invalid IDN') from exc
    labels = name.split('.')
    if len(name) > 253 or len(labels) < 2:
        raise ValueError('invalid FQDN')
    for label in labels:
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            raise ValueError('invalid DNS label')
        if label.startswith('xn--'):
            try:
                if label.encode('ascii').decode('idna').encode('idna').decode('ascii') != label:
                    raise ValueError('invalid punycode')
            except UnicodeError as exc:
                raise ValueError('invalid punycode') from exc
    return name


class DirectPrefixIndex:
    """Membership in the project's DIRECT list, not a geolocation assertion."""

    def __init__(self, prefixes):
        groups = {4: [], 6: []}
        for text in prefixes:
            net = ipaddress.ip_network(text, strict=False)
            groups[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.intervals = {}
        self.starts = {}
        for version, intervals in groups.items():
            merged = []
            for first, last in sorted(intervals):
                if merged and first <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
                else:
                    merged.append((first, last))
            self.intervals[version] = merged
            self.starts[version] = [first for first, _ in merged]

    def contains(self, address):
        ip = ipaddress.ip_address(address)
        # Non-public addresses must not pass even if present in an input list.
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            return False
        value = int(ip)
        index = bisect.bisect_right(self.starts[ip.version], value) - 1
        return index >= 0 and value <= self.intervals[ip.version][index][1]

