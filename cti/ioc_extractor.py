#!/usr/bin/env python3

import ipaddress
from urllib.parse import urlparse


FIELD_MAPPINGS = [
    ("data.dstip", "IPv4"),
    ("data.dest_ip", "IPv4"),
    ("data.destination_ip", "IPv4"),
    ("data.srcip", "IPv4"),
    ("data.src_ip", "IPv4"),
    ("data.source_ip", "IPv4"),
    ("data.domain", "domain"),
    ("data.url", "url"),
    ("syscheck.sha256_after", "file"),
    ("syscheck.sha1_after", "file"),
    ("syscheck.md5_after", "file")
]


def get_nested_value(data, field_path):
    current = data

    for key in field_path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None

        current = current[key]

    return current


def validate_indicator(value, indicator_type):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if indicator_type == "IPv4":
        try:
            address = ipaddress.ip_address(value)

            return (
                address.version == 4
                and address.is_global
                and not address.is_private
                and not address.is_loopback
                and not address.is_multicast
            )
        except ValueError:
            return False

    if indicator_type == "domain":
        return (
            "." in value
            and " " not in value
            and len(value) <= 253
        )

    if indicator_type == "url":
        parsed_url = urlparse(value)

        return (
            parsed_url.scheme in {"http", "https"}
            and bool(parsed_url.netloc)
        )

    if indicator_type == "file":
        valid_hash_lengths = {32, 40, 64}

        return (
            len(value) in valid_hash_lengths
            and all(
                character in "0123456789abcdefABCDEF"
                for character in value
            )
        )

    return False


def extract_indicators(alert):
    indicators = []
    observed = set()

    for field_path, indicator_type in FIELD_MAPPINGS:
        value = get_nested_value(alert, field_path)

        if not value or not validate_indicator(value, indicator_type):
            continue

        value = value.strip()
        unique_key = (indicator_type, value.lower())

        if unique_key in observed:
            continue

        observed.add(unique_key)

        indicators.append(
            {
                "value": value,
                "type": indicator_type,
                "source_field": field_path
            }
        )

    return indicators
