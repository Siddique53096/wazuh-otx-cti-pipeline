#!/usr/bin/env python3

import sys
from pathlib import Path

CTI_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CTI_DIRECTORY))

from ioc_extractor import extract_indicators
from normalizer import normalize_otx_result


def test_extract_public_ip_and_exclude_private_ip():
    alert = {
        "data": {
            "srcip": "192.168.1.20",
            "dstip": "8.8.8.8"
        }
    }

    results = extract_indicators(alert)

    assert len(results) == 1
    assert results[0]["value"] == "8.8.8.8"
    assert results[0]["type"] == "IPv4"
    assert results[0]["source_field"] == "data.dstip"


def test_extract_domain():
    alert = {
        "data": {
            "domain": "example.com"
        }
    }

    results = extract_indicators(alert)

    assert len(results) == 1
    assert results[0]["value"] == "example.com"
    assert results[0]["type"] == "domain"


def test_extract_sha256():
    sample_hash = (
        "275a021bbfb6489e54d471899f7db9d1"
        "663fc695ec2fe2a2c4538aabf651fd0f"
    )

    alert = {
        "syscheck": {
            "sha256_after": sample_hash
        }
    }

    results = extract_indicators(alert)

    assert len(results) == 1
    assert results[0]["value"] == sample_hash
    assert results[0]["type"] == "file"


def test_normalize_matched_response():
    indicator = {
        "value": "8.8.8.8",
        "type": "IPv4",
        "source_field": "data.dstip"
    }

    response = {
        "reputation": 0,
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "name": "Test Pulse",
                    "tags": ["network", "test"]
                }
            ]
        }
    }

    result = normalize_otx_result(indicator, response)

    assert result["matched"] is True
    assert result["pulse_count"] == 1
    assert result["pulse_names"] == ["Test Pulse"]
    assert result["error"] is None


def test_no_supported_indicator():
    alert = {
        "data": {
            "srcip": "192.168.1.20",
            "dstip": "192.168.1.50"
        }
    }

    assert extract_indicators(alert) == []
