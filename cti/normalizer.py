#!/usr/bin/env python3


def normalize_otx_result(indicator, response):
    pulse_info = response.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []

    pulse_names = []
    tags = set()

    for pulse in pulses[:10]:
        name = pulse.get("name")

        if name:
            pulse_names.append(name)

        for tag in pulse.get("tags") or []:
            if isinstance(tag, str):
                tags.add(tag)

    return {
        "matched": len(pulses) > 0,
        "indicator": indicator["value"],
        "indicator_type": indicator["type"],
        "source_field": indicator["source_field"],
        "source": "AlienVault OTX",
        "pulse_count": pulse_info.get("count", len(pulses)),
        "reputation": response.get("reputation", 0),
        "pulse_names": pulse_names,
        "tags": sorted(tags),
        "error": None
    }


def build_error_result(indicator, error_message):
    return {
        "matched": False,
        "indicator": indicator["value"],
        "indicator_type": indicator["type"],
        "source_field": indicator["source_field"],
        "source": "AlienVault OTX",
        "pulse_count": 0,
        "reputation": 0,
        "pulse_names": [],
        "tags": [],
        "error": error_message
    }
