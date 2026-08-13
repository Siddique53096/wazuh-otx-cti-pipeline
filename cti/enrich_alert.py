#!/usr/bin/env python3

import json
import sys

import requests

from ioc_extractor import extract_indicators
from normalizer import build_error_result, normalize_otx_result
from otx_client import OTXClient


def enrich_alert(alert):
    indicators = extract_indicators(alert)

    if not indicators:
        return {
            "integration": "otx",
            "original_alert": {
                "timestamp": alert.get("timestamp"),
                "rule": alert.get("rule", {}),
                "agent": alert.get("agent", {})
            },
            "cti": {
                "matched": False,
                "reason": "No supported public IOC found",
                "results": []
            }
        }

    client = OTXClient()
    results = []

    for indicator in indicators:
        try:
            response = client.lookup(
                indicator["type"],
                indicator["value"]
            )

            normalized_result = normalize_otx_result(
                indicator,
                response
            )

            results.append(normalized_result)

        except requests.Timeout:
            results.append(
                build_error_result(
                    indicator,
                    "CTI request timed out"
                )
            )

        except requests.RequestException as error:
            results.append(
                build_error_result(
                    indicator,
                    f"CTI request failed: {type(error).__name__}"
                )
            )

    return {
        "integration": "otx",
        "original_alert": {
            "timestamp": alert.get("timestamp"),
            "rule": alert.get("rule", {}),
            "agent": alert.get("agent", {})
        },
        "cti": {
            "matched": any(
                result["matched"] for result in results
            ),
            "results": results
        }
    }


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} ALERT_FILE",
            file=sys.stderr
        )
        return 1

    alert_path = sys.argv[1]

    try:
        with open(
            alert_path,
            "r",
            encoding="utf-8"
        ) as alert_file:
            alert = json.load(alert_file)

        result = enrich_alert(alert)

        print(
            json.dumps(
                result,
                separators=(",", ":")
            )
        )

        return 0

    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "integration": "otx",
                    "cti": {
                        "matched": False,
                        "error": f"Alert file not found: {alert_path}"
                    }
                }
            )
        )
        return 1

    except json.JSONDecodeError as error:
        print(
            json.dumps(
                {
                    "integration": "otx",
                    "cti": {
                        "matched": False,
                        "error": f"Invalid alert JSON: {error}"
                    }
                }
            )
        )
        return 1

    except RuntimeError as error:
        print(
            json.dumps(
                {
                    "integration": "otx",
                    "cti": {
                        "matched": False,
                        "error": str(error)
                    }
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
