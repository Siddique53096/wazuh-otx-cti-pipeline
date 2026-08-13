#!/usr/bin/env python3

import json
import sys

import requests

from otx_client import OTXClient


def main():
    try:
        client = OTXClient()
        result = client.lookup("IPv4", "8.8.8.8")

        safe_output = {
            "indicator": result.get("indicator"),
            "type": result.get("type"),
            "reputation": result.get("reputation"),
            "pulse_count": (
                result.get("pulse_info", {}).get("count", 0)
            )
        }

        print(json.dumps(safe_output, indent=2))
        return 0

    except RuntimeError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 1

    except requests.Timeout:
        print("Error: OTX request timed out", file=sys.stderr)
        return 1

    except requests.RequestException as error:
        print(
            f"OTX request failed: {type(error).__name__}",
            file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
