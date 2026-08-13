#!/usr/bin/env python3

import json
import sys

from ioc_extractor import extract_indicators


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ALERT_FILE")
        return 1

    alert_path = sys.argv[1]

    try:
        with open(alert_path, "r", encoding="utf-8") as alert_file:
            alert = json.load(alert_file)
    except FileNotFoundError:
        print(f"Error: file not found: {alert_path}")
        return 1
    except json.JSONDecodeError as error:
        print(f"Error: invalid JSON: {error}")
        return 1

    indicators = extract_indicators(alert)
    print(json.dumps(indicators, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
