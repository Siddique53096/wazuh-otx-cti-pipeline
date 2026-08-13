#!/usr/bin/env python3

import json

from normalizer import normalize_otx_result


indicator = {
    "value": "8.8.8.8",
    "type": "IPv4",
    "source_field": "data.dstip"
}

mock_otx_response = {
    "reputation": 0,
    "pulse_info": {
        "count": 1,
        "pulses": [
            {
                "name": "Laboratory CTI Test",
                "tags": [
                    "test",
                    "network"
                ]
            }
        ]
    }
}

normalized_result = normalize_otx_result(
    indicator,
    mock_otx_response
)

print(json.dumps(normalized_result, indent=2))
