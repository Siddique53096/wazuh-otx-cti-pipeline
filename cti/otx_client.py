#!/usr/bin/env python3

import os
from urllib.parse import quote

import requests


class OTXClient:
    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY")

        self.base_url = os.getenv(
            "OTX_BASE_URL",
            "https://otx.alienvault.com/api/v1"
        ).rstrip("/")

        try:
            self.timeout = int(
                os.getenv("CTI_REQUEST_TIMEOUT", "10")
            )
        except ValueError:
            self.timeout = 10

        if not self.api_key:
            raise RuntimeError("OTX_API_KEY is not configured")

    def lookup(self, indicator_type, value):
        encoded_value = quote(value, safe="")

        endpoint = (
            f"{self.base_url}/indicators/"
            f"{indicator_type}/{encoded_value}/general"
        )

        response = requests.get(
            endpoint,
            headers={
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json"
            },
            timeout=self.timeout
        )

        response.raise_for_status()
        return response.json()

