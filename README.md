# Wazuh OTX CTI Integration Pipeline

An automated deployment pipeline that installs Wazuh, deploys Linux agents
and integrates AlienVault OTX Cyber Threat Intelligence with Wazuh.

## Project Workflow

1. A Wazuh agent collects an endpoint event.
2. Wazuh generates a JSON security alert.
3. The custom OTX integration receives the alert.
4. The IOC extractor identifies public IP addresses, domains, URLs or hashes.
5. The integration queries the AlienVault OTX API.
6. OTX results are normalized into a consistent JSON structure.
7. The enriched event is returned to Wazuh.
8. Custom Wazuh rules classify matched and unmatched indicators.
9. The enriched alert becomes available to the dashboard and AI component.

## Supported Indicators

| Wazuh field | Indicator type |
|---|---|
| `data.dstip` | Destination IPv4 |
| `data.srcip` | Source IPv4 |
| `data.destination_ip` | Destination IPv4 |
| `data.source_ip` | Source IPv4 |
| `data.domain` | Domain |
| `data.url` | URL |
| `syscheck.md5_after` | MD5 |
| `syscheck.sha1_after` | SHA-1 |
| `syscheck.sha256_after` | SHA-256 |

Private, loopback and multicast addresses are excluded from public CTI
lookups.

## Repository Structure

```text
wazuh-cti-pipeline/
├── cti/
│   ├── enrich_alert.py
│   ├── ioc_extractor.py
│   ├── normalizer.py
│   ├── otx_client.py
│   └── tests/
├── pipeline/
│   ├── inventory/
│   ├── playbooks/
│   └── templates/
├── wazuh/
│   ├── integrations/
│   └── rules/
├── requirements.txt
└── README.md
