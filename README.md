# LogEnricher - CSV Threat Intelligence Enrichment Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/dfirvault/LogEnricher)

**LogEnricher** is a powerful cybersecurity tool that automatically enriches CSV log files with threat intelligence from multiple sources. It extracts indicators of compromise (IOCs) from your logs and adds contextual threat intelligence, geolocation data, proxy/VPN detection, and reputation scores.

## 🚀 Features

- **Multi-Source Threat Intelligence**
  - AlienVault OTX - Pulse feeds and threat scores
  - AbuseIPDB - IP reputation and confidence scores
  - IP2Location PX12 - Proxy, VPN, TOR, and hosting detection
  - Tor Exit Node - Real-time TOR exit node detection

- **IOC Extraction**
  - IP addresses (IPv4)
  - Domain names
  - URLs
  - File hashes (MD5, SHA1, SHA256)

- **Rich Enrichment Data**
  - Geolocation (country, region, city, ISP)
  - Proxy/VPN/TOR detection
  - Threat scores and confidence ratings
  - Malicious pulse information
  - ASN and network provider data
  - Fraud scores

- **User-Friendly Features**
  - Interactive CLI with `questionary`
  - Beautiful console output with `rich`
  - Progress bars and real-time status updates
  - Windows Registry configuration persistence
  - Local caching for offline performance
  - Batch processing for multiple CSV files

## 📋 Prerequisites

- Python 3.7 or higher
- Active internet connection for API lookups
- API keys for services you wish to use

### Required API Keys (Free Tiers Available)

| Service | Free Tier | Registration |
|---------|-----------|---------------|
| AlienVault OTX | ✅ Up to 1000 requests/day | [Register Here](https://otx.alienvault.com/) |
| IP2Location PX12 LITE | ✅ Free with token | [Register Here](https://www.ip2location.com/register) |
| AbuseIPDB | ✅ 1000 requests/day | [Register Here](https://www.abuseipdb.com/register) |

## 🔧 Installation

### Method 1: Pre-compiled Executable (Windows)

1. Download the latest `LogEnricher.exe` from [Releases](https://github.com/dfirvault/LogEnricher/releases)
2. Run the executable - no Python installation required!

### Method 2: From Source

```bash
# Clone the repository
git clone https://github.com/dfirvault/LogEnricher.git
cd LogEnricher

# Install required packages
pip install -r requirements.txt

# Run the tool
python LogEnricher.py
