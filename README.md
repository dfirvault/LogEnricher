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
  - Interactive CLI with questionary
  - Beautiful console output with rich
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

`#` Clone the repository
`git clone https://github.com/dfirvault/LogEnricher.git`
`cd LogEnricher`

`#` Run the tool
`python LogEnricher.py`

### Requirements.txt

`questionary&gt;=2.0.0`
`rich&gt;=13.0.0`
`requests&gt;=2.31.0`

## 💻 Usage

### Quick Start

`python LogEnricher.py`

The tool will guide you through:
1. API key configuration
2. Enrichment service selection
3. File/folder selection
4. Output directory selection

### Input Format

Any CSV file containing logs, events, or text data. The tool automatically:
- Detects CSV dialect and encoding
- Extracts IOCs from all columns
- Preserves original data while adding enrichment columns

### Output Format

Original columns + enrichment columns (prefixed by source):
- `geo_*` - Geolocation data (IP2Location)
- `proxy_*` - Proxy/VPN detection
- `abuse_*` - AbuseIPDB reputation
- `otx_*` - OTX threat intelligence
- `combined_threat_score` - Aggregated threat score (0-100)

### Example Output Columns

| Original | Enriched |
|----------|----------|
| timestamp | geo_country_code |
| src_ip | geo_country_name |
| dst_ip | proxy_type |
| user_agent | abuse_confidence_score |
| url | otx_pulse_count |
| ... | combined_threat_score |

## 🎯 Use Cases

### Security Operations (SOC)
- Enrich firewall logs with threat intelligence
- Identify malicious IPs in real-time
- Prioritize incident response based on threat scores

### Threat Hunting
- Extract IOCs from historical logs
- Identify previously missed indicators
- Build threat intelligence datasets

### Forensic Analysis
- Enrich PCAP/NetFlow logs
- Geolocate suspicious connections
- Detect proxy/VPN usage

### Compliance Reporting
- Generate enriched evidence files
- Create audit-ready reports
- Demonstrate threat detection capabilities

## 🔒 Windows Registry Configuration

The tool saves API keys and preferences to:
`HKEY_CURRENT_USER\Software\DFIRVault\LogEnricher`

Saved settings include:
- API keys (encrypted in registry)
- Last used input/output paths
- Enabled enrichment services

## 📁 Cache System

Local caching improves performance and reduces API calls:

`%USERPROFILE%\.log_enricher_cache\`
`├── ip2location_px12_db.pkl`      `#` IP2Location database (30-day cache)
`├── tor_exit_nodes.pkl`            `#` TOR exit nodes (24-hour cache)
`└── ip2location_px12_metadata.json`

## 📊 Performance Considerations

- **First run**: Downloads IP2Location database (~50MB)
- **Subsequent runs**: Uses cached database
- **API rate limiting**: Built-in delays prevent throttling
- **Memory usage**: ~200-300MB for IP database
- **Processing speed**: ~1000 rows/second (excluding API calls)

## 🐛 Troubleshooting

### Common Issues

**Q: "No module named 'questionary'"**
`pip install questionary rich requests`

**Q: IP2Location download fails**
- Verify your token at IP2Location.com
- Check internet connectivity
- Ensure firewall allows downloads

**Q: Windows registry access denied**
- Run as administrator
- Tool will continue without registry saving

**Q: Large CSV files are slow**
- Reduce enrichment services
- Use smaller batch sizes
- Consider splitting large files

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- [ ] IPv6 support
- [ ] Additional threat feeds (VirusTotal, URLhaus)
- [ ] Parallel processing for large files
- [ ] GUI interface
- [ ] Export to JSON/Parquet formats
- [ ] Real-time enrichment mode
- [ ] Docker container support

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🔗 Links

- [GitHub Repository](https://github.com/dfirvault/LogEnricher)
- [Issue Tracker](https://github.com/dfirvault/LogEnricher/issues)
- [DFIRVault Blog](https://dfirvault.com)

## 🙏 Acknowledgments

- AlienVault for OTX threat intelligence
- IP2Location for proxy detection database
- AbuseIPDB for reputation data
- Tor Project for exit node lists

## 📧 Contact

- **Author**: DFIRVault
- **Email**: contact@dfirvault.com
- **Twitter**: [@DFIRVault](https://twitter.com/DFIRVault)
