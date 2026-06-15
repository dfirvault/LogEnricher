#!/usr/bin/env python3
"""
CSV Log Enricher for Cybersecurity Analysis
Enriches CSV files with threat intelligence from multiple sources
"""

import csv
import os
import sys
import re
import ipaddress
import requests
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from urllib.parse import urlparse
import time
from datetime import datetime, timedelta
import json
from collections import defaultdict
import hashlib
from io import StringIO
import struct
import socket
import pickle

# Windows registry support
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# For CLI interface
try:
    import questionary
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
except ImportError:
    print("Required packages not found. Installing...")
    os.system("pip install questionary rich requests")
    import questionary
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint

console = Console()

# Registry paths
REG_PATH = r"Software\DFIRVault\LogEnricher"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".log_enricher_cache")


class ConfigManager:
    """Manage configuration storage in Windows Registry"""
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration to registry"""
        if not HAS_WINREG:
            return False
        
        try:
            # Create or open the registry key
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
            
            # Save each configuration value
            for key_name, value in config.items():
                if value is not None:
                    if isinstance(value, bool):
                        winreg.SetValueEx(key, key_name, 0, winreg.REG_DWORD, int(value))
                    else:
                        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, str(value))
            
            winreg.CloseKey(key)
            return True
            
        except Exception as e:
            console.print(f"[dim]Could not save config to registry: {e}[/dim]")
            return False
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration from registry"""
        config = {}
        
        if not HAS_WINREG:
            return config
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
            
            i = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, i)
                    
                    # Convert value types
                    if value_type == winreg.REG_DWORD:
                        config[name] = bool(value)
                    else:
                        config[name] = value
                    
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
            
        except FileNotFoundError:
            # No saved config yet
            pass
        except Exception as e:
            console.print(f"[dim]Could not load config from registry: {e}[/dim]")
        
        return config


class IndicatorExtractor:
    """Extract and deduplicate indicators from CSV data"""
    
    # Regex patterns for different indicator types
    IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    
    HASH_PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[-\w%!$&\'()*+,;=:@/~.]*)?(?:\?[-\w%!$&\'()*+,;=:@/~]*)?(?:#[-\w%!$&\'()*+,;=:@/~]*)?'
    )
    
    @classmethod
    def extract_indicators_from_text(cls, text: str) -> Dict[str, List[str]]:
        """Extract all indicators from a text string, maintaining order"""
        indicators = {
            'ips': [],
            'hashes': [],
            'domains': [],
            'urls': []
        }
        
        if not text:
            return indicators
            
        text = str(text)
        
        # Extract IPs
        indicators['ips'] = cls.IP_PATTERN.findall(text)
        
        # Extract hashes
        for hash_type, pattern in cls.HASH_PATTERNS.items():
            indicators['hashes'].extend(pattern.findall(text))
        
        # Extract URLs first
        indicators['urls'] = cls.URL_PATTERN.findall(text)
        
        # Extract domains (excluding those that are part of URLs)
        domains = cls.DOMAIN_PATTERN.findall(text)
        common_tlds = {'.com', '.org', '.net', '.gov', '.edu', '.io', '.co', '.uk', '.us', 
                      '.de', '.jp', '.fr', '.au', '.br', '.ca', '.cn', '.ru', '.in', '.info', '.biz'}
        
        for domain in domains:
            if any(domain.lower().endswith(tld) for tld in common_tlds):
                # Check if domain is part of a URL
                is_in_url = False
                for url in indicators['urls']:
                    if domain in url:
                        is_in_url = True
                        break
                if not is_in_url:
                    indicators['domains'].append(domain)
        
        return indicators


class OTXEnricher:
    """AlienVault OTX threat intelligence enrichment"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}
        self.cache = {}
        
    def enrich_indicator(self, indicator_type: str, indicator: str) -> Dict:
        """Get threat details for an indicator from OTX"""
        # Check cache first
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            url = f"{self.base_url}/indicators/{indicator_type}/{indicator}/general"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                
                # Calculate threat metrics
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                threat_score = min(100, pulse_count * 10)
                
                # Extract pulse information
                pulse_names = []
                all_tags = set()
                malicious_count = 0
                
                for pulse in pulses[:10]:  # Limit to first 10 pulses
                    name = pulse.get('name', '')
                    if name:
                        pulse_names.append(name[:100])
                    tags = pulse.get('tags', [])
                    all_tags.update(tags)
                    if pulse.get('is_malicious', False):
                        malicious_count += 1
                
                result = {
                    'otx_threat_score': threat_score,
                    'otx_pulse_count': pulse_count,
                    'otx_malicious_pulses': malicious_count,
                    'otx_pulse_names': ' | '.join(pulse_names[:5]),
                    'otx_tags': ', '.join(list(all_tags)[:15]),
                    'otx_malicious': malicious_count > 0,
                    'otx_found': True
                }
                
                self.cache[cache_key] = result
                return result
                
            elif response.status_code == 404:
                result = {
                    'otx_threat_score': 0,
                    'otx_pulse_count': 0,
                    'otx_malicious_pulses': 0,
                    'otx_pulse_names': '',
                    'otx_tags': '',
                    'otx_malicious': False,
                    'otx_found': False
                }
                self.cache[cache_key] = result
                return result
                
        except Exception as e:
            console.print(f"[yellow]OTX lookup failed for {indicator}: {str(e)[:50]}[/yellow]")
        
        return {
            'otx_threat_score': 0,
            'otx_pulse_count': 0,
            'otx_malicious_pulses': 0,
            'otx_pulse_names': '',
            'otx_tags': '',
            'otx_malicious': False,
            'otx_found': False
        }


class IP2LocationEnricher:
    """IP2Location PX12 Proxy database enrichment with local database"""
    
    def __init__(self, token: str):
        self.token = token
        self.db_path = None
        self.ip_ranges = []
        self.cache = {}
        self.cache_dir = CACHE_DIR
        self.db_cache_file = os.path.join(self.cache_dir, "ip2location_px12_db.pkl")
        self.metadata_file = os.path.join(self.cache_dir, "ip2location_px12_metadata.json")
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def check_cached_database(self) -> Tuple[bool, Optional[Dict]]:
        """Check if a cached database exists and return metadata"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Check if cache is less than 30 days old
                cache_date = datetime.fromisoformat(metadata.get('download_date', '2000-01-01'))
                age = datetime.now() - cache_date
                
                if age.days < 30 and os.path.exists(self.db_cache_file):
                    return True, metadata
            except:
                pass
        
        return False, None
    
    def load_cached_database(self) -> bool:
        """Load database from cache"""
        try:
            console.print("[cyan]Loading cached IP2Location PX12 database...[/cyan]")
            
            with open(self.db_cache_file, 'rb') as f:
                self.ip_ranges = pickle.load(f)
            
            console.print(f"[green]Loaded {len(self.ip_ranges):,} IP ranges from cache[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to load cached database: {e}[/red]")
            return False
    
    def save_to_cache(self):
        """Save database to cache"""
        try:
            console.print("[cyan]Saving database to cache...[/cyan]")
            
            # Save the IP ranges
            with open(self.db_cache_file, 'wb') as f:
                pickle.dump(self.ip_ranges, f, pickle.HIGHEST_PROTOCOL)
            
            # Save metadata
            metadata = {
                'download_date': datetime.now().isoformat(),
                'record_count': len(self.ip_ranges),
                'token_hash': hashlib.md5(self.token.encode()).hexdigest()[:8]
            }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f)
            
            console.print(f"[green]Database cached successfully[/green]")
            
        except Exception as e:
            console.print(f"[yellow]Failed to cache database: {e}[/yellow]")
    
    def download_database(self, force: bool = False) -> bool:
        """Download IP2Location PX12 LITE database"""
        try:
            url = f"https://www.ip2location.com/download?token={self.token}&file=PX12LITECSV"
            console.print("[cyan]Downloading IP2Location PX12 LITE Proxy database...[/cyan]")
            console.print("[dim]This database contains proxy, VPN, and threat information[/dim]")
            
            response = requests.get(url, stream=True, timeout=60)
            if response.status_code != 200:
                console.print(f"[red]Failed to download: HTTP {response.status_code}[/red]")
                if response.status_code == 403:
                    console.print("[yellow]Invalid token or download limit exceeded[/yellow]")
                return False
            
            # Create temp directory
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, "ip2location.zip")
            
            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            with Progress() as progress:
                task = progress.add_task("[cyan]Downloading...", total=total_size)
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        progress.advance(task, len(chunk))
            
            # Extract
            console.print("[cyan]Extracting database...[/cyan]")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find CSV file
            self.db_path = None
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.csv'):
                        self.db_path = os.path.join(root, file)
                        console.print(f"[green]Found: {file}[/green]")
                        break
                if self.db_path:
                    break
            
            if not self.db_path:
                console.print("[red]No CSV file found in archive[/red]")
                return False
            
            # Load database
            self._load_database()
            
            # Save to cache
            self.save_to_cache()
            
            console.print(f"[green]Loaded {len(self.ip_ranges):,} IP ranges[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Error downloading database: {e}[/red]")
            return False
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer"""
        try:
            # Try using ipaddress module first
            return int(ipaddress.IPv4Address(ip))
        except:
            try:
                # Fallback manual conversion
                parts = ip.split('.')
                if len(parts) == 4:
                    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
            except:
                pass
        return 0
    
    def _load_database(self):
        """Load IP2Location PX12 database into memory"""
        self.ip_ranges = []
        
        if not self.db_path:
            console.print("[red]No database path specified[/red]")
            return
        
        console.print("[cyan]Parsing IP2Location PX12 Proxy database...[/cyan]")
        console.print("[dim]Fields: ip_from, ip_to, country_code, country_name, region_name, city_name, isp, domain, usage_type, asn, as_name, proxy_type, threat, provider, fraud_score[/dim]")
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        loaded = False
        
        for encoding in encodings:
            try:
                with open(self.db_path, 'r', encoding=encoding, errors='ignore') as f:
                    # Read first few lines to determine format
                    first_lines = [f.readline() for _ in range(5)]
                    f.seek(0)
                    
                    # Check if there's a header
                    has_header = any('ip_from' in line.lower() for line in first_lines)
                    
                    if has_header:
                        # Skip header
                        header = next(f)
                        console.print(f"[dim]Detected header[/dim]")
                    
                    # Count total lines for progress
                    console.print("[dim]Counting records...[/dim]")
                    total_lines = sum(1 for _ in f)
                    f.seek(0)
                    if has_header:
                        next(f)
                    
                    console.print(f"[dim]Processing {total_lines:,} records...[/dim]")
                    
                    reader = csv.reader(f)
                    processed = 0
                    errors = 0
                    
                    with Progress() as progress:
                        task = progress.add_task("[cyan]Parsing...", total=total_lines)
                        
                        for row in reader:
                            processed += 1
                            
                            if len(row) >= 15:  # PX12 has 15 fields
                                try:
                                    # Parse IP ranges - these should be decimal numbers
                                    ip_from_str = row[0].strip().strip('"')
                                    ip_to_str = row[1].strip().strip('"')
                                    
                                    # Convert to integers
                                    if '.' in ip_from_str:
                                        ip_from = self._ip_to_int(ip_from_str)
                                    else:
                                        ip_from = int(float(ip_from_str))
                                    
                                    if '.' in ip_to_str:
                                        ip_to = self._ip_to_int(ip_to_str)
                                    else:
                                        ip_to = int(float(ip_to_str))
                                    
                                    if ip_from > 0 and ip_to > 0 and ip_from <= ip_to:
                                        # Parse all PX12 fields
                                        self.ip_ranges.append({
                                            'ip_from': ip_from,
                                            'ip_to': ip_to,
                                            'country_code': row[2].strip('"') if len(row) > 2 else '',
                                            'country_name': row[3].strip('"') if len(row) > 3 else '',
                                            'region_name': row[4].strip('"') if len(row) > 4 else '',
                                            'city_name': row[5].strip('"') if len(row) > 5 else '',
                                            'isp': row[6].strip('"') if len(row) > 6 else '',
                                            'domain': row[7].strip('"') if len(row) > 7 else '',
                                            'usage_type': row[8].strip('"') if len(row) > 8 else '',
                                            'asn': row[9].strip('"') if len(row) > 9 else '',
                                            'as_name': row[10].strip('"') if len(row) > 10 else '',
                                            'proxy_type': row[11].strip('"') if len(row) > 11 else '',
                                            'threat': row[12].strip('"') if len(row) > 12 else '',
                                            'provider': row[13].strip('"') if len(row) > 13 else '',
                                            'fraud_score': row[14].strip('"') if len(row) > 14 else ''
                                        })
                                except (ValueError, IndexError) as e:
                                    errors += 1
                                    if errors < 5:  # Only show first few errors
                                        console.print(f"[dim]Parse error at row {processed}: {e}[/dim]")
                            
                            progress.advance(task)
                            
                            # Progress update every 100,000 records
                            if processed % 100000 == 0:
                                console.print(f"[dim]Processed {processed:,} records, loaded {len(self.ip_ranges):,} ranges[/dim]")
                    
                    if self.ip_ranges:
                        console.print(f"[dim]Successfully loaded with {encoding} encoding[/dim]")
                        console.print(f"[dim]Parse errors: {errors}[/dim]")
                        loaded = True
                        break
                        
            except Exception as e:
                console.print(f"[yellow]Failed with {encoding}: {str(e)[:100]}[/yellow]")
                continue
        
        if not loaded:
            console.print("[red]Failed to load database with any encoding[/red]")
            return
        
        # Sort by ip_from for binary search
        console.print("[cyan]Sorting IP ranges for binary search...[/cyan]")
        self.ip_ranges.sort(key=lambda x: x['ip_from'])
        console.print(f"[green]Database ready with {len(self.ip_ranges):,} ranges[/green]")
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup geolocation and proxy information for an IP address"""
        # Check cache
        if ip in self.cache:
            return self.cache[ip]
        
        if not self.ip_ranges:
            console.print(f"[yellow]No IP ranges loaded for lookup of {ip}[/yellow]")
            result = self._get_empty_result()
            self.cache[ip] = result
            return result
        
        try:
            ip_int = self._ip_to_int(ip)
            
            if ip_int == 0:
                console.print(f"[yellow]Invalid IP: {ip}[/yellow]")
                result = self._get_empty_result()
                self.cache[ip] = result
                return result
            
            # Binary search
            left, right = 0, len(self.ip_ranges) - 1
            
            while left <= right:
                mid = (left + right) // 2
                range_data = self.ip_ranges[mid]
                
                if range_data['ip_from'] <= ip_int <= range_data['ip_to']:
                    result = {
                        # Geolocation fields
                        'geo_country_code': range_data['country_code'],
                        'geo_country_name': range_data['country_name'],
                        'geo_region': range_data['region_name'],
                        'geo_city': range_data['city_name'],
                        'geo_isp': range_data['isp'],
                        'geo_domain': range_data['domain'],
                        
                        # Proxy and network fields
                        'proxy_usage_type': range_data['usage_type'],
                        'proxy_asn': range_data['asn'],
                        'proxy_as_name': range_data['as_name'],
                        'proxy_type': range_data['proxy_type'],
                        'proxy_threat': range_data['threat'],
                        'proxy_provider': range_data['provider'],
                        'proxy_fraud_score': range_data['fraud_score'],
                        
                        # Status
                        'geo_found': True,
                        'is_proxy': range_data['proxy_type'] not in ['', '-', 'NON-PROXY'],
                        'is_vpn': 'VPN' in range_data['usage_type'].upper() if range_data['usage_type'] else False,
                        'is_hosting': 'DCH' in range_data['usage_type'].upper() if range_data['usage_type'] else False,
                        'is_tor': 'TOR' in range_data['proxy_type'].upper() if range_data['proxy_type'] else False
                    }
                    self.cache[ip] = result
                    return result
                elif ip_int < range_data['ip_from']:
                    right = mid - 1
                else:
                    left = mid + 1
                    
        except Exception as e:
            console.print(f"[yellow]Lookup error for {ip}: {e}[/yellow]")
        
        result = self._get_empty_result()
        self.cache[ip] = result
        return result
    
    def _get_empty_result(self) -> Dict:
        """Return empty result structure"""
        return {
            'geo_country_code': '',
            'geo_country_name': '',
            'geo_region': '',
            'geo_city': '',
            'geo_isp': '',
            'geo_domain': '',
            'proxy_usage_type': '',
            'proxy_asn': '',
            'proxy_as_name': '',
            'proxy_type': '',
            'proxy_threat': '',
            'proxy_provider': '',
            'proxy_fraud_score': '',
            'geo_found': False,
            'is_proxy': False,
            'is_vpn': False,
            'is_hosting': False,
            'is_tor': False
        }


class AbuseIPDBEnricher:
    """AbuseIPDB threat intelligence enrichment"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}
        
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation on AbuseIPDB"""
        # Check cache
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            url = f"{self.base_url}/check"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                result = {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'abuse_total_reports': data.get('totalReports', 0),
                    'abuse_last_reported': data.get('lastReportedAt', '')[:10] if data.get('lastReportedAt') else '',
                    'abuse_country': data.get('countryCode', ''),
                    'abuse_usage_type': data.get('usageType', ''),
                    'abuse_isp': data.get('isp', ''),
                    'abuse_domain': data.get('domain', ''),
                    'abuse_is_whitelisted': data.get('isWhitelisted', False),
                    'abuse_found': data.get('totalReports', 0) > 0
                }
                self.cache[ip] = result
                return result
                
        except Exception as e:
            console.print(f"[yellow]AbuseIPDB lookup failed for {ip}: {str(e)[:50]}[/yellow]")
        
        result = {
            'abuse_confidence_score': 0,
            'abuse_total_reports': 0,
            'abuse_last_reported': '',
            'abuse_country': '',
            'abuse_usage_type': '',
            'abuse_isp': '',
            'abuse_domain': '',
            'abuse_is_whitelisted': False,
            'abuse_found': False
        }
        self.cache[ip] = result
        return result


class TorExitNodeChecker:
    """Check if IP is a Tor exit node"""
    
    def __init__(self):
        self.tor_exit_nodes = set()
        self.cache_file = os.path.join(CACHE_DIR, "tor_exit_nodes.pkl")
        self._load_tor_exit_nodes()
    
    def _load_tor_exit_nodes(self):
        """Download current Tor exit node list or load from cache"""
        # Check cache first (less than 24 hours old)
        if os.path.exists(self.cache_file):
            try:
                cache_time = os.path.getmtime(self.cache_file)
                if time.time() - cache_time < 86400:  # 24 hours
                    with open(self.cache_file, 'rb') as f:
                        self.tor_exit_nodes = pickle.load(f)
                    console.print(f"[green]Loaded {len(self.tor_exit_nodes):,} Tor exit nodes from cache[/green]")
                    return
            except:
                pass
        
        # Download fresh list
        try:
            url = "https://check.torproject.org/exit-addresses"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.startswith('ExitAddress'):
                        parts = line.split()
                        if len(parts) >= 2:
                            self.tor_exit_nodes.add(parts[1])
                
                # Save to cache
                os.makedirs(CACHE_DIR, exist_ok=True)
                with open(self.cache_file, 'wb') as f:
                    pickle.dump(self.tor_exit_nodes, f)
                
                console.print(f"[green]Downloaded {len(self.tor_exit_nodes):,} Tor exit nodes[/green]")
        except Exception as e:
            console.print(f"[yellow]Could not load Tor exit nodes: {e}[/yellow]")
    
    def is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node"""
        return ip in self.tor_exit_nodes


class CSVLogEnricher:
    """Main CSV enrichment engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Initialize enrichers
        self.otx = OTXEnricher(config['otx_key']) if config.get('otx_enabled') else None
        self.abuseipdb = AbuseIPDBEnricher(config['abuseipdb_key']) if config.get('abuseipdb_enabled') else None
        self.tor_checker = TorExitNodeChecker() if config.get('tor_enabled') else None
        
        self.ip2location = None
        if config.get('geolocation_enabled') and config.get('ip2location_token'):
            self.ip2location = IP2LocationEnricher(config['ip2location_token'])
            
            # Check for cached database
            has_cache, metadata = self.ip2location.check_cached_database()
            
            if has_cache:
                console.print(f"[cyan]Cached IP2Location PX12 database found:[/cyan]")
                console.print(f"  • Date: {metadata.get('download_date', 'Unknown')}")
                console.print(f"  • Records: {metadata.get('record_count', 0):,}")
                
                should_update = questionary.confirm(
                    "Update IP2Location database? (Recommended every 30 days)",
                    default=False
                ).ask()
                
                if should_update:
                    if not self.ip2location.download_database(force=True):
                        console.print("[yellow]Failed to update, falling back to cached version[/yellow]")
                        if not self.ip2location.load_cached_database():
                            console.print("[red]Failed to load any database, geolocation disabled[/red]")
                            self.ip2location = None
                            self.config['geolocation_enabled'] = False
                else:
                    if not self.ip2location.load_cached_database():
                        console.print("[red]Failed to load cached database[/red]")
                        self.ip2location = None
                        self.config['geolocation_enabled'] = False
            else:
                console.print("[yellow]No cached database found, downloading...[/yellow]")
                if not self.ip2location.download_database():
                    console.print("[red]Failed to download database, geolocation disabled[/red]")
                    self.ip2location = None
                    self.config['geolocation_enabled'] = False
    
    def process_file(self, input_path: str, output_path: str) -> bool:
        """Process a single CSV file"""
        try:
            console.print(f"\n[bold cyan]Processing: {Path(input_path).name}[/bold cyan]")
            
            # Step 1: Read CSV and extract all unique indicators
            rows, fieldnames = self._read_csv(input_path)
            if not rows:
                console.print("[yellow]No data found[/yellow]")
                return False
            
            console.print(f"[dim]Read {len(rows)} rows with {len(fieldnames)} columns[/dim]")
            
            # Step 2: Extract and deduplicate all indicators
            unique_indicators = self._extract_unique_indicators(rows)
            
            # Step 3: Enrich all unique indicators
            enriched_indicators = self._enrich_all_indicators(unique_indicators)
            
            # Step 4: Apply enrichments to each row
            enriched_rows = self._apply_enrichments_to_rows(rows, enriched_indicators)
            
            # Step 5: Write output - ensure directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            self._write_enriched_csv(output_path, enriched_rows, fieldnames)
            
            # Verify file was created
            if os.path.exists(output_path):
                file_size = os.path.getsize(output_path)
                console.print(f"[green]✓ Saved to: {output_path} ({file_size:,} bytes)[/green]")
                return True
            else:
                console.print(f"[red]Failed to create output file: {output_path}[/red]")
                return False
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            import traceback
            traceback.print_exc()
            return False
    
    def _read_csv(self, file_path: str) -> Tuple[List[Dict], List[str]]:
        """Read CSV file with encoding detection"""
        # Detect encoding
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'iso-8859-1', 'cp1252']
        rows = []
        fieldnames = []
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    # Try to detect dialect
                    sample = f.read(4096)
                    f.seek(0)
                    
                    try:
                        dialect = csv.Sniffer().sniff(sample)
                        has_header = csv.Sniffer().has_header(sample)
                    except:
                        dialect = 'excel'
                        has_header = True
                    
                    if has_header:
                        reader = csv.DictReader(f, dialect=dialect)
                        fieldnames = list(reader.fieldnames) if reader.fieldnames else []
                        rows = list(reader)
                    else:
                        # No header, create generic column names
                        reader = csv.reader(f, dialect=dialect)
                        try:
                            first_row = next(reader)
                            fieldnames = [f"Column_{i+1}" for i in range(len(first_row))]
                            f.seek(0)
                            reader = csv.DictReader(f, fieldnames=fieldnames, dialect=dialect)
                            rows = list(reader)
                        except StopIteration:
                            rows = []
                    
                    if rows:
                        console.print(f"[dim]Successfully read with {encoding} encoding[/dim]")
                        return rows, fieldnames
                        
            except Exception as e:
                continue
        
        console.print(f"[red]Failed to read CSV with any encoding[/red]")
        return [], []
    
    def _extract_unique_indicators(self, rows: List[Dict]) -> Dict[str, Set[str]]:
        """Extract and deduplicate all indicators from all rows"""
        unique_indicators = {
            'ips': set(),
            'hashes': set(),
            'domains': set(),
            'urls': set()
        }
        
        console.print("[cyan]Extracting and deduplicating indicators...[/cyan]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning rows...", total=len(rows))
            
            for row in rows:
                # Combine all fields for scanning
                row_text = ' '.join(str(v) for v in row.values() if v)
                indicators = IndicatorExtractor.extract_indicators_from_text(row_text)
                
                unique_indicators['ips'].update(indicators['ips'])
                unique_indicators['hashes'].update(indicators['hashes'])
                unique_indicators['domains'].update(indicators['domains'])
                unique_indicators['urls'].update(indicators['urls'])
                
                progress.advance(task)
        
        console.print(f"[green]Found unique indicators:[/green]")
        console.print(f"  • {len(unique_indicators['ips'])} IP addresses")
        console.print(f"  • {len(unique_indicators['hashes'])} file hashes")
        console.print(f"  • {len(unique_indicators['domains'])} domains")
        console.print(f"  • {len(unique_indicators['urls'])} URLs")
        
        return unique_indicators
    
    def _enrich_all_indicators(self, unique_indicators: Dict[str, Set[str]]) -> Dict[str, Dict]:
        """Enrich all unique indicators using enabled services"""
        enriched = {}
        
        # Enrich IPs
        if unique_indicators['ips']:
            console.print(f"\n[cyan]Enriching {len(unique_indicators['ips'])} IP addresses...[/cyan]")
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing IPs...", total=len(unique_indicators['ips']))
                
                for ip in unique_indicators['ips']:
                    enriched[ip] = self._enrich_ip(ip)
                    progress.advance(task)
                    time.sleep(0.05)  # Rate limiting
        
        # Enrich domains via OTX
        if unique_indicators['domains'] and self.otx:
            console.print(f"\n[cyan]Enriching {len(unique_indicators['domains'])} domains via OTX...[/cyan]")
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing domains...", total=len(unique_indicators['domains']))
                
                for domain in unique_indicators['domains']:
                    enriched[domain] = self.otx.enrich_indicator('domain', domain)
                    progress.advance(task)
                    time.sleep(0.05)
        
        # Enrich URLs via OTX
        if unique_indicators['urls'] and self.otx:
            console.print(f"\n[cyan]Enriching {len(unique_indicators['urls'])} URLs via OTX...[/cyan]")
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing URLs...", total=len(unique_indicators['urls']))
                
                for url in unique_indicators['urls']:
                    enriched[url] = self.otx.enrich_indicator('url', url)
                    progress.advance(task)
                    time.sleep(0.05)
        
        # Enrich hashes via OTX
        if unique_indicators['hashes'] and self.otx:
            console.print(f"\n[cyan]Enriching {len(unique_indicators['hashes'])} hashes via OTX...[/cyan]")
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing hashes...", total=len(unique_indicators['hashes']))
                
                for hash_val in unique_indicators['hashes']:
                    enriched[hash_val] = self.otx.enrich_indicator('file', hash_val)
                    progress.advance(task)
                    time.sleep(0.05)
        
        return enriched
    
    def _enrich_ip(self, ip: str) -> Dict:
        """Enrich a single IP with all enabled services"""
        data = {'ip': ip}
        
        # IP2Location PX12 enrichment (includes proxy, VPN, threat data)
        if self.ip2location:
            geo_data = self.ip2location.lookup_ip(ip)
            data.update(geo_data)
        
        # OTX
        if self.otx:
            otx_data = self.otx.enrich_indicator('IPv4', ip)
            data.update(otx_data)
        
        # AbuseIPDB
        if self.abuseipdb:
            abuse_data = self.abuseipdb.check_ip(ip)
            data.update(abuse_data)
        
        # Tor exit node
        if self.tor_checker:
            data['is_tor_exit_node'] = self.tor_checker.is_tor_exit_node(ip)
        
        # Combined threat assessment
        threat_score = 0
        if data.get('otx_malicious'):
            threat_score += 30
        if data.get('abuse_confidence_score', 0) > 50:
            threat_score += 30
        if data.get('is_proxy', False):
            threat_score += 20
        if data.get('is_tor', False) or data.get('is_tor_exit_node', False):
            threat_score += 20
        if data.get('is_vpn', False):
            threat_score += 15
        if data.get('is_hosting', False):
            threat_score += 10
        
        data['combined_threat_score'] = min(100, threat_score)
        
        return data
    
    def _apply_enrichments_to_rows(self, rows: List[Dict], enriched_data: Dict[str, Dict]) -> List[Dict]:
        """Apply enrichment data back to original rows"""
        console.print("\n[cyan]Applying enrichments to rows...[/cyan]")
        
        enriched_rows = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing rows...", total=len(rows))
            
            for row in rows:
                enriched_row = row.copy()
                
                # Extract indicators from this specific row
                row_text = ' '.join(str(v) for v in row.values() if v)
                indicators = IndicatorExtractor.extract_indicators_from_text(row_text)
                
                # Track counts for numbering multiple indicators of same type
                counts = defaultdict(int)
                
                # Add enrichment for each IP found in row
                for ip in indicators['ips']:
                    if ip in enriched_data:
                        counts['ip'] += 1
                        suffix = f"_{counts['ip']}" if counts['ip'] > 1 else ""
                        
                        for key, value in enriched_data[ip].items():
                            if key != 'ip':  # Skip the ip field itself
                                enriched_row[f"{key}{suffix}"] = value
                
                # Add enrichment for each domain
                for domain in indicators['domains']:
                    if domain in enriched_data:
                        counts['domain'] += 1
                        suffix = f"_{counts['domain']}" if counts['domain'] > 1 else ""
                        
                        for key, value in enriched_data[domain].items():
                            enriched_row[f"{key}_domain{suffix}"] = value
                
                # Add enrichment for each URL
                for url in indicators['urls']:
                    if url in enriched_data:
                        counts['url'] += 1
                        suffix = f"_{counts['url']}" if counts['url'] > 1 else ""
                        
                        for key, value in enriched_data[url].items():
                            enriched_row[f"{key}_url{suffix}"] = value
                
                # Add enrichment for each hash
                for hash_val in indicators['hashes']:
                    if hash_val in enriched_data:
                        counts['hash'] += 1
                        suffix = f"_{counts['hash']}" if counts['hash'] > 1 else ""
                        
                        for key, value in enriched_data[hash_val].items():
                            enriched_row[f"{key}_hash{suffix}"] = value
                
                enriched_rows.append(enriched_row)
                progress.advance(task)
        
        return enriched_rows
    
    def _write_enriched_csv(self, output_path: str, rows: List[Dict], original_fieldnames: List[str]):
        """Write enriched data to CSV"""
        # Collect all field names that appear in any row
        all_fieldnames = set()
        
        # Add original fieldnames, filtering out None values
        for field in original_fieldnames:
            if field is not None:
                all_fieldnames.add(str(field))
        
        # Add all keys from all rows, filtering out None values
        for row in rows:
            for key in row.keys():
                if key is not None:
                    all_fieldnames.add(str(key))
        
        # Separate original and new fieldnames
        original_set = {str(f) for f in original_fieldnames if f is not None}
        new_fieldnames = [f for f in all_fieldnames if f not in original_set]
        
        # Sort new fieldnames, handling potential None values by converting to string
        new_fieldnames.sort(key=lambda x: str(x) if x is not None else "")
        
        # Create final fieldnames list
        final_fieldnames = [f for f in original_fieldnames if f is not None] + new_fieldnames
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=final_fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows)
            
            console.print(f"[dim]Output has {len(final_fieldnames)} columns[/dim]")
            
        except Exception as e:
            console.print(f"[red]Error writing CSV: {e}[/red]")
            raise


def main():
    """Main CLI interface"""
    console.print(Panel.fit(
        "[bold cyan]CSV Log Enricher for Cybersecurity[/bold cyan]\n"
        "[dim]Enrich CSV logs with threat intelligence from multiple sources[/dim]",
        border_style="cyan"
    ))
    
    # Load saved configuration
    saved_config = ConfigManager.load_config()
    
    config = {}
    
    # API Configuration
    console.print("\n[bold]API Configuration[/bold]")
    
    # OTX API Key
    default_otx = saved_config.get('otx_key', '')
    config['otx_key'] = questionary.password(
        "Enter your AlienVault OTX API key:",
        default=default_otx if default_otx else "",
        validate=lambda text: len(text) > 0 or "API key is required"
    ).ask()
    
    # IP2Location Token
    default_ip2location = saved_config.get('ip2location_token', '')
    use_ip2location = questionary.confirm(
        "Do you have an IP2Location download token?",
        default=bool(default_ip2location)
    ).ask()
    
    if use_ip2location:
        config['ip2location_token'] = questionary.password(
            "Enter your IP2Location download token:",
            default=default_ip2location if default_ip2location else ""
        ).ask()
    else:
        config['ip2location_token'] = None
    
    # AbuseIPDB Token
    default_abuseipdb = saved_config.get('abuseipdb_key', '')
    use_abuseipdb = questionary.confirm(
        "Do you have an AbuseIPDB API key?",
        default=bool(default_abuseipdb)
    ).ask()
    
    if use_abuseipdb:
        config['abuseipdb_key'] = questionary.password(
            "Enter your AbuseIPDB API key:",
            default=default_abuseipdb if default_abuseipdb else ""
        ).ask()
    else:
        config['abuseipdb_key'] = None
    
    # Enrichment options
    console.print("\n[bold]Enrichment Options[/bold]")
    
    enrich_choices = [
        questionary.Choice(
            "OTX Threat Intelligence", 
            checked=saved_config.get('otx_enabled', True), 
            value="otx"
        ),
    ]
    
    if config.get('ip2location_token'):
        enrich_choices.append(
            questionary.Choice(
                "IP2Location PX12 (Geolocation + Proxy/VPN/Threat Detection)", 
                checked=saved_config.get('geolocation_enabled', True), 
                value="geolocation"
            )
        )
    
    if config.get('abuseipdb_key'):
        enrich_choices.append(
            questionary.Choice(
                "AbuseIPDB Reputation", 
                checked=saved_config.get('abuseipdb_enabled', True), 
                value="abuseipdb"
            )
        )
    
    enrich_choices.append(
        questionary.Choice(
            "Tor Exit Node Detection", 
            checked=saved_config.get('tor_enabled', True), 
            value="tor"
        )
    )
    
    enrich_options = questionary.checkbox(
        "Select enrichments to enable (space to select, enter for default=all):",
        choices=enrich_choices
    ).ask()
    
    config['otx_enabled'] = 'otx' in enrich_options
    config['geolocation_enabled'] = 'geolocation' in enrich_options
    config['abuseipdb_enabled'] = 'abuseipdb' in enrich_options
    config['tor_enabled'] = 'tor' in enrich_options
    
    # Save configuration
    config_to_save = {
        'otx_key': config['otx_key'],
        'ip2location_token': config.get('ip2location_token', ''),
        'abuseipdb_key': config.get('abuseipdb_key', ''),
        'otx_enabled': config['otx_enabled'],
        'geolocation_enabled': config['geolocation_enabled'],
        'abuseipdb_enabled': config['abuseipdb_enabled'],
        'tor_enabled': config['tor_enabled']
    }
    
    if ConfigManager.save_config(config_to_save):
        console.print("[dim]Configuration saved to registry[/dim]")
    
    # File selection
    console.print("\n[bold]File Selection[/bold]")
    
    # Use saved paths if available
    default_input_path = saved_config.get('last_input_path', '')
    default_output_path = saved_config.get('last_output_path', '')
    
    input_type = questionary.select(
        "Select input type:",
        choices=["Single file", "Folder with multiple CSV files"]
    ).ask()
    
    if input_type == "Single file":
        input_path = questionary.path(
            "Select CSV file to enrich:",
            default=default_input_path if default_input_path and os.path.exists(default_input_path) else "",
            validate=lambda path: path.endswith('.csv') or "Must be a CSV file",
            only_directories=False
        ).ask()
        files_to_process = [input_path]
    else:
        input_path = questionary.path(
            "Select folder containing CSV files:",
            default=default_input_path if default_input_path and os.path.isdir(default_input_path) else "",
            only_directories=True
        ).ask()
        files_to_process = [str(f) for f in Path(input_path).glob("*.csv")]
        
        if not files_to_process:
            console.print("[red]No CSV files found[/red]")
            sys.exit(1)
        
        console.print(f"[green]Found {len(files_to_process)} CSV files[/green]")
    
    # Save input path
    config_to_save['last_input_path'] = input_path if input_type == "Single file" else input_path
    ConfigManager.save_config(config_to_save)
    
    # Output directory
    console.print("\n[bold]Output Configuration[/bold]")
    output_path = questionary.path(
        "Select output directory:",
        default=default_output_path if default_output_path and os.path.isdir(default_output_path) else "",
        only_directories=True
    ).ask()
    
    # Save output path
    config_to_save['last_output_path'] = output_path
    ConfigManager.save_config(config_to_save)
    
    # Create cache and output directories
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(output_path, exist_ok=True)
    
    # Initialize enricher
    console.print("\n[bold cyan]Initializing enricher...[/bold cyan]")
    enricher = CSVLogEnricher(config)
    
    # Process files
    console.print("\n[bold cyan]Starting enrichment process...[/bold cyan]")
    
    successful = 0
    failed = 0
    
    for file_path in files_to_process:
        input_filename = Path(file_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"{input_filename}_enriched_{timestamp}.csv"
        output_file = os.path.join(output_path, output_filename)
        
        if enricher.process_file(file_path, output_file):
            successful += 1
        else:
            failed += 1
    
    # Summary
    console.print("\n[bold green]✓ Processing Complete![/bold green]")
    console.print(f"[green]Successfully processed: {successful} files[/green]")
    if failed > 0:
        console.print(f"[red]Failed to process: {failed} files[/red]")
    console.print(f"[cyan]Output directory: {output_path}[/cyan]")
    console.print(f"[dim]Cache directory: {CACHE_DIR}[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Process interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)