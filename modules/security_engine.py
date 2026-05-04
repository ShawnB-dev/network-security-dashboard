import socket
import ssl
import subprocess
import json
import requests
from datetime import datetime
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from celery import Celery
import redis
import logging

# Configure logging to see connection issues in the terminal
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REDIS_HOST = 'localhost'
REDIS_PORT = 6379

# --- Celery App Instance ---
celery_app = Celery(
    'security_scanner',
    broker=f'redis://{REDIS_HOST}:{REDIS_PORT}/0',
    backend=f'redis://{REDIS_HOST}:{REDIS_PORT}/0'
)

# --- Caching Layer ---
try:
    # Using DB 1 for caching to separate from Celery's DB 0 (default)
    cache_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=1, decode_responses=True, socket_timeout=2)
    if cache_client.ping():
        logging.info(f"✅ Redis Cache connected on {REDIS_HOST}:{REDIS_PORT}")
    else:
        cache_client = None
except Exception as e:
    logging.error(f"❌ Redis Cache connection failed: {e}")
    cache_client = None

# --- Asynchronous Task Wrapper ---
@celery_app.task(bind=True)
def run_async_scan(self, target, **kwargs):
    """
    Celery task that initializes the engine and runs all modules.
    """
    import socket
    logging.info(f"[*] Starting async scan for target: {target}")
    
    # Initialize the modules
    modules = [
        WebHeaderAuditModule(),
        PortDiscoveryModule(),
        SSLAuditModule(),
        CookieSecurityModule(),
        SensitiveFileModule(),
        ServiceFingerprintModule(),
        IPReputationModule(),
        WhoisLookupModule()
    ]

    results = {}
    total_findings = 0

    for module in modules:
        findings = module.run(target)
        results[module.name] = [f.to_dict() for f in findings]
        total_findings += len([f for f in findings if f.severity != "INFO"])

    # Calculate a basic health score (starting at 100, -10 per non-info finding)
    health_score = max(0, 100 - (total_findings * 10))

    return {
        "target": target,
        "status": "Healthy" if health_score > 70 else "Action Required",
        "overall_health_score": health_score,
        "detailed_findings": results,
        "resolved_ip": socket.gethostbyname(target)
    }

class Finding:
    """Represents a single security vulnerability or health observation."""
    def __init__(self, severity: str, title: str, description: str, mitigation: str):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.mitigation = mitigation

    def to_dict(self):
        return self.__dict__

# --- Abstract Base Module ---

class NetworkSecurityModule(ABC):
    """Abstract interface for all security modules."""
    @abstractmethod
    def run(self, target: str) -> List[Finding]:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

# --- Security Modules (Attack Vectors) ---

class WebHeaderAuditModule(NetworkSecurityModule):
    """
    Checks for missing security headers.
    Attack Vector: XSS, Clickjacking, Protocol Downgrade.
    """
    @property
    def name(self): return "HTTP Security Headers"

    def run(self, target: str) -> List[Finding]:
        findings = []
        url = f"https://{target}"
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            security_headers = {
                "Strict-Transport-Security": "HSTS not enforced.",
                "Content-Security-Policy": "CSP missing; prone to XSS.",
                "X-Frame-Options": "Clickjacking protection missing."
            }
            
            for header, msg in security_headers.items():
                if header not in headers:
                    findings.append(Finding("MEDIUM", f"Missing {header}", msg, f"Configure {header} in web server settings."))
        except Exception as e:
            findings.append(Finding("INFO", "Web Audit Skipped", str(e), "Check connectivity."))
        return findings

class PortDiscoveryModule(NetworkSecurityModule):
    """
    Checks for open ports and service exposure.
    Attack Vector: Reconnaissance / Initial Access.
    """
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]

    @property
    def name(self): return "Port & Service Discovery"

    def run(self, target: str) -> List[Finding]:
        findings = []
        for port in self.common_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    findings.append(Finding(
                        "MEDIUM" if port not in [80, 443] else "INFO",
                        f"Open Port Detected: {port}",
                        f"Port {port} is open and accepting connections.",
                        "Close unnecessary ports or implement IP whitelisting."
                    ))
        return findings

class SSLAuditModule(NetworkSecurityModule):
    """
    Checks for weak SSL/TLS configurations.
    Attack Vector: Man-in-the-Middle (MITM).
    """
    @property
    def name(self): return "SSL/TLS Security Audit"

    def run(self, target: str) -> List[Finding]:
        findings = []
        context = ssl.create_default_context()
        try:
            with socket.create_connection((target, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    if "TLSv1" in version:
                        findings.append(Finding("HIGH", "Deprecated TLS Version", 
                            f"Host is using {version}.", "Upgrade to TLS 1.2 or 1.3."))
                    
                    findings.append(Finding("INFO", "SSL Health Check", 
                        f"Using cipher: {cipher[0]}", "Ensure strong ciphers are prioritized."))
        except Exception as e:
            findings.append(Finding("LOW", "SSL Not Reachable", str(e), "Verify HTTPS config."))
        return findings

class DNSIntegrityModule(NetworkSecurityModule):
    """
    Checks for DNS misconfigurations.
    Attack Vector: DNS Hijacking / Zone Transfers.
    """
    @property
    def name(self): return "DNS Health & Integrity"

    def run(self, target: str) -> List[Finding]:
        findings = []
        # Simulated check for Zone Transfer (AXFR) vulnerability
        # In a real system, you'd use 'dnspython' or subprocess 'dig'
        findings.append(Finding("INFO", "DNS Record Visibility", 
            "Public DNS records are standard.", "Monitor for unauthorized record changes."))
        return findings

class CookieSecurityModule(NetworkSecurityModule):
    """
    Analyzes cookies for security flags (Secure, HttpOnly, SameSite).
    Attack Vector: Session Hijacking, XSS.
    """
    @property
    def name(self): return "Cookie Security Audit"

    def run(self, target: str) -> List[Finding]:
        findings = []
        url = f"https://{target}"
        try:
            response = requests.get(url, timeout=5)
            if not response.cookies:
                findings.append(Finding("INFO", "No Cookies Found", "The target does not set any cookies.", "N/A"))
                return findings

            for cookie in response.cookies:
                if not cookie.secure:
                    findings.append(Finding("HIGH", f"Insecure Cookie: {cookie.name}", 
                        "Cookie is missing the 'Secure' flag.", "Set the 'Secure' attribute on all session cookies."))
                # Check for HttpOnly (stored in _rest attribute in requests)
                if 'httponly' not in [k.lower() for k in cookie._rest.keys()]:
                    findings.append(Finding("MEDIUM", f"Cookie missing HttpOnly: {cookie.name}", 
                        "Cookie is missing the 'HttpOnly' flag.", "Set 'HttpOnly' to prevent client-side script access."))
        except Exception as e:
            findings.append(Finding("INFO", "Cookie Audit Skipped", str(e), "Check connectivity."))
        return findings

class SensitiveFileModule(NetworkSecurityModule):
    """
    Probes for sensitive files and directories.
    Attack Vector: Information Disclosure.
    """
    @property
    def name(self): return "Sensitive File Probe"

    def run(self, target: str) -> List[Finding]:
        findings = []
        paths = ["/.env", "/.git/config", "/backup.sql", "/phpinfo.php"]
        for path in paths:
            url = f"https://{target}{path}"
            try:
                # allow_redirects=False is key to avoid False Positives from login redirects
                response = requests.get(url, timeout=3, allow_redirects=False)
                if response.status_code == 200:
                    findings.append(Finding("CRITICAL", f"Sensitive File Exposed: {path}", 
                        f"File found at {url}.", "Immediately remove or restrict access to this file."))
            except:
                continue
        return findings

class ServiceFingerprintModule(NetworkSecurityModule):
    """
    Attempts to identify service versions via banner grabbing.
    Attack Vector: Exploit Public-Facing Applications.
    """
    @property
    def name(self): return "Service Fingerprinting"

    def _get_cves_from_nvd(self, keyword: str) -> List[Finding]:
        """Queries the NVD API 2.0 for vulnerabilities matching the keyword."""
        # 1. Check local cache first
        if cache_client:
            try:
                cached_data = cache_client.get(f"nvd_cache:{keyword}")
                if cached_data:
                    raw_findings = json.loads(cached_data)
                    return [Finding(**f) for f in raw_findings]
            except Exception:
                pass

        findings = []
        # NVD API 2.0 Endpoint
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword.strip(),
            "resultsPerPage": 10  # Query more to find high-severity ones after filtering
        }
        
        try:
            # Note: NIST recommends an API Key for higher rate limits.
            response = requests.get(api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    
                    # Extract CVSS score (prioritizing V3.1, then V3.0)
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    
                    score = 0.0
                    if cvss_v31:
                        score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
                    elif cvss_v30:
                        score = cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)
                    
                    # Only report vulnerabilities with a CVSS score of 7.0 or higher
                    if score >= 7.0:
                        descriptions = cve.get("descriptions", [])
                        desc_text = descriptions[0].get("value") if descriptions else "No description available."
                        
                        findings.append(Finding(
                            "CRITICAL" if score >= 9.0 else "HIGH",
                            f"NVD Match: {cve_id} (CVSS v3: {score})",
                            f"Service '{keyword}' matches {cve_id}: {desc_text[:200]}...",
                            "Consult the NVD database for specific patch versions or workarounds."
                        ))
                    
                    if len(findings) >= 5: # Return top 5 matches
                        break
                
                # 2. Store results in cache (expire in 24 hours)
                if cache_client:
                    try:
                        # Cache even empty results (negative caching) to prevent repeated API hits
                        cache_value = json.dumps([f.to_dict() for f in findings])
                        cache_client.setex(
                            f"nvd_cache:{keyword}",
                            86400,
                            cache_value
                        )
                    except Exception:
                        pass

        except Exception as e:
            findings.append(Finding("INFO", "NVD Lookup Error", str(e), "Verify API connectivity."))
        return findings

    def run(self, target: str) -> List[Finding]:
        findings = []
        # Attempt to grab a version from HTTP headers as a primary fingerprint
        try:
            response = requests.get(f"https://{target}", timeout=5)
            server_header = response.headers.get("Server")
            if server_header:
                findings.append(Finding("INFO", f"Server Header Detected: {server_header}", 
                    "Service versioning is exposed in headers.", "Disable Server tokens."))
                
                # Query NVD for the specific version found
                findings.extend(self._get_cves_from_nvd(server_header))
        except:
            pass
            
        return findings

class IPReputationModule(NetworkSecurityModule):
    """
    Checks the target IP against public DNS-based Blacklists (DNSBL).
    Attack Vector: Malicious Infrastructure, IP Reputation.
    """
    @property
    def name(self): return "IP Reputation"

    def run(self, target: str) -> List[Finding]:
        findings = []
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            findings.append(Finding("INFO", "IP Resolution Failed", str(e), "Ensure host is reachable."))
            return findings

        # 1. Check Cache
        if cache_client:
            cached = cache_client.get(f"ip_rep:{ip}")
            if cached:
                raw_findings = json.loads(cached)
                return [Finding(**f) for f in raw_findings]

        # 2. Query Public Blacklists (DNSBL)
        blacklists = ["zen.spamhaus.org", "bl.spamcop.net"]
        listed_on = []
        
        # Reverse IP for DNSBL query (e.g., 1.2.3.4 -> 4.3.2.1.zen.spamhaus.org)
        reverse_ip = ".".join(reversed(ip.split(".")))

        for bl in blacklists:
            query = f"{reverse_ip}.{bl}"
            try:
                # If this resolves, the IP is listed
                socket.gethostbyname(query)
                listed_on.append(bl)
            except socket.gaierror:
                #gaierror usually means NOT listed (NXDOMAIN)
                continue

        if listed_on:
            findings.append(Finding(
                "HIGH",
                f"IP Blacklisted: {ip}",
                f"Target IP is currently listed on: {', '.join(listed_on)}.",
                "Investigate origin of malicious traffic or request delisting if IP was inherited."
            ))
        else:
            findings.append(Finding(
                "INFO",
                f"Clean IP Reputation: {ip}",
                "IP was not found on common public blocklists.",
                "Continue monitoring for suspicious activity."
            ))

        # 3. Store in Cache (24 hour TTL)
        if cache_client:
            try:
                cache_client.setex(
                    f"ip_rep:{ip}",
                    86400,
                    json.dumps([f.to_dict() for f in findings])
                )
            except Exception:
                pass

        return findings

class WhoisLookupModule(NetworkSecurityModule):
    """
    Performs a WHOIS/RDAP lookup to identify the organization and country.
    Attack Vector: Attribution / Reconnaissance.
    """
    @property
    def name(self): return "WHOIS Lookup"

    def run(self, target: str) -> List[Finding]:
        findings = []
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            findings.append(Finding("INFO", "IP Resolution Failed", str(e), "Ensure host is reachable."))
            return findings

        # Check Cache
        if cache_client:
            try:
                cached = cache_client.get(f"whois_cache:{ip}")
                if cached:
                    raw_findings = json.loads(cached)
                    return [Finding(**f) for f in raw_findings]
            except Exception:
                pass

        try:
            # Inline import to prevent crash if library is missing
            from ipwhois import IPWhois
            
            obj = IPWhois(ip)
            # RDAP provides structured JSON data about IP ownership
            results = obj.lookup_rdap(depth=1)
            
            asn_description = results.get('asn_description', 'N/A')
            asn_country = results.get('asn_country_code', 'N/A')
            
            findings.append(Finding(
                "INFO",
                f"WHOIS Information for {ip}",
                f"Organization: {asn_description}\nCountry: {asn_country}",
                "Use this information for attribution and to verify the target's ownership."
            ))
            
            if cache_client:
                try:
                    cache_client.setex(f"whois_cache:{ip}", 86400, json.dumps([f.to_dict() for f in findings]))
                except Exception: pass
        except ImportError:
            findings.append(Finding("INFO", "WHOIS Lookup Skipped", "ipwhois library not installed.", "Run 'pip install ipwhois'."))
        except Exception as e:
            findings.append(Finding("INFO", "WHOIS Lookup Failed", str(e), "Verify target and internet connectivity."))
        return findings