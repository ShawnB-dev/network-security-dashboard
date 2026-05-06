# type: ignore
from ipwhois import IPWhois
import logging

def get_ip_metadata(ip_address):
    """Perform a WHOIS lookup for a given IP address."""
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)
        return {
            "asn": results.get("asn"),
            "asn_description": results.get("asn_description"),
            "country": results.get("asn_country_code"),
            "range": results.get("network", {}).get("cidr")
        }
    except Exception as e:
        logging.error(f"Failed to lookup IP {ip_address}: {e}")
        return None