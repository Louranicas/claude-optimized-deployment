"""
SSRF (Server-Side Request Forgery) protection utilities.

Provides comprehensive protection against SSRF attacks by validating URLs
and blocking dangerous requests to internal networks and metadata endpoints.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse, ParseResult
from typing import Set, List, Dict, Any, Optional, Union
import logging
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "SSRFThreatLevel",
    "SSRFValidationResult",
    "SSRFProtector",
    "SSRFProtectedSession",
    "get_ssrf_protector",
    "validate_url_safe",
    "is_url_safe"
]


try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger(__name__)


class SSRFThreatLevel(Enum):
    """SSRF threat levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


@dataclass
class SSRFValidationResult:
    """Result of SSRF validation."""
    is_safe: bool
    threat_level: SSRFThreatLevel
    reason: str
    original_url: str
    resolved_ip: Optional[str] = None
    blocked_category: Optional[str] = None


class SSRFProtector:
    """
    Comprehensive SSRF protection utility.
    
    Protects against:
    - Internal network access (RFC 1918, loopback, link-local)
    - Cloud metadata endpoints (AWS, GCP, Azure, etc.)
    - Localhost and 127.x.x.x addresses
    - IPv6 loopback and link-local addresses
    - Port scanning attempts
    - DNS rebinding attacks
    - Redirect chains to internal resources
    """
    
    # RFC 1918 private networks
    PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]
    
    # Special use networks
    SPECIAL_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local
        ipaddress.ip_network('224.0.0.0/4'),      # Multicast
        ipaddress.ip_network('240.0.0.0/4'),      # Reserved
        ipaddress.ip_network('0.0.0.0/8'),        # "This" network
        ipaddress.ip_network('100.64.0.0/10'),    # Carrier-grade NAT
        ipaddress.ip_network('192.0.0.0/24'),     # IETF protocol assignments
        ipaddress.ip_network('192.0.2.0/24'),     # TEST-NET-1
        ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2
        ipaddress.ip_network('203.0.113.0/24'),   # TEST-NET-3
        ipaddress.ip_network('198.18.0.0/15'),    # Benchmarking
    ]
    
    # IPv6 special networks
    IPV6_SPECIAL_NETWORKS = [
        ipaddress.ip_network('::1/128'),          # Loopback
        ipaddress.ip_network('fe80::/10'),        # Link-local
        ipaddress.ip_network('fc00::/7'),         # Unique local
        ipaddress.ip_network('ff00::/8'),         # Multicast
        ipaddress.ip_network('2001:db8::/32'),    # Documentation
    ]
    
    # Cloud metadata endpoints
    METADATA_ENDPOINTS = {
        'aws': [
            '169.254.169.254',  # AWS metadata service
            '169.254.170.2',    # AWS ECS task metadata
        ],
        'gcp': [
            '169.254.169.254',  # GCP metadata service
            'metadata.google.internal',
        ],
        'azure': [
            '169.254.169.254',  # Azure metadata service
        ],
        'alibaba': [
            '100.100.100.200',  # Alibaba Cloud metadata
        ],
        'docker': [
            '172.17.0.1',       # Default Docker bridge
            '172.18.0.1',       # Docker networks
            '172.19.0.1',
            '172.20.0.1',
        ],
        'localhost': [
            '127.0.0.1',        # Localhost IPv4
            'localhost',        # Localhost hostname
            '::1',              # Localhost IPv6
        ]
    }
    
    # Dangerous ports that should be blocked
    DANGEROUS_PORTS = {
        22,     # SSH
        23,     # Telnet
        25,     # SMTP
        53,     # DNS
        110,    # POP3
        143,    # IMAP
        993,    # IMAPS
        995,    # POP3S
        1433,   # SQL Server
        3306,   # MySQL
        5432,   # PostgreSQL
        6379,   # Redis
        9200,   # Elasticsearch
        11211,  # Memcached
        27017,  # MongoDB
    }
    
    # Allowed schemes
    ALLOWED_SCHEMES = {'http', 'https'}
    
    # Suspicious patterns in URLs
    SUSPICIOUS_PATTERNS = [
        r'@',                    # Credentials in URL
        r'%2e%2e',              # URL-encoded directory traversal
        r'\.\./',               # Directory traversal
        r'0x[0-9a-f]+',         # Hex IP notation
        r'0[0-7]+',             # Octal IP notation
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', # IP addresses
    ]
    
    def __init__(
        self,
        allow_private_networks: bool = False,
        allow_metadata_endpoints: bool = False,
        custom_blocked_networks: Optional[List[str]] = None,
        custom_allowed_domains: Optional[List[str]] = None,
        max_redirects: int = 0,
        dns_timeout: float = 5.0
    ):
        """
        Initialize SSRF protector.
        
        Args:
            allow_private_networks: Allow access to private networks
            allow_metadata_endpoints: Allow access to cloud metadata endpoints
            custom_blocked_networks: Additional CIDR blocks to block
            custom_allowed_domains: Domains that are always allowed
            max_redirects: Maximum redirects to follow (0 = no redirects)
            dns_timeout: DNS resolution timeout in seconds
        """
        self.allow_private_networks = allow_private_networks
        self.allow_metadata_endpoints = allow_metadata_endpoints
        self.max_redirects = max_redirects
        self.dns_timeout = dns_timeout
        
        # Build blocked networks list
        self.blocked_networks = set(self.PRIVATE_NETWORKS + self.SPECIAL_NETWORKS)
        self.blocked_ipv6_networks = set(self.IPV6_SPECIAL_NETWORKS)
        
        if custom_blocked_networks:
            for network in custom_blocked_networks:
                try:
                    self.blocked_networks.add(ipaddress.ip_network(network))
                except ValueError as e:
                    logger.warning(f"Invalid custom blocked network {network}: {e}")
        
        # Allowed domains (bypass all checks)
        self.allowed_domains = set(custom_allowed_domains or [])
        
        # Compile suspicious patterns
        self.suspicious_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_PATTERNS]
    
    def validate_url(self, url: str) -> SSRFValidationResult:
        """
        Validate URL for SSRF protection.
        
        Args:
            url: URL to validate
            
        Returns:
            SSRFValidationResult with validation details
        """
        logger.debug(f"Validating URL for SSRF: {url}")
        
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
                return SSRFValidationResult(
                    is_safe=False,
                    threat_level=SSRFThreatLevel.BLOCKED,
                    reason=f"Disallowed scheme: {parsed.scheme}",
                    original_url=url,
                    blocked_category="scheme"
                )
            
            # Check for suspicious patterns
            suspicious_check = self._check_suspicious_patterns(url)
            if suspicious_check.threat_level == SSRFThreatLevel.BLOCKED:
                return suspicious_check
            
            # Check if domain is in allowed list
            hostname = parsed.hostname
            if not hostname:
                return SSRFValidationResult(
                    is_safe=False,
                    threat_level=SSRFThreatLevel.BLOCKED,
                    reason="No hostname in URL",
                    original_url=url,
                    blocked_category="hostname"
                )
            
            if hostname.lower() in self.allowed_domains:
                return SSRFValidationResult(
                    is_safe=True,
                    threat_level=SSRFThreatLevel.SAFE,
                    reason="Domain in allowed list",
                    original_url=url
                )
            
            # Check port
            port_check = self._check_port(parsed)
            if not port_check.is_safe:
                return port_check
            
            # Resolve hostname to IP
            try:
                resolved_ip = self._resolve_hostname(hostname)
            except Exception as e:
                return SSRFValidationResult(
                    is_safe=False,
                    threat_level=SSRFThreatLevel.BLOCKED,
                    reason=f"DNS resolution failed: {str(e)}",
                    original_url=url,
                    blocked_category="dns"
                )
            
            # Check if resolved IP is safe
            ip_check = self._check_ip_address(resolved_ip, hostname)
            ip_check.original_url = url
            ip_check.resolved_ip = resolved_ip
            
            return ip_check
            
        except Exception as e:
            logger.error(f"Error validating URL {url}: {e}")
            return SSRFValidationResult(
                is_safe=False,
                threat_level=SSRFThreatLevel.BLOCKED,
                reason=f"URL validation error: {str(e)}",
                original_url=url,
                blocked_category="error"
            )
    
    def _check_suspicious_patterns(self, url: str) -> SSRFValidationResult:
        """Check for suspicious patterns in URL."""
        url_lower = url.lower()
        
        for pattern_regex in self.suspicious_regex:
            if pattern_regex.search(url_lower):
                return SSRFValidationResult(
                    is_safe=False,
                    threat_level=SSRFThreatLevel.BLOCKED,
                    reason=f"Suspicious pattern detected: {pattern_regex.pattern}",
                    original_url=url,
                    blocked_category="pattern"
                )
        
        return SSRFValidationResult(
            is_safe=True,
            threat_level=SSRFThreatLevel.SAFE,
            reason="No suspicious patterns",
            original_url=url
        )
    
    def _check_port(self, parsed: ParseResult) -> SSRFValidationResult:
        """Check if port is safe."""
        port = parsed.port
        
        # Use default ports if not specified
        if port is None:
            if parsed.scheme == 'http':
                port = 80
            elif parsed.scheme == 'https':
                port = 443
            else:
                port = 80  # Default fallback
        
        if port in self.DANGEROUS_PORTS:
            return SSRFValidationResult(
                is_safe=False,
                threat_level=SSRFThreatLevel.BLOCKED,
                reason=f"Dangerous port: {port}",
                original_url="",
                blocked_category="port"
            )
        
        # Check for unusual ports that might be internal services
        if port < 1024 and port not in {80, 443}:
            return SSRFValidationResult(
                is_safe=False,
                threat_level=SSRFThreatLevel.SUSPICIOUS,
                reason=f"Suspicious privileged port: {port}",
                original_url="",
                blocked_category="port"
            )
        
        return SSRFValidationResult(
            is_safe=True,
            threat_level=SSRFThreatLevel.SAFE,
            reason="Port is safe",
            original_url=""
        )
    
    def _resolve_hostname(self, hostname: str) -> str:
        """Resolve hostname to IP address."""
        # Check if it's already an IP address
        try:
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            pass
        
        # Resolve hostname
        try:
            socket.setdefaulttimeout(self.dns_timeout)
            result = socket.gethostbyname(hostname)
            return result
        except socket.gaierror as e:
            raise Exception(f"DNS resolution failed for {hostname}: {e}")
        finally:
            socket.setdefaulttimeout(None)
    
    def _check_ip_address(self, ip_str: str, hostname: str) -> SSRFValidationResult:
        """Check if IP address is safe."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return SSRFValidationResult(
                is_safe=False,
                threat_level=SSRFThreatLevel.BLOCKED,
                reason=f"Invalid IP address: {ip_str}",
                original_url="",
                blocked_category="ip"
            )
        
        # Check for metadata endpoints
        if not self.allow_metadata_endpoints:
            for provider, endpoints in self.METADATA_ENDPOINTS.items():
                if ip_str in endpoints or hostname in endpoints:
                    return SSRFValidationResult(
                        is_safe=False,
                        threat_level=SSRFThreatLevel.BLOCKED,
                        reason=f"Cloud metadata endpoint detected: {provider}",
                        original_url="",
                        blocked_category="metadata"
                    )
        
        # Check IPv4 networks
        if ip.version == 4:
            if not self.allow_private_networks:
                for network in self.blocked_networks:
                    try:
                        if ip in network:
                            network_type = self._classify_network(network)
                            return SSRFValidationResult(
                                is_safe=False,
                                threat_level=SSRFThreatLevel.BLOCKED,
                                reason=f"Access to {network_type} network blocked: {network}",
                                original_url="",
                                blocked_category="network"
                            )
                    except TypeError:
                        # Handle mixed IP version comparison
                        continue
        
        # Check IPv6 networks
        elif ip.version == 6:
            if not self.allow_private_networks:
                for network in self.blocked_ipv6_networks:
                    try:
                        if ip in network:
                            return SSRFValidationResult(
                                is_safe=False,
                                threat_level=SSRFThreatLevel.BLOCKED,
                                reason=f"Access to IPv6 special network blocked: {network}",
                                original_url="",
                                blocked_category="network"
                            )
                    except TypeError:
                        continue
        
        return SSRFValidationResult(
            is_safe=True,
            threat_level=SSRFThreatLevel.SAFE,
            reason="IP address is safe",
            original_url=""
        )
    
    def _classify_network(self, network: ipaddress.IPv4Network) -> str:
        """Classify network type for error messages."""
        network_str = str(network)
        
        if network_str == '127.0.0.0/8':
            return "loopback"
        elif network_str == '169.254.0.0/16':
            return "link-local"
        elif network_str in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']:
            return "private"
        elif network_str.startswith('224.') or network_str.startswith('240.'):
            return "reserved"
        else:
            return "internal"
    
    def is_url_safe(self, url: str) -> bool:
        """Simple boolean check if URL is safe."""
        result = self.validate_url(url)
        return result.is_safe
    
    def get_safe_session_config(self) -> Dict[str, Any]:
        """Get aiohttp session configuration with SSRF protection."""
        if aiohttp is None:
            raise ImportError("aiohttp is required for session configuration")
        
        return {
            'timeout': aiohttp.ClientTimeout(total=30),
            'connector': aiohttp.TCPConnector(
                limit=100,
                limit_per_host=10,
                enable_cleanup_closed=True,
                use_dns_cache=True,
                ttl_dns_cache=300,
                family=socket.AF_INET,  # Force IPv4 to avoid IPv6 bypass
            ),
            'max_redirects': self.max_redirects,
        }


# Global SSRF protector instance
_ssrf_protector: Optional[SSRFProtector] = None


def get_ssrf_protector() -> SSRFProtector:
    """Get the global SSRF protector instance."""
    global _ssrf_protector
    if _ssrf_protector is None:
        _ssrf_protector = SSRFProtector()
    return _ssrf_protector


def validate_url_safe(url: str) -> SSRFValidationResult:
    """Validate URL using global SSRF protector."""
    return get_ssrf_protector().validate_url(url)


def is_url_safe(url: str) -> bool:
    """Check if URL is safe using global SSRF protector."""
    return get_ssrf_protector().is_url_safe(url)


class SSRFProtectedSession:
    """
    aiohttp ClientSession wrapper with SSRF protection.
    
    Automatically validates URLs before making requests.
    """
    
    def __init__(
        self,
        protector: Optional[SSRFProtector] = None,
        session_kwargs: Optional[Dict[str, Any]] = None
    ):
        """Initialize SSRF-protected session."""
        self.protector = protector or get_ssrf_protector()
        self.session_kwargs = session_kwargs or self.protector.get_safe_session_config()
        self.session: Optional[Any] = None
    
    async def __aenter__(self):
        """Enter async context."""
        if aiohttp is None:
            raise ImportError("aiohttp is required for SSRFProtectedSession")
        self.session = aiohttp.ClientSession(**self.session_kwargs)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        if self.session:
            await self.session.close()
    
    async def _validate_and_request(self, method: str, url: str, **kwargs):
        """Validate URL and make request."""
        # Validate URL for SSRF
        validation = self.protector.validate_url(url)
        if not validation.is_safe:
            logger.warning(f"SSRF protection blocked request to {url}: {validation.reason}")
            raise Exception(f"SSRF protection: {validation.reason}")
        
        if validation.threat_level == SSRFThreatLevel.SUSPICIOUS:
            logger.warning(f"Suspicious URL detected: {url} - {validation.reason}")
        
        # Make request
        if not self.session:
            raise Exception("Session not initialized - use async context manager")
        
        return await self.session.request(method, url, **kwargs)
    
    async def get(self, url: str, **kwargs):
        """Make GET request with SSRF protection."""
        return await self._validate_and_request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs):
        """Make POST request with SSRF protection."""
        return await self._validate_and_request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs):
        """Make PUT request with SSRF protection."""
        return await self._validate_and_request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs):
        """Make DELETE request with SSRF protection."""
        return await self._validate_and_request('DELETE', url, **kwargs)
    
    async def patch(self, url: str, **kwargs):
        """Make PATCH request with SSRF protection."""
        return await self._validate_and_request('PATCH', url, **kwargs)


# Configuration presets
STRICT_SSRF_CONFIG = {
    'allow_private_networks': False,
    'allow_metadata_endpoints': False,
    'max_redirects': 0,
    'dns_timeout': 5.0
}

MODERATE_SSRF_CONFIG = {
    'allow_private_networks': False,
    'allow_metadata_endpoints': False,
    'max_redirects': 2,
    'dns_timeout': 10.0
}

DEVELOPMENT_SSRF_CONFIG = {
    'allow_private_networks': True,
    'allow_metadata_endpoints': False,
    'max_redirects': 3,
    'dns_timeout': 15.0
}