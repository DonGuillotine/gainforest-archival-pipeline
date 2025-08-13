"""
Validation module for URLs and content
"""
import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse

import validators

from src.config import get_settings
from src.config.logging_config import get_logger

logger = get_logger(__name__)


class URLValidator:
    """
    Comprehensive URL validation with security checks
    """

    def __init__(self):
        """Initialize URL validator"""
        settings = get_settings()
        self.allowed_domains = [d.lower() for d in settings.ALLOWED_DOMAINS]
        self.max_redirects = 5

        # Blocked IP ranges (private networks)
        self.blocked_ip_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10"),
        ]

        # Suspicious patterns
        self.suspicious_patterns = [
            re.compile(r'\.\./', re.IGNORECASE),  # Path traversal
            re.compile(r'<script', re.IGNORECASE),  # XSS attempt
            re.compile(r'javascript:', re.IGNORECASE),  # JavaScript protocol
            re.compile(r'data:text/html', re.IGNORECASE),  # Data URL with HTML
            re.compile(r'file://', re.IGNORECASE),  # File protocol
            re.compile(r'\\x[0-9a-f]{2}', re.IGNORECASE),  # Hex encoding
            re.compile(r'%00', re.IGNORECASE),  # Null byte
        ]

        logger.info("Initialized URLValidator")

    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL with comprehensive security checks

        Args:
            url: URL to validate

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Basic validation
        if not url or not isinstance(url, str):
            return False, "Invalid URL format"

        url = url.strip()

        # Check URL structure
        if not validators.url(url):
            return False, "Malformed URL"

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Failed to parse URL: {e}"

        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, f"Invalid scheme: {parsed.scheme}"

        # Check domain
        domain = parsed.netloc.lower()
        if not domain:
            return False, "Missing domain"

        # Remove port for domain checking
        domain_without_port = domain.split(':')[0]

        # Check against allowed domains
        if not self._is_domain_allowed(domain_without_port):
            return False, f"Domain not allowed: {domain_without_port}"

        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(url):
                return False, f"Suspicious pattern detected in URL"

        # Check for IP address (not domain name)
        if self._is_ip_address(domain_without_port):
            return False, "Direct IP addresses not allowed"

        # Additional checks for specific services
        if "drive.google.com" in domain:
            is_valid, error = self._validate_google_drive_url(url)
            if not is_valid:
                return False, error

        elif "youtube.com" in domain or "youtu.be" in domain:
            is_valid, error = self._validate_youtube_url(url)
            if not is_valid:
                return False, error

        return True, None

    def _is_domain_allowed(self, domain: str) -> bool:
        """
        Check if domain is in allowed list

        Args:
            domain: Domain to check

        Returns:
            bool: True if allowed
        """
        domain = domain.lower().replace("www.", "")

        for allowed in self.allowed_domains:
            allowed = allowed.replace("www.", "")
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        return False

    def _is_ip_address(self, host: str) -> bool:
        """
        Check if host is an IP address

        Args:
            host: Host to check

        Returns:
            bool: True if IP address
        """
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _validate_google_drive_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate Google Drive URL format

        Args:
            url: Google Drive URL

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Valid Google Drive patterns
        patterns = [
            r'drive\.google\.com/file/d/([a-zA-Z0-9_-]+)',
            r'drive\.google\.com/open\?id=([a-zA-Z0-9_-]+)',
            r'drive\.google\.com/drive/folders/([a-zA-Z0-9_-]+)',
            r'docs\.google\.com/document/d/([a-zA-Z0-9_-]+)',
            r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)',
            r'docs\.google\.com/presentation/d/([a-zA-Z0-9_-]+)',
        ]

        for pattern in patterns:
            if re.search(pattern, url):
                return True, None

        return False, "Invalid Google Drive URL format"

    def _validate_youtube_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate YouTube URL format

        Args:
            url: YouTube URL

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Valid YouTube patterns
        patterns = [
            r'youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
            r'youtu\.be/([a-zA-Z0-9_-]{11})',
            r'youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                video_id = match.group(1)
                # Validate video ID format
                if len(video_id) == 11:
                    return True, None

        return False, "Invalid YouTube URL format"

    def extract_resource_id(self, url: str) -> Optional[Dict[str, str]]:
        """
        Extract resource ID from URL

        Args:
            url: URL to extract from

        Returns:
            Optional[Dict]: Resource info with type and ID
        """
        # Google Drive
        drive_patterns = [
            (r'drive\.google\.com/file/d/([a-zA-Z0-9_-]+)', 'google_drive_file'),
            (r'drive\.google\.com/open\?id=([a-zA-Z0-9_-]+)', 'google_drive_file'),
            (r'drive\.google\.com/drive/folders/([a-zA-Z0-9_-]+)', 'google_drive_folder'),
            (r'docs\.google\.com/document/d/([a-zA-Z0-9_-]+)', 'google_docs'),
            (r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)', 'google_sheets'),
            (r'docs\.google\.com/presentation/d/([a-zA-Z0-9_-]+)', 'google_slides'),
        ]

        for pattern, resource_type in drive_patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    "type": resource_type,
                    "id": match.group(1),
                    "platform": "google"
                }

        # YouTube
        youtube_patterns = [
            r'youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
            r'youtu\.be/([a-zA-Z0-9_-]{11})',
            r'youtube\.com/embed/([a-zA-Z0-9_-]{11})',
        ]

        for pattern in youtube_patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    "type": "youtube_video",
                    "id": match.group(1),
                    "platform": "youtube"
                }

        return None

    def check_url_accessibility(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Check if URL is accessible (DNS resolution)

        Args:
            url: URL to check

        Returns:
            Tuple[bool, Optional[str]]: (is_accessible, error_message)
        """
        domain = None

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]

            if not domain:
                return False, "Invalid URL: no domain found"

            # DNS resolution check
            socket.gethostbyname(domain)
            return True, None

        except socket.gaierror:
            return False, f"Domain not found: {domain or 'unknown'}"
        except Exception as e:
            return False, f"Accessibility check failed: {e}"

    def batch_validate_urls(
            self,
            urls: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Validate multiple URLs

        Args:
            urls: List of URLs to validate

        Returns:
            Dict: Validation results for each URL
        """
        results = {}

        for url in urls:
            is_valid, error = self.validate_url(url)

            result = {
                "url": url,
                "is_valid": is_valid,
                "error": error,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            if is_valid:
                # Extract resource info
                resource_info = self.extract_resource_id(url)
                if resource_info:
                    result["resource"] = resource_info

                # Check accessibility
                is_accessible, access_error = self.check_url_accessibility(url)
                result["is_accessible"] = is_accessible
                if not is_accessible:
                    result["accessibility_error"] = access_error

            results[url] = result

        # Log summary
        valid_count = sum(1 for r in results.values() if r["is_valid"])
        logger.info(f"Validated {len(urls)} URLs: {valid_count} valid, {len(urls) - valid_count} invalid")

        return results
