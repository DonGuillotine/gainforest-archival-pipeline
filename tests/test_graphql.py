"""
Tests for GraphQL query functionality
"""
import json
from unittest.mock import Mock, patch

import pytest

from src.core.graphql_client import (
    GraphQLClient,
    LinkExtractor,
    EcocertQueryService,
    GraphQLError
)
from src.core.models import ExternalLink


class TestGraphQLClient:
    """Test GraphQL client"""

    def test_client_initialization(self):
        """Test client initialization"""
        client = GraphQLClient("https://test.endpoint.com")
        assert client.endpoint == "https://test.endpoint.com"
        assert client.timeout == 30

    @patch('requests.Session.post')
    def test_execute_query_success(self, mock_post):
        """Test successful query execution"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {"test": "result"}
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = GraphQLClient("https://test.endpoint.com")
        result = client.execute_query("query { test }")

        assert result == {"test": "result"}
        mock_post.assert_called_once()

    @patch('requests.Session.post')
    def test_execute_query_with_errors(self, mock_post):
        """Test query with GraphQL errors"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "errors": [{"message": "Test error"}]
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = GraphQLClient("https://test.endpoint.com")

        with pytest.raises(GraphQLError) as exc:
            client.execute_query("query { test }")

        assert "Test error" in str(exc.value)


class TestLinkExtractor:
    """Test link extraction"""

    def test_extract_from_sources_array(self):
        """Test extraction from sources array"""
        extractor = LinkExtractor()

        attestation_data = {
            "decodedData": {
                "sources": [
                    {
                        "type": "url",
                        "src": "https://drive.google.com/file/d/ABC123",
                        "description": "Test file"
                    },
                    {
                        "type": "url",
                        "src": "https://youtube.com/watch?v=XYZ789"
                    }
                ]
            }
        }

        links = extractor.extract_links_from_attestation(attestation_data)

        assert len(links) == 2
        assert links[0].url == "https://drive.google.com/file/d/ABC123"
        assert links[0].description == "Test file"
        assert links[1].url == "https://youtube.com/watch?v=XYZ789"

    def test_extract_from_hex_data(self):
        """Test extraction from hex-encoded data"""
        extractor = LinkExtractor()

        # Create hex-encoded JSON
        json_data = json.dumps({
            "sources": [
                {"src": "https://docs.google.com/document/d/TEST123"}
            ]
        })
        hex_data = "0x" + json_data.encode('utf-8').hex()

        attestation_data = {
            "data": hex_data
        }

        links = extractor.extract_links_from_attestation(attestation_data)

        assert len(links) == 1
        assert "docs.google.com" in links[0].url

    def test_url_validation(self):
        """Test URL validation against allowed domains"""
        extractor = LinkExtractor()

        # Valid URLs
        assert extractor._is_valid_url("https://drive.google.com/file/d/123")
        assert extractor._is_valid_url("https://www.youtube.com/watch?v=abc")
        assert extractor._is_valid_url("https://docs.google.com/document/d/xyz")

        # Invalid URLs
        assert not extractor._is_valid_url("https://evil.com/malware")
        assert not extractor._is_valid_url("ftp://drive.google.com/file")
        assert not extractor._is_valid_url("not-a-url")

    def test_deduplicate_links(self):
        """Test link deduplication"""
        extractor = LinkExtractor()

        links = [
            ExternalLink(url="https://drive.google.com/file/d/123"),
            ExternalLink(url="https://drive.google.com/file/d/123/"),  # Trailing slash
            ExternalLink(url="https://DRIVE.GOOGLE.COM/file/d/123"),  # Different case
            ExternalLink(url="https://youtube.com/watch?v=abc"),
        ]

        unique_links = extractor._deduplicate_links(links)

        assert len(unique_links) == 2
        urls = [link.url for link in unique_links]
        assert any("drive.google.com" in url for url in urls)
        assert any("youtube.com" in url for url in urls)


class TestEcocertQueryService:
    """Test ecocert query service"""

    @patch('src.core.graphql_client.HypercertsClient.get_attestation_uids_from_ecocert')
    @patch('src.core.graphql_client.EASClient.get_attestation_by_uid')
    def test_query_ecocert_success(self, mock_get_attestation, mock_get_uids):
        """Test successful ecocert query"""
        # Mock attestation UIDs retrieval - return list of attestation info
        mock_get_uids.return_value = [
            {
                "uid": "0xTESTUID123",
                "schema_uid": "0xSCHEMA123",
                "data": {},
                "priority": 100,
                "hypercert_index": 0
            }
        ]

        # Mock attestation data
        mock_get_attestation.return_value = {
            "id": "0xTESTUID123",
            "decodedData": {
                "sources": [
                    {
                        "src": "https://drive.google.com/file/d/TEST",
                        "type": "url"
                    }
                ]
            }
        }

        service = EcocertQueryService()
        result = service.query_ecocert("42220-0xABC-123")

        assert result is not None
        assert result.ecocert_id == "42220-0xABC-123"
        assert result.attestation_uid == "0xTESTUID123"
        assert len(result.external_links) == 1
        assert "drive.google.com" in result.external_links[0].url

    @patch('src.core.graphql_client.HypercertsClient.get_attestation_uid_from_ecocert')
    def test_query_ecocert_no_attestation(self, mock_get_uid):
        """Test query when no attestation found"""
        mock_get_uid.return_value = None

        service = EcocertQueryService()
        result = service.query_ecocert("42220-0xABC-123")

        assert result is None


class TestURLValidator:
    """Test URL validation"""

    def test_validate_google_drive_urls(self):
        """Test Google Drive URL validation"""
        from src.security.validator import URLValidator

        validator = URLValidator()

        # Valid URLs
        valid_urls = [
            "https://drive.google.com/file/d/1ABC123xyz/view",
            "https://drive.google.com/open?id=1ABC123xyz",
            "https://docs.google.com/document/d/1ABC123xyz/edit",
            "https://docs.google.com/spreadsheets/d/1ABC123xyz/edit",
        ]

        for url in valid_urls:
            is_valid, error = validator.validate_url(url)
            assert is_valid, f"URL should be valid: {url}, error: {error}"

        # Invalid URLs
        invalid_urls = [
            "https://drive.google.com/",  # No file ID
            "https://evil.google.com/file/d/123",  # Wrong domain
            "javascript:alert('xss')",  # XSS attempt
        ]

        for url in invalid_urls:
            is_valid, error = validator.validate_url(url)
            assert not is_valid, f"URL should be invalid: {url}"

    def test_validate_youtube_urls(self):
        """Test YouTube URL validation"""
        from src.security.validator import URLValidator

        validator = URLValidator()

        # Valid URLs
        valid_urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be/dQw4w9WgXcQ",
        ]

        for url in valid_urls:
            is_valid, error = validator.validate_url(url)
            assert is_valid, f"URL should be valid: {url}, error: {error}"

        # Invalid URLs
        invalid_urls = [
            "https://youtube.com/watch?v=SHORT",  # Wrong video ID length
            "https://youtub.com/watch?v=dQw4w9WgXcQ",  # Typo in domain
        ]

        for url in invalid_urls:
            is_valid, error = validator.validate_url(url)
            assert not is_valid, f"URL should be invalid: {url}"

    def test_extract_resource_id(self):
        """Test resource ID extraction"""
        from src.security.validator import URLValidator

        validator = URLValidator()

        # Google Drive
        result = validator.extract_resource_id("https://drive.google.com/file/d/ABC123/view")
        assert result["type"] == "google_drive_file"
        assert result["id"] == "ABC123"

        # YouTube
        result = validator.extract_resource_id("https://youtube.com/watch?v=dQw4w9WgXcQ")
        assert result["type"] == "youtube_video"
        assert result["id"] == "dQw4w9WgXcQ"
