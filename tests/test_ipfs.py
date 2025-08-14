"""
Tests for IPFS integration
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.storage.content_handler import IPFSContentHandler, ContentMetadata
from src.storage.ipfs_client import PinataClient, IPFSUploadManager, PinataResponse


class TestPinataClient:
    """Test Pinata client"""

    @patch('requests.Session.get')
    def test_authentication(self, mock_get):
        """Test Pinata authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'message': 'Congratulations! You are communicating with the Pinata API!'}
        mock_get.return_value = mock_response

        client = PinataClient(api_key="test_key", secret_key="test_secret")
        assert client.test_authentication()

    @patch('requests.Session.post')
    def test_pin_file_success(self, mock_post):
        """Test successful file pinning"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'IpfsHash': 'QmTestHash123',
            'PinSize': 1024,
            'Timestamp': '2024-01-01T00:00:00Z'
        }
        mock_post.return_value = mock_response

        client = PinataClient(api_key="test_key", secret_key="test_secret")

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Test content")
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            response = client.pin_file_to_ipfs(tmp_path)

            assert response.success
            assert response.ipfs_hash == 'QmTestHash123'
            assert response.pin_size == 1024
        finally:
            # Clean up the temporary file
            if tmp_path.exists():
                os.unlink(tmp_path)

    @patch('requests.Session.post')
    def test_pin_json_success(self, mock_post):
        """Test JSON pinning"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'IpfsHash': 'QmJSONHash456',
            'PinSize': 256,
            'Timestamp': '2024-01-01T00:00:00Z'
        }
        mock_post.return_value = mock_response

        client = PinataClient(api_key="test_key", secret_key="test_secret")

        response = client.pin_json_to_ipfs(
            json_data={"test": "data"},
            pin_name="test_json"
        )

        assert response.success
        assert response.ipfs_hash == 'QmJSONHash456'

    @patch('requests.Session.get')
    def test_verify_pin(self, mock_get):
        """Test pin verification"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'rows': [{'ipfs_pin_hash': 'QmTestHash123'}]
        }
        mock_get.return_value = mock_response

        client = PinataClient(api_key="test_key", secret_key="test_secret")

        assert client.verify_pin('QmTestHash123')


class TestIPFSUploadManager:
    """Test IPFS upload manager"""

    @patch.object(PinataClient, 'test_authentication')
    @patch.object(PinataClient, 'pin_file_to_ipfs')
    def test_upload_file(self, mock_pin, mock_auth):
        """Test file upload"""
        mock_auth.return_value = True
        mock_pin.return_value = PinataResponse(
            success=True,
            ipfs_hash='QmTestHash',
            pin_size=1024,
            gateway_url='https://gateway.pinata.cloud/ipfs/QmTestHash'
        )

        manager = IPFSUploadManager()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Test content")
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            result = manager.upload_file(
                file_path=tmp_path,
                content_type="test",
                metadata={"test": "metadata"}
            )

            assert result.success
            assert result.ipfs_hash == 'QmTestHash'
            assert result.gateway_url == 'https://gateway.pinata.cloud/ipfs/QmTestHash'
        finally:
            # Clean up the temporary file
            if tmp_path.exists():
                os.unlink(tmp_path)

    @patch.object(PinataClient, 'verify_pin')
    @patch('requests.head')
    def test_verify_upload(self, mock_head, mock_verify):
        """Test upload verification"""
        mock_verify.return_value = True
        mock_head.return_value.status_code = 200

        manager = IPFSUploadManager()

        assert manager.verify_upload('QmTestHash')


class TestIPFSContentHandler:
    """Test IPFS content handler"""

    def test_prepare_metadata(self):
        """Test metadata preparation"""
        handler = IPFSContentHandler()

        metadata = ContentMetadata(
            ecocert_id="test_eco_123",
            attestation_uid="0xUID123",
            original_url="https://example.com/file.pdf",
            content_type="document",
            platform="google_drive",
            file_name="test.pdf",
            file_size=1024,
            mime_type="application/pdf",
            checksum="abc123",
            download_timestamp="2024-01-01T00:00:00Z"
        )

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Test content")
            tmp.flush()
            tmp_path = Path(tmp.name)

        try:
            prepared = handler.prepare_content_for_upload(tmp_path, metadata)

            assert prepared["ecocert_id"] == "test_eco_123"
            assert prepared["platform"] == "google_drive" 
            assert prepared["file_size"] == 1024
        finally:
            # Clean up the temporary file
            if tmp_path.exists():
                os.unlink(tmp_path)
