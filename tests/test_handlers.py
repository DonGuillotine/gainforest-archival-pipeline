"""
Tests for content download handlers
"""
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.handlers.base import DownloadResult
from src.handlers.download_manager import DownloadManager
from src.handlers.google_drive import GoogleDriveHandler
from src.handlers.youtube import YouTubeHandler


class TestGoogleDriveHandler:
    """Test Google Drive handler"""

    def test_can_handle_urls(self):
        """Test URL detection"""
        handler = GoogleDriveHandler()

        # Valid URLs
        assert handler.can_handle("https://drive.google.com/file/d/ABC123/view")
        assert handler.can_handle("https://docs.google.com/document/d/XYZ/edit")
        assert handler.can_handle("https://docs.google.com/spreadsheets/d/123/edit")

        # Invalid URLs
        assert not handler.can_handle("https://youtube.com/watch?v=123")
        assert not handler.can_handle("https://example.com/file.pdf")

    def test_extract_file_info(self):
        """Test file ID extraction"""
        handler = GoogleDriveHandler()

        # Drive file
        file_id, service = handler._extract_file_info(
            "https://drive.google.com/file/d/ABC123xyz/view"
        )
        assert file_id == "ABC123xyz"
        assert service == "drive"

        # Google Docs
        file_id, service = handler._extract_file_info(
            "https://docs.google.com/document/d/DOC456/edit"
        )
        assert file_id == "DOC456"
        assert service == "docs"

        # Google Sheets
        file_id, service = handler._extract_file_info(
            "https://docs.google.com/spreadsheets/d/SHEET789/edit"
        )
        assert file_id == "SHEET789"
        assert service == "sheets"

    def test_get_download_url(self):
        """Test download URL generation"""
        handler = GoogleDriveHandler()

        # Drive file
        url = handler.get_download_url("https://drive.google.com/file/d/ABC123/view")
        assert "export=download" in url
        assert "id=ABC123" in url

        # Google Docs (should export as PDF)
        url = handler.get_download_url("https://docs.google.com/document/d/DOC456/edit")
        assert "export?format=pdf" in url
        assert "/document/d/DOC456/" in url

        # Google Sheets (should export as XLSX)
        url = handler.get_download_url("https://docs.google.com/spreadsheets/d/SHEET789/edit")
        assert "export?format=xlsx" in url
        assert "/spreadsheets/d/SHEET789/" in url

    @patch('requests.get')
    def test_download_validation(self, mock_get):
        """Test content validation"""
        handler = GoogleDriveHandler()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Write valid PDF header
            tmp.write(b'%PDF-1.4')
            tmp_path = Path(tmp.name)

        try:
            # Should pass validation
            is_valid, error = handler.validate_content(tmp_path)
            assert is_valid

            # Test HTML error page detection
            with open(tmp_path, 'wb') as f:
                f.write(b'<!DOCTYPE html><html>You need access</html>')

            is_valid, error = handler.validate_content(tmp_path)
            assert not is_valid
            assert "not publicly accessible" in error

        finally:
            tmp_path.unlink()


class TestYouTubeHandler:
    """Test YouTube handler"""

    def test_can_handle_urls(self):
        """Test URL detection"""
        handler = YouTubeHandler()

        # Valid URLs
        assert handler.can_handle("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert handler.can_handle("https://youtu.be/dQw4w9WgXcQ")
        assert handler.can_handle("https://youtube.com/watch?v=abc&t=10s")

        # Invalid URLs
        assert not handler.can_handle("https://vimeo.com/123456")
        assert not handler.can_handle("https://drive.google.com/file/d/ABC")

    @patch('src.handlers.youtube.YoutubeDL')
    def test_get_video_info(self, mock_ydl_class):
        """Test video info extraction"""
        handler = YouTubeHandler()

        # Mock the YoutubeDL instance and its extract_info method
        mock_ydl_instance = mock_ydl_class.return_value.__enter__.return_value
        mock_ydl_instance.extract_info.return_value = {
            'id': 'test123',
            'title': 'Test Video',
            'duration': 60,
            'filesize': 5000000,
            'uploader': 'Test Channel'
        }

        info = handler._get_video_info("https://youtube.com/watch?v=test123")

        assert info['id'] == 'test123'
        assert info['title'] == 'Test Video'
        assert info['duration'] == 60

    def test_validate_video_info(self):
        """Test video validation"""
        handler = YouTubeHandler()

        # Valid video
        is_valid, error = handler._validate_video_info({
            'duration': 600,  # 10 minutes
            'filesize': 50000000  # 50MB
        })
        assert is_valid

        # Video too long
        is_valid, error = handler._validate_video_info({
            'duration': 3600,  # 1 hour
            'filesize': 50000000
        })
        assert not is_valid
        assert "too long" in error

        # File too large
        is_valid, error = handler._validate_video_info({
            'duration': 600,
            'filesize': 200000000  # 200MB
        })
        assert not is_valid
        assert "too large" in error


class TestDownloadManager:
    """Test download manager"""

    def test_get_handler(self):
        """Test handler selection"""
        manager = DownloadManager()

        # Google Drive URL
        handler = manager.get_handler("https://drive.google.com/file/d/ABC/view")
        assert isinstance(handler, GoogleDriveHandler)

        # YouTube URL
        handler = manager.get_handler("https://youtube.com/watch?v=123")
        assert isinstance(handler, YouTubeHandler)

        # Unknown URL
        handler = manager.get_handler("https://example.com/file.pdf")
        assert handler is None

    @patch.object(GoogleDriveHandler, 'download')
    def test_download_content(self, mock_download):
        """Test content download"""
        manager = DownloadManager()

        mock_download.return_value = DownloadResult(
            success=True,
            file_path=Path("/tmp/test.pdf"),
            file_size=1000
        )

        result = manager.download_content("https://drive.google.com/file/d/ABC/view")

        assert result.success
        assert result.file_size == 1000
        mock_download.assert_called_once()
