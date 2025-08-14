"""
Handler for Google Drive and Google Docs content
"""
import re
from pathlib import Path
from typing import Optional, Dict, Any

from src.config.logging_config import get_logger
from src.handlers.base import BaseContentHandler

logger = get_logger(__name__)


class GoogleDriveHandler(BaseContentHandler):
    """
    Handler for downloading content from Google Drive and Google Docs
    Handles only public files (no OAuth required)
    """

    def __init__(self):
        """Initialize Google Drive handler"""
        super().__init__()

        # Patterns for different Google services
        self.patterns = {
            'drive_file': re.compile(r'drive\.google\.com/file/d/([a-zA-Z0-9_-]+)'),
            'drive_open': re.compile(r'drive\.google\.com/open\?id=([a-zA-Z0-9_-]+)'),
            'docs': re.compile(r'docs\.google\.com/document/d/([a-zA-Z0-9_-]+)'),
            'sheets': re.compile(r'docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)'),
            'slides': re.compile(r'docs\.google\.com/presentation/d/([a-zA-Z0-9_-]+)'),
        }

        # Export formats for Google Docs/Sheets/Slides
        self.export_formats = {
            'docs': 'pdf',  # Export Google Docs as PDF
            'sheets': 'xlsx',  # Export Google Sheets as Excel
            'slides': 'pdf',  # Export Google Slides as PDF
        }

    def can_handle(self, url: str) -> bool:
        """
        Check if this handler can process the given URL

        Args:
            url: URL to check

        Returns:
            bool: True if this is a Google Drive/Docs URL
        """
        url_lower = url.lower()
        return any([
            'drive.google.com' in url_lower,
            'docs.google.com' in url_lower
        ])

    def get_download_url(self, url: str) -> str:
        """
        Convert Google Drive/Docs public URL to direct download URL

        Args:
            url: Public Google Drive/Docs URL

        Returns:
            str: Direct download URL
        """
        # Extract file ID and determine service type
        file_id, service_type = self._extract_file_info(url)

        if not file_id:
            raise ValueError(f"Could not extract file ID from URL: {url}")

        # Generate appropriate download URL based on service type
        if service_type == 'drive':
            # Direct download URL for Google Drive files
            download_url = f"https://drive.google.com/uc?export=download&id={file_id}"
            logger.info(f"Generated Drive download URL for file ID: {file_id}")

        elif service_type == 'docs':
            # Export URL for Google Docs
            export_format = self.export_formats['docs']
            download_url = f"https://docs.google.com/document/d/{file_id}/export?format={export_format}"
            logger.info(f"Generated Docs export URL for file ID: {file_id} (format: {export_format})")

        elif service_type == 'sheets':
            # Export URL for Google Sheets
            export_format = self.export_formats['sheets']
            download_url = f"https://docs.google.com/spreadsheets/d/{file_id}/export?format={export_format}"
            logger.info(f"Generated Sheets export URL for file ID: {file_id} (format: {export_format})")

        elif service_type == 'slides':
            # Export URL for Google Slides
            export_format = self.export_formats['slides']
            download_url = f"https://docs.google.com/presentation/d/{file_id}/export?format={export_format}"
            logger.info(f"Generated Slides export URL for file ID: {file_id} (format: {export_format})")

        else:
            raise ValueError(f"Unknown Google service type: {service_type}")

        return download_url

    def get_platform_name(self) -> str:
        """
        Get the platform name for organizing downloads

        Returns:
            str: Platform name
        """
        return "google_drive"

    def _extract_file_info(self, url: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract file ID and service type from Google URL

        Args:
            url: Google Drive/Docs URL

        Returns:
            tuple: (file_id, service_type) or (None, None)
        """
        # Check Drive file patterns
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(url)
            if match:
                file_id = match.group(1)

                # Determine service type
                if 'drive' in pattern_name:
                    return file_id, 'drive'
                elif 'docs' in pattern_name:
                    return file_id, 'docs'
                elif 'sheets' in pattern_name:
                    return file_id, 'sheets'
                elif 'slides' in pattern_name:
                    return file_id, 'slides'

        return None, None

    def _get_file_extension(self, url: str) -> str:
        """
        Get appropriate file extension based on URL type

        Args:
            url: Google Drive/Docs URL

        Returns:
            str: File extension with dot
        """
        _, service_type = self._extract_file_info(url)

        if service_type == 'docs':
            return '.pdf'
        elif service_type == 'sheets':
            return '.xlsx'
        elif service_type == 'slides':
            return '.pdf'
        else:
            # For Drive files, use .tmp initially - we'll detect the proper extension later
            return '.tmp'

    def validate_content(self, file_path: Path) -> tuple[bool, Optional[str]]:
        """
        Validate downloaded Google Drive content

        Args:
            file_path: Path to the downloaded file

        Returns:
            tuple: (is_valid, error_message)
        """
        # First, run base validation
        is_valid, error_msg = super().validate_content(file_path)
        if not is_valid:
            return is_valid, error_msg

        # Check for Google's virus scan warning HTML
        # Large files might return an HTML page instead of the file
        with open(file_path, 'rb') as f:
            first_bytes = f.read(1024)

            # Check if we got an HTML error page instead of the file
            if b'<!DOCTYPE html' in first_bytes or b'<html' in first_bytes:
                if b'Google Drive - Virus scan warning' in first_bytes:
                    return False, "File requires virus scan confirmation (too large for direct download)"
                elif b'You need access' in first_bytes or b'Request access' in first_bytes:
                    return False, "File is not publicly accessible"
                else:
                    return False, "Received HTML page instead of file content"

        # Additional MIME type validation based on expected format
        mime_type = self._detect_mime_type(file_path)

        # Define expected MIME types for each export format
        expected_types = {
            '.pdf': ['application/pdf'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.bin': None  # Can be any type for direct Drive downloads
        }

        extension = file_path.suffix
        if extension in expected_types and expected_types[extension]:
            if mime_type not in expected_types[extension]:
                logger.warning(f"Unexpected MIME type {mime_type} for {extension} file")
                # Don't fail, just warn - Google might use different MIME types

        return True, None

    def extract_metadata(self, file_path: Path, original_url: str) -> Dict[str, Any]:
        """
        Extract metadata from Google Drive content

        Args:
            file_path: Path to the downloaded file
            original_url: Original Google Drive/Docs URL

        Returns:
            Dict[str, Any]: Metadata
        """
        metadata = super().extract_metadata(file_path, original_url)

        # Add Google-specific metadata
        file_id, service_type = self._extract_file_info(original_url)
        if file_id:
            metadata['google_file_id'] = file_id
            metadata['google_service'] = service_type

        return metadata

    def _detect_proper_extension(self, file_path: Path, mime_type: str) -> str:
        """
        Detect proper file extension based on content

        Args:
            file_path: Path to the file
            mime_type: Detected MIME type

        Returns:
            str: Proper file extension with dot
        """
        # Common MIME type to extension mappings
        mime_to_ext = {
            'text/plain': '.txt',
            'text/markdown': '.md',
            'text/html': '.html',
            'text/css': '.css',
            'text/javascript': '.js',
            'application/json': '.json',
            'application/xml': '.xml',
            'text/xml': '.xml',
            'application/pdf': '.pdf',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/svg+xml': '.svg',
            'video/mp4': '.mp4',
            'video/webm': '.webm',
            'video/avi': '.avi',
            'audio/mpeg': '.mp3',
            'audio/wav': '.wav',
            'application/zip': '.zip',
            'application/x-zip-compressed': '.zip',
            'application/vnd.ms-excel': '.xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'application/vnd.ms-powerpoint': '.ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
        }

        # Check if we have a direct mapping
        if mime_type in mime_to_ext:
            return mime_to_ext[mime_type]

        # For text files, try to detect more specific types by reading content
        if mime_type.startswith('text/'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_few_lines = ''.join(f.readlines()[:10]).lower()
                    
                    # Check for common markdown indicators
                    markdown_patterns = [
                        '# ',           # Headers
                        '## ', '### ', '#### ', '##### ', '###### ',
                        '- ',           # Bullet lists  
                        '* ',           # Bullet lists
                        '**',           # Bold text
                        '__',           # Bold text (alternative)
                        '[',            # Links start
                        '](',           # Links middle
                        '```',          # Code blocks
                        '`',            # Inline code
                        '> ',           # Blockquotes
                        '---',          # Horizontal rules
                        '1. ',          # Numbered lists (check if followed by text)
                        '2. ', '3. ', '4. ', '5. '
                    ]
                    if any(marker in first_few_lines for marker in markdown_patterns):
                        return '.md'
                    
                    # Check for HTML
                    if any(tag in first_few_lines for tag in ['<html', '<div', '<body', '<!doctype', '<head']):
                        return '.html'
                    
                    # Check for JSON
                    if first_few_lines.strip().startswith('{') and '"' in first_few_lines:
                        return '.json'
                    
                    # Check for XML
                    if first_few_lines.strip().startswith('<') and any(tag in first_few_lines for tag in ['<?xml', '<root', '<config']):
                        return '.xml'
                        
            except Exception:
                pass  # If we can't read as text, fall back to default

        # Default fallback based on major type
        if mime_type.startswith('text/'):
            return '.txt'
        elif mime_type.startswith('image/'):
            return '.img'
        elif mime_type.startswith('video/'):
            return '.video'
        elif mime_type.startswith('audio/'):
            return '.audio'
        else:
            return '.bin'

    def _move_to_completed(self, temp_path: Path, checksum: str) -> Path:
        """
        Move downloaded file to completed directory with proper extension

        Args:
            temp_path: Temporary file path
            checksum: File checksum for naming

        Returns:
            Path: Final file path with correct extension
        """
        # Detect MIME type first
        mime_type = self._detect_mime_type(temp_path)
        
        # Get proper extension based on content
        proper_extension = self._detect_proper_extension(temp_path, mime_type)
        
        # Create platform-specific subdirectory
        platform_dir = self.completed_dir / self.get_platform_name()
        platform_dir.mkdir(parents=True, exist_ok=True)

        # Use checksum as filename with proper extension
        final_filename = f"{checksum[:16]}{proper_extension}"
        final_path = platform_dir / final_filename

        # Move file
        import shutil
        shutil.move(str(temp_path), str(final_path))

        logger.info(f"Moved file with proper extension: {final_filename}")
        return final_path
