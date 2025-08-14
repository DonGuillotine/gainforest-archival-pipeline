"""
Handler for Google Drive and Google Docs content
"""
import re
import time
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import parse_qs, urlparse

import requests
from bs4 import BeautifulSoup

from src.config.logging_config import get_logger
from src.handlers.base import BaseContentHandler, DownloadResult

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
            'drive_folder': re.compile(r'drive\.google\.com/drive/folders/([a-zA-Z0-9_-]+)'),
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

        elif service_type == 'drive_folder':
            # For folders, we'll create a special download URL that we'll handle in our download method
            download_url = f"https://drive.google.com/drive/folders/{file_id}"
            logger.info(f"Generated folder download URL for folder ID: {file_id}")

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

    def download(self, url: str, progress_callback: Optional[callable] = None) -> DownloadResult:
        """
        Download Google Drive content (files or folders) with retry strategies

        Args:
            url: Google Drive URL
            progress_callback: Optional callback for progress updates

        Returns:
            DownloadResult: Result of the download operation
        """
        start_time = time.time()

        try:
            file_id, service_type = self._extract_file_info(url)
            
            if service_type == 'drive_folder':
                # Handle folder downloads
                return self._download_folder(url, file_id, progress_callback, start_time)
            elif service_type == 'drive':
                # Handle regular Drive files with retry strategies
                return self._download_drive_file_with_retry(url, file_id, progress_callback, start_time)
            else:
                # Handle Google Docs/Sheets/Slides using base class method
                return super().download(url, progress_callback)

        except Exception as e:
            logger.error(f"Google Drive download failed for {url}: {e}")
            return DownloadResult(
                success=False,
                error=str(e),
                download_time=time.time() - start_time
            )

    def _download_drive_file_with_retry(self, url: str, file_id: str, progress_callback: Optional[callable], start_time: float) -> DownloadResult:
        """
        Download a Google Drive file with multiple retry strategies

        Args:
            url: Original Drive file URL
            file_id: Extracted file ID
            progress_callback: Progress callback function
            start_time: Download start time

        Returns:
            DownloadResult: Result of the download operation
        """
        # Try multiple download URL strategies
        download_strategies = [
            # Strategy 1: Standard export download
            f"https://drive.google.com/uc?export=download&id={file_id}",
            # Strategy 2: Direct download attempt
            f"https://drive.google.com/file/d/{file_id}/view?usp=sharing",
            # Strategy 3: Alternative export format
            f"https://drive.google.com/uc?id={file_id}&export=download",
            # Strategy 4: Force download with confirmation bypass
            f"https://drive.google.com/uc?export=download&id={file_id}&confirm=t",
        ]

        last_error = None
        
        for strategy_idx, download_url in enumerate(download_strategies):
            try:
                if strategy_idx > 0:
                    logger.info(f"Trying Google Drive download strategy {strategy_idx + 1}")
                
                # Create a temporary modified URL for this strategy
                temp_url = download_url
                
                # Use the base class download method but override the download URL temporarily
                original_get_download_url = self.get_download_url
                
                def temp_get_download_url(url_param):
                    return download_url
                
                # Temporarily override the method
                self.get_download_url = temp_get_download_url
                
                try:
                    result = super().download(temp_url, progress_callback)
                    
                    # If successful, check if we got actual content or HTML
                    if result.success and result.file_path:
                        # Quick validation to see if we got HTML instead of file
                        with open(result.file_path, 'rb') as f:
                            first_bytes = f.read(1024)
                        
                        if b'<!DOCTYPE html' in first_bytes or b'<html' in first_bytes:
                            # We got HTML - this strategy failed, try next
                            if result.file_path.exists():
                                result.file_path.unlink()
                            logger.warning(f"Strategy {strategy_idx + 1} returned HTML page instead of file")
                            continue
                        else:
                            # Success with actual content
                            if strategy_idx > 0:
                                logger.info(f"Successfully downloaded with strategy {strategy_idx + 1}")
                            return result
                    elif not result.success:
                        # This strategy failed, try next
                        last_error = result.error
                        continue
                
                finally:
                    # Restore original method
                    self.get_download_url = original_get_download_url
                    
            except Exception as e:
                logger.warning(f"Google Drive strategy {strategy_idx + 1} failed: {e}")
                last_error = str(e)
                continue
        
        # All strategies failed
        return DownloadResult(
            success=False,
            error=f"All download strategies failed. Last error: {last_error}",
            download_time=time.time() - start_time
        )

    def _download_folder(self, url: str, folder_id: str, progress_callback: Optional[callable], start_time: float) -> DownloadResult:
        """
        Download a Google Drive folder by scraping public folder contents and creating a ZIP

        Args:
            url: Original folder URL
            folder_id: Extracted folder ID
            progress_callback: Progress callback function
            start_time: Download start time

        Returns:
            DownloadResult: Result of the download operation
        """
        from src.handlers.base import DownloadProgress

        try:
            if progress_callback:
                progress_callback(DownloadProgress(
                    total_bytes=0,
                    downloaded_bytes=0,
                    percentage=0.0,
                    speed=0,
                    eta=0,
                    status='downloading',
                    message=f"Accessing folder contents..."
                ))

            # Try to get folder contents via Google Drive's public folder view
            folder_files = self._get_folder_files(folder_id)
            
            if not folder_files:
                return DownloadResult(
                    success=False,
                    error="Could not access folder contents. Folder may be private or empty.",
                    download_time=time.time() - start_time
                )

            # Create ZIP file with folder contents
            zip_path = self._create_folder_zip(folder_id, folder_files, progress_callback)
            
            if not zip_path or not zip_path.exists():
                return DownloadResult(
                    success=False,
                    error="Failed to create folder archive",
                    download_time=time.time() - start_time
                )

            # Validate the ZIP file
            is_valid, error_msg = self.validate_content(zip_path)
            if not is_valid:
                zip_path.unlink(missing_ok=True)
                return DownloadResult(
                    success=False,
                    error=f"Content validation failed: {error_msg}",
                    download_time=time.time() - start_time
                )

            # Calculate checksum
            checksum = self._calculate_checksum(zip_path)

            # Detect MIME type
            mime_type = self._detect_mime_type(zip_path)

            # Move to completed directory
            final_path = self._move_to_completed(zip_path, checksum)

            # Extract metadata
            metadata = self.extract_metadata(final_path, url)
            metadata.update({
                'folder_id': folder_id,
                'folder_files_count': len(folder_files),
                'content_type': 'folder_archive'
            })

            download_time = time.time() - start_time
            logger.info(f"Successfully downloaded Google Drive folder {url} with {len(folder_files)} files in {download_time:.2f}s")

            return DownloadResult(
                success=True,
                file_path=final_path,
                file_size=final_path.stat().st_size,
                mime_type=mime_type,
                checksum=checksum,
                metadata=metadata,
                download_time=download_time
            )

        except Exception as e:
            logger.error(f"Folder download failed for {url}: {e}")
            return DownloadResult(
                success=False,
                error=str(e),
                download_time=time.time() - start_time
            )

    def _get_folder_files(self, folder_id: str) -> List[Dict[str, str]]:
        """
        Get files from a public Google Drive folder by scraping the public view

        Args:
            folder_id: Google Drive folder ID

        Returns:
            List[Dict]: List of file information dictionaries
        """
        try:
            # Use Google Drive's public folder view endpoint
            folder_url = f"https://drive.google.com/drive/folders/{folder_id}"
            
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            response = session.get(folder_url, timeout=30)
            response.raise_for_status()
            
            # Try to extract file information from the HTML
            # This is a simplified approach - in production, you might want to use Google Drive API
            files = []
            
            # Look for file download links in the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find script tags that contain file data
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and 'drive.google.com/file/d/' in script.string:
                    # Extract file IDs from the script content
                    import json
                    script_content = script.string
                    
                    # Look for file ID patterns in the script
                    file_id_pattern = r'drive\.google\.com/file/d/([a-zA-Z0-9_-]+)'
                    file_ids = re.findall(file_id_pattern, script_content)
                    
                    for file_id in file_ids[:10]:  # Limit to 10 files to avoid overwhelming
                        files.append({
                            'id': file_id,
                            'name': f'file_{file_id}',
                            'download_url': f'https://drive.google.com/uc?export=download&id={file_id}'
                        })
                        
            # Remove duplicates
            seen_ids = set()
            unique_files = []
            for file_info in files:
                if file_info['id'] not in seen_ids:
                    seen_ids.add(file_info['id'])
                    unique_files.append(file_info)
                    
            logger.info(f"Found {len(unique_files)} files in folder {folder_id}")
            return unique_files[:10]  # Limit to 10 files
            
        except Exception as e:
            logger.error(f"Failed to get folder files for {folder_id}: {e}")
            return []

    def _create_folder_zip(self, folder_id: str, folder_files: List[Dict[str, str]], progress_callback: Optional[callable]) -> Optional[Path]:
        """
        Create a ZIP file containing all files from the folder

        Args:
            folder_id: Google Drive folder ID
            folder_files: List of file information
            progress_callback: Progress callback function

        Returns:
            Optional[Path]: Path to created ZIP file
        """
        from src.handlers.base import DownloadProgress
        
        try:
            zip_filename = f"folder_{folder_id}.zip"
            zip_path = self.temp_dir / zip_filename
            
            total_files = len(folder_files)
            downloaded_files = 0
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                for i, file_info in enumerate(folder_files):
                    try:
                        if progress_callback:
                            progress = (i / total_files) * 100
                            progress_callback(DownloadProgress(
                                total_bytes=total_files,
                                downloaded_bytes=i,
                                percentage=progress,
                                speed=0,
                                eta=0,
                                status='downloading',
                                message=f"Downloading file {i+1}/{total_files}: {file_info.get('name', 'Unknown')}"
                            ))
                        
                        # Download file content
                        response = session.get(file_info['download_url'], timeout=30, stream=True)
                        
                        if response.status_code == 200:
                            # Check if we got actual file content (not HTML error page)
                            content_type = response.headers.get('content-type', '').lower()
                            if 'text/html' not in content_type:
                                file_content = response.content
                                if len(file_content) > 100:  # Ensure we got actual content
                                    zip_file.writestr(f"{file_info['name']}", file_content)
                                    downloaded_files += 1
                                    logger.info(f"Added file {file_info['name']} to ZIP ({len(file_content)} bytes)")
                            else:
                                logger.warning(f"Skipped file {file_info['name']} - got HTML response")
                        else:
                            logger.warning(f"Failed to download file {file_info['name']}: HTTP {response.status_code}")
                            
                    except Exception as e:
                        logger.warning(f"Failed to download file {file_info.get('name', 'Unknown')}: {e}")
                        continue
                        
            if downloaded_files == 0:
                # No files were successfully downloaded
                zip_path.unlink(missing_ok=True)
                logger.error(f"No files could be downloaded from folder {folder_id}")
                return None
                
            if progress_callback:
                progress_callback(DownloadProgress(
                    total_bytes=total_files,
                    downloaded_bytes=total_files,
                    percentage=100.0,
                    speed=0,
                    eta=0,
                    status='complete',
                    message=f"Created folder archive with {downloaded_files} files"
                ))
                
            logger.info(f"Created ZIP archive with {downloaded_files}/{total_files} files: {zip_path}")
            return zip_path
            
        except Exception as e:
            logger.error(f"Failed to create folder ZIP: {e}")
            return None

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
                if pattern_name == 'drive_folder':
                    return file_id, 'drive_folder'
                elif 'drive' in pattern_name:
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
        elif service_type == 'drive_folder':
            return '.zip'
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
