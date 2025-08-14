"""
Base content handler with common functionality for all download handlers
"""
import hashlib
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Tuple

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import get_settings
from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class DownloadProgress:
    """Download progress information"""
    total_bytes: int
    downloaded_bytes: int
    percentage: float
    speed: float
    eta: int
    status: str
    message: Optional[str] = None


@dataclass
class DownloadResult:
    """Result of a download operation"""
    success: bool
    file_path: Optional[Path] = None
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    checksum: Optional[str] = None
    metadata: Dict[str, Any] = None
    error: Optional[str] = None
    download_time: Optional[float] = None


class BaseContentHandler(ABC):
    """
    Abstract base class for content download handlers
    """

    def __init__(self):
        """Initialize base handler"""
        self.settings = get_settings()
        self.chunk_size = 8192
        self.timeout = 300
        self.max_file_size = self.settings.MAX_FILE_SIZE

        # Create temp directory
        self.temp_dir = Path("downloads/temp")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Create completed directory
        self.completed_dir = Path("downloads/completed")
        self.completed_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initialized {self.__class__.__name__}")

    @abstractmethod
    def can_handle(self, url: str) -> bool:
        """
        Check if this handler can process the given URL

        Args:
            url: URL to check

        Returns:
            bool: True if this handler can process the URL
        """
        pass

    @abstractmethod
    def get_download_url(self, url: str) -> str:
        """
        Convert the public URL to a direct download URL

        Args:
            url: Public URL

        Returns:
            str: Direct download URL
        """
        pass

    @abstractmethod
    def get_platform_name(self) -> str:
        """
        Get the platform name for organizing downloads

        Returns:
            str: Platform name (e.g., 'google_drive', 'youtube')
        """
        pass

    def download(
            self,
            url: str,
            progress_callback: Optional[Callable[[DownloadProgress], None]] = None
    ) -> DownloadResult:
        """
        Download content from URL

        Args:
            url: URL to download from
            progress_callback: Optional callback for progress updates

        Returns:
            DownloadResult: Result of the download operation
        """
        start_time = time.time()

        try:
            # Get direct download URL
            download_url = self.get_download_url(url)
            logger.info(f"Starting download from: {url}")

            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(
                dir=self.temp_dir,
                delete=False,
                suffix=self._get_file_extension(url)
            )
            temp_path = Path(temp_file.name)
            temp_file.close()  # Close the file handle to prevent WinError 32

            # Download with progress tracking
            downloaded_size = self._download_with_progress(
                download_url,
                temp_path,
                progress_callback
            )

            # Validate downloaded content
            is_valid, error_msg = self.validate_content(temp_path)
            if not is_valid:
                temp_path.unlink(missing_ok=True)
                return DownloadResult(
                    success=False,
                    error=f"Content validation failed: {error_msg}"
                )

            # Calculate checksum
            checksum = self._calculate_checksum(temp_path)

            # Detect MIME type
            mime_type = self._detect_mime_type(temp_path)

            # Move to completed directory
            final_path = self._move_to_completed(temp_path, checksum)

            # Extract minimal metadata
            metadata = self.extract_metadata(final_path, url)

            download_time = time.time() - start_time

            logger.info(f"Successfully downloaded {url} in {download_time:.2f}s")

            return DownloadResult(
                success=True,
                file_path=final_path,
                file_size=downloaded_size,
                mime_type=mime_type,
                checksum=checksum,
                metadata=metadata,
                download_time=download_time
            )

        except Exception as e:
            logger.error(f"Download failed for {url}: {e}")
            return DownloadResult(
                success=False,
                error=str(e),
                download_time=time.time() - start_time
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    def _download_with_progress(
            self,
            url: str,
            output_path: Path,
            progress_callback: Optional[Callable] = None
    ) -> int:
        """
        Download file with progress tracking and retry logic

        Args:
            url: Direct download URL
            output_path: Path to save the file
            progress_callback: Optional progress callback

        Returns:
            int: Total downloaded size in bytes
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = requests.get(url, headers=headers, stream=True, timeout=30)
        response.raise_for_status()

        # Get total file size from headers
        content_length = response.headers.get('content-length', '0')
        try:
            total_size = int(content_length) if content_length else 0
        except (ValueError, TypeError):
            total_size = 0
            
        # Log if we don't have content-length for debugging
        if total_size == 0:
            logger.debug(f"No content-length header found, progress will show downloaded bytes only")

        # Check file size limit
        if total_size > self.max_file_size:
            raise ValueError(f"File too large: {total_size} bytes (max: {self.max_file_size})")

        downloaded = 0
        start_time = time.time()

        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=self.chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)

                    # Update progress
                    if progress_callback:
                        elapsed = time.time() - start_time
                        speed = downloaded / elapsed if elapsed > 0 else 0
                        
                        if total_size > 0:
                            percentage = (downloaded / total_size) * 100
                            eta = int((total_size - downloaded) / speed) if speed > 0 else 0
                        else:
                            percentage = 0.0  # Unknown progress percentage
                            eta = 0

                        progress = DownloadProgress(
                            total_bytes=total_size,
                            downloaded_bytes=downloaded,
                            percentage=percentage,
                            speed=speed,
                            eta=eta,
                            status="downloading"
                        )
                        progress_callback(progress)

        # Final progress update
        if progress_callback:
            progress = DownloadProgress(
                total_bytes=downloaded,
                downloaded_bytes=downloaded,
                percentage=100.0,
                speed=0,
                eta=0,
                status="complete"
            )
            progress_callback(progress)

        return downloaded

    def validate_content(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        """
        Validate downloaded content

        Args:
            file_path: Path to the downloaded file

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Check file exists and is not empty
        if not file_path.exists():
            return False, "File does not exist"

        file_size = file_path.stat().st_size
        if file_size == 0:
            return False, "File is empty"

        if file_size > self.max_file_size:
            return False, f"File exceeds size limit: {file_size} bytes"

        # Additional validation can be implemented by subclasses
        return True, None

    def extract_metadata(self, file_path: Path, original_url: str) -> Dict[str, Any]:
        """
        Extract minimal metadata from downloaded content

        Args:
            file_path: Path to the downloaded file
            original_url: Original URL

        Returns:
            Dict[str, Any]: Minimal metadata
        """
        return {
            "original_url": original_url,
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size,
            "download_timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": self.get_platform_name()
        }

    def _calculate_checksum(self, file_path: Path) -> str:
        """
        Calculate SHA256 checksum of file

        Args:
            file_path: Path to file

        Returns:
            str: SHA256 hex digest
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _detect_mime_type(self, file_path: Path) -> str:
        """
        Detect MIME type of file

        Args:
            file_path: Path to file

        Returns:
            str: MIME type
        """
        import magic

        try:
            mime = magic.from_file(str(file_path), mime=True)
            return mime
        except Exception as e:
            logger.warning(f"Could not detect MIME type: {e}")
            return "application/octet-stream"

    def _move_to_completed(self, temp_path: Path, checksum: str) -> Path:
        """
        Move downloaded file to completed directory

        Args:
            temp_path: Temporary file path
            checksum: File checksum for naming

        Returns:
            Path: Final file path
        """
        # Create platform-specific subdirectory
        platform_dir = self.completed_dir / self.get_platform_name()
        platform_dir.mkdir(parents=True, exist_ok=True)

        # Use checksum as filename to avoid duplicates
        extension = temp_path.suffix
        final_filename = f"{checksum[:16]}{extension}"
        final_path = platform_dir / final_filename

        # Move file
        shutil.move(str(temp_path), str(final_path))

        return final_path

    def _get_file_extension(self, url: str) -> str:
        """
        Get file extension from URL or return default

        Args:
            url: URL to parse

        Returns:
            str: File extension with dot
        """
        # Override in subclasses for specific platforms
        return ".tmp"

    def cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self.temp_dir.glob("*"):
            try:
                if temp_file.is_file():
                    # Only remove files older than 1 hour
                    age = time.time() - temp_file.stat().st_mtime
                    if age > 3600:
                        temp_file.unlink()
                        logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.warning(f"Could not clean up {temp_file}: {e}")
