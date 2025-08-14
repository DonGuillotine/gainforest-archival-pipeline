"""
Handler for YouTube video content using yt-dlp
"""
from pathlib import Path
from typing import Optional, Dict, Any

import yt_dlp
from yt_dlp import YoutubeDL

from src.config.logging_config import get_logger
from src.handlers.base import BaseContentHandler, DownloadResult

logger = get_logger(__name__)


class YouTubeHandler(BaseContentHandler):
    """
    Handler for downloading YouTube videos
    Downloads actual video content (not just metadata)
    """

    def __init__(self):
        """Initialize YouTube handler"""
        super().__init__()

        # yt-dlp options for downloading
        self.ydl_opts = {
            'format': 'best[height<=720]/best[height<=1080]/best',  # More flexible format selection
            'outtmpl': str(self.temp_dir / '%(id)s.%(ext)s'),
            'quiet': True,
            'no_warnings': True,
            'extract_flat': False,
            'max_filesize': self.max_file_size,
            'socket_timeout': 30,
            'retries': 3,
            'fragment_retries': 3,
            'continuedl': True,
            'noprogress': False,
            'logger': logger,
            'progress_hooks': [],
            'no_playlist': True,
            'age_limit': None,
            'geo_bypass': False,
            'writethumbnail': False,
            'writesubtitles': False,
            'writeautomaticsub': False,
            'writedescription': False,
            'writeinfojson': False,
        }

        # Maximum video duration (30 minutes)
        self.max_duration = 1800  # seconds

    def can_handle(self, url: str) -> bool:
        """
        Check if this handler can process the given URL

        Args:
            url: URL to check

        Returns:
            bool: True if this is a YouTube URL
        """
        url_lower = url.lower()
        return any([
            'youtube.com' in url_lower,
            'youtu.be' in url_lower
        ])

    def get_download_url(self, url: str) -> str:
        """
        YouTube URLs are used directly with yt-dlp

        Args:
            url: YouTube URL

        Returns:
            str: Same URL (yt-dlp handles it)
        """
        return url

    def get_platform_name(self) -> str:
        """
        Get the platform name for organizing downloads

        Returns:
            str: Platform name
        """
        return "youtube"

    def download(
            self,
            url: str,
            progress_callback: Optional[callable] = None
    ) -> "DownloadResult":
        """
        Download YouTube video

        Args:
            url: YouTube URL
            progress_callback: Optional callback for progress updates

        Returns:
            DownloadResult: Result of the download operation
        """
        from src.handlers.base import DownloadResult, DownloadProgress
        import time

        start_time = time.time()

        try:
            # First, check video info
            video_info = self._get_video_info(url)

            if not video_info:
                return DownloadResult(
                    success=False,
                    error="Could not retrieve video information"
                )

            # Validate video before downloading
            is_valid, error_msg = self._validate_video_info(video_info)
            if not is_valid:
                return DownloadResult(
                    success=False,
                    error=error_msg
                )

            # Setup progress hook if callback provided
            if progress_callback:
                # Send initial progress
                progress_callback(DownloadProgress(
                    total_bytes=0,
                    downloaded_bytes=0,
                    percentage=0.0,
                    speed=0,
                    eta=0,
                    status='downloading',
                    message=f"Preparing to download {video_info.get('title', 'video')}"
                ))

                def progress_hook(d):
                    if d['status'] == 'downloading':
                        total = d.get('total_bytes') or d.get('total_bytes_estimate', 0)
                        downloaded = d.get('downloaded_bytes', 0)

                        if total > 0:
                            percentage = (downloaded / total) * 100
                            speed = d.get('speed', 0) or 0
                            eta = d.get('eta', 0) or 0

                            progress = DownloadProgress(
                                total_bytes=total,
                                downloaded_bytes=downloaded,
                                percentage=percentage,
                                speed=speed,
                                eta=eta,
                                status='downloading'
                            )
                            progress_callback(progress)

                    elif d['status'] == 'finished':
                        total_bytes = d.get('total_bytes', 0)
                        progress = DownloadProgress(
                            total_bytes=total_bytes,
                            downloaded_bytes=total_bytes,
                            percentage=100.0,
                            speed=0,
                            eta=0,
                            status='complete'
                        )
                        progress_callback(progress)

                self.ydl_opts['progress_hooks'] = [progress_hook]

            # Download the video
            downloaded_path = self._download_video(url, video_info)

            if not downloaded_path or not downloaded_path.exists():
                return DownloadResult(
                    success=False,
                    error="Download failed - file not created"
                )

            # Validate downloaded content
            is_valid, error_msg = self.validate_content(downloaded_path)
            if not is_valid:
                downloaded_path.unlink(missing_ok=True)
                return DownloadResult(
                    success=False,
                    error=f"Content validation failed: {error_msg}"
                )

            # Calculate checksum
            checksum = self._calculate_checksum(downloaded_path)

            # Detect MIME type
            mime_type = self._detect_mime_type(downloaded_path)

            # Move to completed directory
            final_path = self._move_to_completed(downloaded_path, checksum)

            # Extract metadata
            metadata = self.extract_metadata(final_path, url)
            metadata.update({
                'video_id': video_info.get('id'),
                'title': video_info.get('title'),
                'duration': video_info.get('duration'),
                'uploader': video_info.get('uploader'),
                'upload_date': video_info.get('upload_date'),
            })

            download_time = time.time() - start_time

            logger.info(f"Successfully downloaded YouTube video {url} in {download_time:.2f}s")

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
            logger.error(f"YouTube download failed for {url}: {e}")
            return DownloadResult(
                success=False,
                error=str(e),
                download_time=time.time() - start_time
            )

    def _get_video_info(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get video information without downloading

        Args:
            url: YouTube URL

        Returns:
            Optional[Dict]: Video information
        """
        try:
            ydl_opts = {'quiet': True, 'no_warnings': True}
            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)

                # Extract relevant information
                return {
                    'id': info.get('id'),
                    'title': info.get('title'),
                    'duration': info.get('duration'),
                    'filesize': info.get('filesize') or info.get('filesize_approx'),
                    'uploader': info.get('uploader'),
                    'upload_date': info.get('upload_date'),
                    'ext': info.get('ext'),
                    'height': info.get('height'),
                    'width': info.get('width'),
                }
        except Exception as e:
            logger.error(f"Failed to get video info: {e}")
            return None

    def _validate_video_info(self, video_info: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate video before downloading

        Args:
            video_info: Video information dictionary

        Returns:
            tuple: (is_valid, error_message)
        """
        # Check duration
        duration = video_info.get('duration', 0)
        if duration > self.max_duration:
            return False, f"Video too long: {duration}s (max: {self.max_duration}s)"

        # Check estimated file size if available
        filesize = video_info.get('filesize')
        if filesize and filesize > self.max_file_size:
            return False, f"Video file too large: {filesize} bytes (max: {self.max_file_size})"

        return True, None

    def _download_video(self, url: str, video_info: Dict[str, Any]) -> Optional[Path]:
        """
        Download video using yt-dlp

        Args:
            url: YouTube URL
            video_info: Video information

        Returns:
            Optional[Path]: Path to downloaded file
        """
        try:
            with yt_dlp.YoutubeDL(self.ydl_opts) as ydl:
                ydl.download([url])

                # Find the downloaded file
                video_id = video_info.get('id')

                # Look for the file with video ID
                for file in self.temp_dir.glob(f"{video_id}.*"):
                    if file.is_file():
                        return file

                # If not found by ID, look for any recent video file
                mp4_files = list(self.temp_dir.glob("*.mp4"))
                if mp4_files:
                    # Return the most recent file
                    return max(mp4_files, key=lambda f: f.stat().st_mtime)

                return None

        except Exception as e:
            logger.error(f"yt-dlp download failed: {e}")
            return None

    def _get_file_extension(self, url: str) -> str:
        """
        Get file extension for YouTube videos

        Args:
            url: YouTube URL

        Returns:
            str: File extension
        """
        return '.mp4'

    def validate_content(self, file_path: Path) -> tuple[bool, Optional[str]]:
        """
        Validate downloaded YouTube video

        Args:
            file_path: Path to the downloaded file

        Returns:
            tuple: (is_valid, error_message)
        """
        # First, run base validation
        is_valid, error_msg = super().validate_content(file_path)
        if not is_valid:
            return is_valid, error_msg

        # Check MIME type
        mime_type = self._detect_mime_type(file_path)

        # Accept common video MIME types
        valid_video_types = [
            'video/mp4',
            'video/webm',
            'video/x-matroska',
            'video/quicktime',
            'application/octet-stream'
        ]

        if mime_type not in valid_video_types:
            logger.warning(f"Unexpected video MIME type: {mime_type}")
            # Don't fail - yt-dlp might download in different formats

        return True, None
