"""
Download manager to orchestrate content downloads
"""
from dataclasses import dataclass
from typing import List, Dict, Optional

from src.config.logging_config import get_logger
from src.core.models import ExternalLink
from src.handlers.base import BaseContentHandler, DownloadResult, DownloadProgress
from src.handlers.google_drive import GoogleDriveHandler
from src.handlers.youtube import YouTubeHandler

logger = get_logger(__name__)


@dataclass
class BatchDownloadResult:
    """Result of batch download operation"""
    total_links: int
    successful_downloads: int
    failed_downloads: int
    results: Dict[str, DownloadResult]
    total_size: int
    total_time: float


class DownloadManager:
    """
    Manages sequential downloads from different platforms
    """

    def __init__(self):
        """Initialize download manager with handlers"""
        self.handlers = [
            GoogleDriveHandler(),
            YouTubeHandler()
        ]
        logger.info("Initialized DownloadManager with 2 handlers")

    def get_handler(self, url: str) -> Optional[BaseContentHandler]:
        """
        Get appropriate handler for URL

        Args:
            url: URL to process

        Returns:
            Optional[BaseContentHandler]: Handler that can process the URL
        """
        for handler in self.handlers:
            if handler.can_handle(url):
                return handler
        return None

    def download_content(
            self,
            url: str,
            progress_callback: Optional[callable] = None
    ) -> DownloadResult:
        """
        Download content from URL using appropriate handler

        Args:
            url: URL to download from
            progress_callback: Optional progress callback

        Returns:
            DownloadResult: Download result
        """
        # Get appropriate handler
        handler = self.get_handler(url)

        if not handler:
            logger.warning(f"No handler found for URL: {url}")
            return DownloadResult(
                success=False,
                error="No handler available for this URL type"
            )

        logger.info(f"Using {handler.__class__.__name__} for {url}")

        # Download content
        return handler.download(url, progress_callback)

    def download_batch(
            self,
            links: List[ExternalLink],
            progress_callback: Optional[callable] = None
    ) -> BatchDownloadResult:
        """
        Download multiple links sequentially (no concurrency per requirements)

        Args:
            links: List of external links to download
            progress_callback: Optional callback for overall progress

        Returns:
            BatchDownloadResult: Batch download results
        """
        import time

        start_time = time.time()
        results = {}
        successful = 0
        failed = 0
        total_size = 0

        logger.info(f"Starting batch download of {len(links)} links")

        for i, link in enumerate(links):
            # Update overall progress
            if progress_callback:
                overall_progress = DownloadProgress(
                    total_bytes=len(links),
                    downloaded_bytes=i,
                    percentage=(i / len(links)) * 100,
                    speed=0,
                    eta=0,
                    status=f"Processing link {i + 1}/{len(links)}",
                    message=f"Downloading: {link.url}"
                )
                progress_callback(overall_progress)

            # Download the content
            result = self.download_content(link.url)
            results[link.url] = result

            if result.success:
                successful += 1
                if result.file_size:
                    total_size += result.file_size
                logger.info(f"Successfully downloaded {link.url}")
            else:
                failed += 1
                logger.error(f"Failed to download {link.url}: {result.error}")

        # Final progress update
        if progress_callback:
            overall_progress = DownloadProgress(
                total_bytes=len(links),
                downloaded_bytes=len(links),
                percentage=100.0,
                speed=0,
                eta=0,
                status="Complete",
                message=f"Downloaded {successful}/{len(links)} files"
            )
            progress_callback(overall_progress)

        total_time = time.time() - start_time

        logger.info(
            f"Batch download complete: {successful} successful, "
            f"{failed} failed, {total_size} bytes in {total_time:.2f}s"
        )

        return BatchDownloadResult(
            total_links=len(links),
            successful_downloads=successful,
            failed_downloads=failed,
            results=results,
            total_size=total_size,
            total_time=total_time
        )

    def cleanup_temp_files(self):
        """Clean up temporary files from all handlers"""
        for handler in self.handlers:
            handler.cleanup_temp_files()
        logger.info("Cleaned up temporary files")
