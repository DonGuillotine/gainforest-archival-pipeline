"""
Archive manager to coordinate downloads, uploads, and database tracking
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from src.config.logging_config import get_logger
from src.core.database import DatabaseManager
from src.core.models import ExternalLink
from src.handlers.download_manager import DownloadManager
from src.storage.content_handler import IPFSContentHandler, ContentMetadata
from src.storage.ipfs_client import IPFSUploadManager

logger = get_logger(__name__)


class ArchiveManager:
    """
    Orchestrates the complete archival pipeline:
    1. Download content from external sources
    2. Upload to IPFS for permanent storage
    3. Track in database
    """

    def __init__(
            self,
            download_manager: Optional[DownloadManager] = None,
            upload_manager: Optional[IPFSUploadManager] = None,
            database: Optional[DatabaseManager] = None
    ):
        """
        Initialize archive manager

        Args:
            download_manager: Download manager instance
            upload_manager: IPFS upload manager instance
            database: Database manager instance
        """
        self.download_manager = download_manager or DownloadManager()
        self.upload_manager = upload_manager or IPFSUploadManager()
        self.content_handler = IPFSContentHandler(self.upload_manager)
        self.database = database or DatabaseManager()

        logger.info("Initialized ArchiveManager")

    def archive_link(
            self,
            link: ExternalLink,
            ecocert_id: str,
            attestation_uid: str
    ) -> Dict[str, Any]:
        """
        Archive a single external link

        Args:
            link: External link to archive
            ecocert_id: Ecocert identifier
            attestation_uid: Attestation UID

        Returns:
            Dict: Archive result
        """
        result = {
            "url": link.url,
            "success": False,
            "ipfs_hash": None,
            "error": None,
            "steps": {}
        }

        try:
            # Step 1: Download content
            logger.info(f"Downloading content from: {link.url}")
            download_result = self.download_manager.download_content(link.url)

            result["steps"]["download"] = {
                "success": download_result.success,
                "file_size": download_result.file_size,
                "mime_type": download_result.mime_type,
                "error": download_result.error
            }

            if not download_result.success:
                result["error"] = f"Download failed: {download_result.error}"
                return result

            # Step 2: Prepare metadata
            content_metadata = ContentMetadata(
                ecocert_id=ecocert_id,
                attestation_uid=attestation_uid,
                original_url=link.url,
                content_type=link.detect_content_type().value,
                platform=download_result.metadata.get("platform", "unknown"),
                file_name=download_result.file_path.name,
                file_size=download_result.file_size,
                mime_type=download_result.mime_type,
                checksum=download_result.checksum,
                download_timestamp=datetime.now(timezone.utc).isoformat()
            )

            # Step 3: Upload to IPFS
            logger.info(f"Uploading to IPFS: {download_result.file_path.name}")
            upload_result = self.content_handler.upload_content(
                download_result.file_path,
                content_metadata
            )

            result["steps"]["upload"] = {
                "success": upload_result.success,
                "ipfs_hash": upload_result.ipfs_hash,
                "gateway_url": upload_result.gateway_url,
                "error": upload_result.error
            }

            if not upload_result.success:
                result["error"] = f"Upload failed: {upload_result.error}"
                return result

            # Step 4: Save to database
            logger.info(f"Saving to database: {upload_result.ipfs_hash}")

            db_id = self.database.insert_archived_content(
                ecocert_id=ecocert_id,
                attestation_uid=attestation_uid,
                original_url=link.url,
                content_type=content_metadata.content_type,
                ipfs_hash=upload_result.ipfs_hash,
                file_size=download_result.file_size,
                mime_type=download_result.mime_type,
                metadata={
                    "platform": content_metadata.platform,
                    "file_name": content_metadata.file_name,
                    "checksum": content_metadata.checksum,
                    "gateway_url": upload_result.gateway_url,
                    "download_time": download_result.download_time,
                    "upload_time": upload_result.upload_time
                }
            )

            result["steps"]["database"] = {
                "success": True,
                "record_id": db_id
            }

            # Success!
            result["success"] = True
            result["ipfs_hash"] = upload_result.ipfs_hash

            logger.info(f"Successfully archived {link.url} to IPFS: {upload_result.ipfs_hash}")

        except Exception as e:
            logger.error(f"Archive failed for {link.url}: {e}")
            result["error"] = str(e)

        return result

    def archive_ecocert_links(
            self,
            ecocert_id: str,
            attestation_uid: str,
            links: List[ExternalLink]
    ) -> Dict[str, Any]:
        """
        Archive all links for an ecocert

        Args:
            ecocert_id: Ecocert identifier
            attestation_uid: Attestation UID
            links: List of external links

        Returns:
            Dict: Archive results
        """
        from src.core.database import ProcessingStatusEnum

        results = {
            "ecocert_id": ecocert_id,
            "total_links": len(links),
            "successful": 0,
            "failed": 0,
            "archived_content": []
        }

        # Update processing status
        self.database.update_processing_status(
            ecocert_id=ecocert_id,
            status=ProcessingStatusEnum.PROCESSING,
            total_links=len(links)
        )

        # Process each link sequentially
        for i, link in enumerate(links):
            logger.info(f"Processing link {i + 1}/{len(links)} for {ecocert_id}")

            # Archive the link
            archive_result = self.archive_link(link, ecocert_id, attestation_uid)

            if archive_result["success"]:
                results["successful"] += 1
                results["archived_content"].append({
                    "url": link.url,
                    "ipfs_hash": archive_result["ipfs_hash"]
                })
            else:
                results["failed"] += 1

                # Log error to database
                self.database.log_error(
                    error_type="archive_error",
                    error_message=archive_result["error"],
                    ecocert_id=ecocert_id,
                    url=link.url
                )

            # Update progress
            self.database.update_processing_status(
                ecocert_id=ecocert_id,
                status=ProcessingStatusEnum.PROCESSING,
                processed_links=i + 1,
                failed_links=results["failed"]
            )

        # Final status update
        final_status = ProcessingStatusEnum.COMPLETED if results["failed"] == 0 else ProcessingStatusEnum.FAILED
        self.database.update_processing_status(
            ecocert_id=ecocert_id,
            status=final_status,
            processed_links=len(links),
            failed_links=results["failed"]
        )

        logger.info(
            f"Archival complete for {ecocert_id}: "
            f"{results['successful']} successful, {results['failed']} failed"
        )

        return results

    def get_archive_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about archived content

        Returns:
            Dict: Archive statistics
        """
        stats = self.database.get_statistics()

        # Add IPFS-specific stats if available
        try:
            usage_stats = self.upload_manager.pinata.get_usage_stats()
            if usage_stats:
                stats["ipfs_usage"] = {
                    "pin_count": usage_stats.get("pin_count"),
                    "pin_size_total": usage_stats.get("pin_size_total"),
                    "pin_size_total_mb": usage_stats.get("pin_size_total", 0) / (1024 * 1024)
                }
        except Exception as e:
            logger.warning(f"Could not get IPFS usage stats: {e}")

        return stats
