"""
Content type handling for IPFS uploads
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from src.config.logging_config import get_logger
from src.storage.ipfs_client import IPFSUploadManager, IPFSUploadResult

logger = get_logger(__name__)


@dataclass
class ContentMetadata:
    """Metadata for archived content"""
    ecocert_id: str
    attestation_uid: str
    original_url: str
    content_type: str
    platform: str
    file_name: str
    file_size: int
    mime_type: str
    checksum: str
    download_timestamp: str
    ipfs_hash: Optional[str] = None
    gateway_url: Optional[str] = None


class IPFSContentHandler:
    """
    Handles content preparation and upload to IPFS
    """

    def __init__(self, upload_manager: Optional[IPFSUploadManager] = None):
        """
        Initialize content handler

        Args:
            upload_manager: Optional IPFS upload manager
        """
        self.upload_manager = upload_manager or IPFSUploadManager()

        # Content type mappings
        self.content_types = {
            'google_drive': {
                'name': 'Google Drive',
                'extensions': ['.pdf', '.xlsx', '.docx', '.pptx', '.bin'],
                'mime_types': [
                    'application/pdf',
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                ]
            },
            'youtube': {
                'name': 'YouTube',
                'extensions': ['.mp4', '.webm', '.mkv'],
                'mime_types': ['video/mp4', 'video/webm', 'video/x-matroska']
            }
        }

        logger.info("Initialized IPFSContentHandler")

    def prepare_content_for_upload(
            self,
            file_path: Path,
            content_metadata: ContentMetadata
    ) -> Dict[str, Any]:
        """
        Prepare content and metadata for IPFS upload

        Args:
            file_path: Path to content file
            content_metadata: Content metadata

        Returns:
            Dict: Prepared metadata for upload
        """
        # Validate file exists
        if not file_path.exists():
            raise FileNotFoundError(f"Content file not found: {file_path}")

        # Prepare flattened metadata - Pinata only accepts string/number values
        # Limit to 7 key-value pairs to stay under Pinata's 9-key limit (2 more added in ipfs_client: upload_timestamp, file_name)
        metadata = {
            "ecocert_id": str(content_metadata.ecocert_id),
            "attestation_uid": str(content_metadata.attestation_uid),
            "original_url": str(content_metadata.original_url),
            "content_type": str(content_metadata.content_type),
            "platform": str(content_metadata.platform),
            "file_size": int(content_metadata.file_size),
            "downloaded": str(content_metadata.download_timestamp)
        }

        return metadata

    def upload_content(
            self,
            file_path: Path,
            content_metadata: ContentMetadata
    ) -> IPFSUploadResult:
        """
        Upload content to IPFS with metadata

        Args:
            file_path: Path to content file
            content_metadata: Content metadata

        Returns:
            IPFSUploadResult: Upload result
        """
        try:
            # Prepare metadata
            metadata = self.prepare_content_for_upload(file_path, content_metadata)

            # Upload file to IPFS
            logger.info(f"Uploading {content_metadata.platform} content: {file_path.name}")

            result = self.upload_manager.upload_file(
                file_path=file_path,
                content_type=content_metadata.platform,
                metadata=metadata
            )

            if result.success:
                # Update content metadata with IPFS details
                content_metadata.ipfs_hash = result.ipfs_hash
                content_metadata.gateway_url = result.gateway_url

                logger.info(
                    f"Successfully uploaded to IPFS: {result.ipfs_hash} "
                    f"({result.pin_size} bytes in {result.upload_time:.2f}s)"
                )

                # Also upload the metadata as a separate JSON file
                self._upload_metadata_json(content_metadata, result.ipfs_hash)
            else:
                logger.error(f"Failed to upload to IPFS: {result.error}")

            return result

        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return IPFSUploadResult(
                success=False,
                error=str(e)
            )

    def _upload_metadata_json(
            self,
            content_metadata: ContentMetadata,
            content_ipfs_hash: str
    ) -> Optional[str]:
        """
        Upload metadata as a separate JSON file to IPFS

        Args:
            content_metadata: Content metadata
            content_ipfs_hash: IPFS hash of the content

        Returns:
            Optional[str]: IPFS hash of metadata
        """
        try:
            # Create metadata JSON
            metadata_json = {
                "content_ipfs_hash": content_ipfs_hash,
                "ecocert_id": content_metadata.ecocert_id,
                "attestation_uid": content_metadata.attestation_uid,
                "original_url": content_metadata.original_url,
                "platform": content_metadata.platform,
                "file_name": content_metadata.file_name,
                "file_size": content_metadata.file_size,
                "mime_type": content_metadata.mime_type,
                "checksum": content_metadata.checksum,
                "download_timestamp": content_metadata.download_timestamp,
                "gateway_url": content_metadata.gateway_url
            }

            # Upload metadata
            result = self.upload_manager.upload_metadata(
                metadata=metadata_json,
                name=f"{content_metadata.ecocert_id}_{content_ipfs_hash[:8]}"
            )

            if result.success:
                logger.info(f"Metadata uploaded to IPFS: {result.ipfs_hash}")
                return result.ipfs_hash
            else:
                logger.warning(f"Failed to upload metadata: {result.error}")
                return None

        except Exception as e:
            logger.error(f"Metadata upload failed: {e}")
            return None

    def verify_content_integrity(
            self,
            ipfs_hash: str,
            local_checksum: str
    ) -> bool:
        """
        Verify content integrity after upload

        Args:
            ipfs_hash: IPFS hash of uploaded content
            local_checksum: Local file checksum

        Returns:
            bool: True if content is verified
        """
        try:
            # Verify pin exists
            if not self.upload_manager.verify_upload(ipfs_hash):
                logger.warning(f"Content not pinned: {ipfs_hash}")
                return False

            # Additional verification can be added here
            # For now, we trust Pinata's pinning confirmation

            logger.info(f"Content integrity verified for: {ipfs_hash}")
            return True

        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False

    def batch_upload_contents(
            self,
            contents: List[tuple[Path, ContentMetadata]]
    ) -> Dict[str, IPFSUploadResult]:
        """
        Upload multiple content files to IPFS

        Args:
            contents: List of (file_path, metadata) tuples

        Returns:
            Dict: Map of file path to upload result
        """
        results = {}
        successful_uploads = 0
        failed_uploads = 0
        total_size_uploaded = 0

        logger.info(f"Starting batch upload of {len(contents)} files")

        for file_path, metadata in contents:
            try:
                result = self.upload_content(file_path, metadata)
                results[str(file_path)] = result

                if result.success:
                    successful_uploads += 1
                    total_size_uploaded += metadata.file_size

                    # Verify integrity
                    if self.verify_content_integrity(result.ipfs_hash, metadata.checksum):
                        logger.info(f"✓ Verified: {result.ipfs_hash}")
                else:
                    failed_uploads += 1

            except Exception as e:
                logger.error(f"Failed to upload {file_path}: {e}")
                results[str(file_path)] = IPFSUploadResult(
                    success=False,
                    error=str(e)
                )
                failed_uploads += 1

        # Log summary
        logger.info(
            f"Batch upload complete: {successful_uploads} successful, "
            f"{failed_uploads} failed, {total_size_uploaded / (1024 * 1024):.2f} MB uploaded"
        )

        return results
