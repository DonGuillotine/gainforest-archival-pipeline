"""
Complete database operations for the archival pipeline
"""
from typing import List, Dict, Any, Optional

from src.config.logging_config import get_logger
from src.core.database import DatabaseManager, ProcessingStatusEnum

logger = get_logger(__name__)


class DatabaseOperations:
    """
    Complete CRUD operations for the archival pipeline
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        """Initialize database operations"""
        self.db = db_manager or DatabaseManager()
        logger.info("Initialized DatabaseOperations")

    def record_archive_success(
            self,
            ecocert_id: str,
            attestation_uid: str,
            url: str,
            ipfs_hash: str,
            file_size: int,
            content_type: str,
            metadata: Dict[str, Any]
    ) -> int:
        """
        Record successful archive in database

        Returns:
            int: Record ID
        """
        return self.db.insert_archived_content(
            ecocert_id=ecocert_id,
            attestation_uid=attestation_uid,
            original_url=url,
            content_type=content_type,
            ipfs_hash=ipfs_hash,
            file_size=file_size,
            mime_type=metadata.get('mime_type'),
            metadata=metadata
        )

    def get_ecocert_archives(self, ecocert_id: str) -> List[Dict[str, Any]]:
        """
        Get all archived content for an ecocert

        Returns:
            List[Dict]: Archived content records
        """
        return self.db.get_archived_content(ecocert_id=ecocert_id)

    def mark_ecocert_complete(self, ecocert_id: str, stats: Dict[str, Any]):
        """
        Mark ecocert processing as complete
        """
        status = ProcessingStatusEnum.COMPLETED if stats['failed'] == 0 else ProcessingStatusEnum.FAILED

        self.db.update_processing_status(
            ecocert_id=ecocert_id,
            status=status,
            total_links=stats['total'],
            processed_links=stats['processed'],
            failed_links=stats['failed']
        )

    def get_processing_summary(self) -> Dict[str, Any]:
        """
        Get summary of all processing

        Returns:
            Dict: Processing summary
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Get overall stats
            cursor.execute("""
                           SELECT COUNT(DISTINCT ecocert_id) as total_ecocerts,
                                  COUNT(*)                   as total_archives,
                                  SUM(file_size)             as total_size,
                                  COUNT(DISTINCT ipfs_hash)  as unique_files
                           FROM archived_content
                           """)

            row = cursor.fetchone()

            # Get status breakdown
            cursor.execute("""
                           SELECT status, COUNT(*) as count
                           FROM processing_status
                           GROUP BY status
                           """)

            status_breakdown = {row['status']: row['count'] for row in cursor.fetchall()}

            return {
                'total_ecocerts': row['total_ecocerts'] or 0,
                'total_archives': row['total_archives'] or 0,
                'total_size_bytes': row['total_size'] or 0,
                'total_size_mb': (row['total_size'] or 0) / (1024 * 1024),
                'unique_files': row['unique_files'] or 0,
                'status_breakdown': status_breakdown
            }

    def cleanup_old_temp_records(self, hours: int = 24):
        """
        Clean up old temporary records
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM error_log
                WHERE timestamp < datetime('now', '-{} hours')
            """.format(hours))

            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old error records")
