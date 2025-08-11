"""
Database management for the GainForest Archival Pipeline
"""
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import contextmanager
import json
from enum import Enum

from src.config.logging_config import get_logger

logger = get_logger(__name__)


class ProcessingStatusEnum(str, Enum):
    """Processing status enumeration"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class VerificationStatus(str, Enum):
    """Verification status enumeration"""
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class DatabaseManager:
    """
    SQLite database manager with connection pooling and transaction support
    """

    def __init__(self, database_path: str = "data/archive.db"):
        """
        Initialize database manager

        Args:
            database_path: Path to SQLite database file
        """
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None
        self._init_database()

    def _init_database(self):
        """Initialize database with schema if not exists"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS archived_content
                           (
                               id
                               INTEGER
                               PRIMARY
                               KEY
                               AUTOINCREMENT,
                               ecocert_id
                               TEXT
                               NOT
                               NULL,
                               attestation_uid
                               TEXT
                               NOT
                               NULL,
                               original_url
                               TEXT
                               NOT
                               NULL,
                               content_type
                               TEXT
                               NOT
                               NULL,
                               ipfs_hash
                               TEXT
                               NOT
                               NULL,
                               file_size
                               INTEGER,
                               mime_type
                               TEXT,
                               upload_timestamp
                               DATETIME
                               DEFAULT
                               CURRENT_TIMESTAMP,
                               metadata
                               JSON,
                               verification_status
                               TEXT
                               DEFAULT
                               'pending',
                               created_at
                               DATETIME
                               DEFAULT
                               CURRENT_TIMESTAMP,
                               updated_at
                               DATETIME
                               DEFAULT
                               CURRENT_TIMESTAMP
                           )
                           """)

            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS processing_status
                           (
                               id
                               INTEGER
                               PRIMARY
                               KEY
                               AUTOINCREMENT,
                               ecocert_id
                               TEXT
                               NOT
                               NULL
                               UNIQUE,
                               status
                               TEXT
                               NOT
                               NULL,
                               total_links
                               INTEGER
                               DEFAULT
                               0,
                               processed_links
                               INTEGER
                               DEFAULT
                               0,
                               failed_links
                               INTEGER
                               DEFAULT
                               0,
                               error_message
                               TEXT,
                               started_at
                               DATETIME
                               DEFAULT
                               CURRENT_TIMESTAMP,
                               completed_at
                               DATETIME
                           )
                           """)

            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS error_log
                           (
                               id
                               INTEGER
                               PRIMARY
                               KEY
                               AUTOINCREMENT,
                               ecocert_id
                               TEXT,
                               url
                               TEXT,
                               error_type
                               TEXT,
                               error_message
                               TEXT,
                               stack_trace
                               TEXT,
                               timestamp
                               DATETIME
                               DEFAULT
                               CURRENT_TIMESTAMP
                           )
                           """)

            cursor.execute("""
                           CREATE INDEX IF NOT EXISTS idx_ecocert_id
                               ON archived_content(ecocert_id)
                           """)
            cursor.execute("""
                           CREATE INDEX IF NOT EXISTS idx_attestation_uid
                               ON archived_content(attestation_uid)
                           """)
            cursor.execute("""
                           CREATE INDEX IF NOT EXISTS idx_ipfs_hash
                               ON archived_content(ipfs_hash)
                           """)
            cursor.execute("""
                           CREATE INDEX IF NOT EXISTS idx_processing_status
                               ON processing_status(ecocert_id)
                           """)
            cursor.execute("""
                           CREATE INDEX IF NOT EXISTS idx_error_log_ecocert
                               ON error_log(ecocert_id)
                           """)

            conn.commit()
            logger.info(f"Database initialized at {self.database_path}")

    @contextmanager
    def get_connection(self):
        """
        Get database connection with transaction support

        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(
            str(self.database_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")

        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database transaction failed: {e}")
            raise
        finally:
            conn.close()

    def insert_archived_content(
            self,
            ecocert_id: str,
            attestation_uid: str,
            original_url: str,
            content_type: str,
            ipfs_hash: str,
            file_size: Optional[int] = None,
            mime_type: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Insert archived content record

        Args:
            ecocert_id: Ecocert identifier
            attestation_uid: Attestation UID
            original_url: Original content URL
            content_type: Type of content
            ipfs_hash: IPFS hash of archived content
            file_size: Size of file in bytes
            mime_type: MIME type of content
            metadata: Additional metadata

        Returns:
            int: Inserted record ID
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                           INSERT INTO archived_content (ecocert_id, attestation_uid, original_url,
                                                         content_type, ipfs_hash, file_size, mime_type,
                                                         metadata, upload_timestamp)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                           """, (
                               ecocert_id,
                               attestation_uid,
                               original_url,
                               content_type,
                               ipfs_hash,
                               file_size,
                               mime_type,
                               json.dumps(metadata) if metadata else None,
                               datetime.utcnow()
                           ))

            record_id = cursor.lastrowid
            logger.info(f"Archived content inserted with ID {record_id}")
            return record_id

    def update_processing_status(
            self,
            ecocert_id: str,
            status: ProcessingStatusEnum,
            total_links: Optional[int] = None,
            processed_links: Optional[int] = None,
            failed_links: Optional[int] = None,
            error_message: Optional[str] = None
    ):
        """
        Update or insert processing status

        Args:
            ecocert_id: Ecocert identifier
            status: Processing status
            total_links: Total number of links
            processed_links: Number of processed links
            failed_links: Number of failed links
            error_message: Error message if failed
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM processing_status WHERE ecocert_id = ?",
                (ecocert_id,)
            )
            existing = cursor.fetchone()

            if existing:
                updates = []
                params = []

                updates.append("status = ?")
                params.append(status)

                if total_links is not None:
                    updates.append("total_links = ?")
                    params.append(total_links)

                if processed_links is not None:
                    updates.append("processed_links = ?")
                    params.append(processed_links)

                if failed_links is not None:
                    updates.append("failed_links = ?")
                    params.append(failed_links)

                if error_message is not None:
                    updates.append("error_message = ?")
                    params.append(error_message)

                if status == ProcessingStatusEnum.COMPLETED:
                    updates.append("completed_at = ?")
                    params.append(datetime.utcnow())

                params.append(ecocert_id)

                cursor.execute(f"""
                    UPDATE processing_status
                    SET {', '.join(updates)}
                    WHERE ecocert_id = ?
                """, params)
            else:
                cursor.execute("""
                               INSERT INTO processing_status (ecocert_id, status, total_links,
                                                              processed_links, failed_links, error_message)
                               VALUES (?, ?, ?, ?, ?, ?)
                               """, (
                                   ecocert_id,
                                   status,
                                   total_links or 0,
                                   processed_links or 0,
                                   failed_links or 0,
                                   error_message
                               ))

            logger.debug(f"Processing status updated for {ecocert_id}: {status}")

    def log_error(
            self,
            error_type: str,
            error_message: str,
            ecocert_id: Optional[str] = None,
            url: Optional[str] = None,
            stack_trace: Optional[str] = None
    ):
        """
        Log error to database

        Args:
            error_type: Type of error
            error_message: Error message
            ecocert_id: Related ecocert ID
            url: Related URL
            stack_trace: Stack trace if available
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                           INSERT INTO error_log (ecocert_id, url, error_type,
                                                  error_message, stack_trace)
                           VALUES (?, ?, ?, ?, ?)
                           """, (
                               ecocert_id,
                               url,
                               error_type,
                               error_message,
                               stack_trace
                           ))

            logger.error(f"Error logged: {error_type} - {error_message}")

    def get_processing_status(self, ecocert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get processing status for an ecocert

        Args:
            ecocert_id: Ecocert identifier

        Returns:
            Optional[Dict]: Processing status record
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM processing_status WHERE ecocert_id = ?",
                (ecocert_id,)
            )
            row = cursor.fetchone()

            if row:
                return dict(row)
            return None

    def get_archived_content(
            self,
            ecocert_id: Optional[str] = None,
            ipfs_hash: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get archived content records

        Args:
            ecocert_id: Filter by ecocert ID
            ipfs_hash: Filter by IPFS hash

        Returns:
            List[Dict]: List of archived content records
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM archived_content WHERE 1=1"
            params = []

            if ecocert_id:
                query += " AND ecocert_id = ?"
                params.append(ecocert_id)

            if ipfs_hash:
                query += " AND ipfs_hash = ?"
                params.append(ipfs_hash)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics

        Returns:
            Dict: Statistics about archived content
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as count FROM archived_content")
            total_content = cursor.fetchone()["count"]

            cursor.execute("""
                           SELECT content_type, COUNT(*) as count
                           FROM archived_content
                           GROUP BY content_type
                           """)
            content_by_type = {row["content_type"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("""
                           SELECT status, COUNT(*) as count
                           FROM processing_status
                           GROUP BY status
                           """)
            status_summary = {row["status"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT SUM(file_size) as total_size FROM archived_content")
            total_size = cursor.fetchone()["total_size"] or 0

            cursor.execute("""
                           SELECT COUNT(*) as count
                           FROM error_log
                           WHERE timestamp > datetime('now', '-24 hours')
                           """)
            recent_errors = cursor.fetchone()["count"]

            return {
                "total_archived_content": total_content,
                "content_by_type": content_by_type,
                "processing_status_summary": status_summary,
                "total_file_size_bytes": total_size,
                "recent_errors_24h": recent_errors
            }


def init_database(database_path: str = "data/archive.db") -> DatabaseManager:
    """
    Initialize database with schema

    Args:
        database_path: Path to database file

    Returns:
        DatabaseManager: Initialized database manager
    """
    return DatabaseManager(database_path)
