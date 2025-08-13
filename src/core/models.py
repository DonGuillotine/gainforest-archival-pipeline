"""
Data models for the GainForest Archival Pipeline
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class ContentType(str, Enum):
    """Content type enumeration"""
    GOOGLE_DRIVE = "google_drive"
    GOOGLE_DOCS = "google_docs"
    YOUTUBE_VIDEO = "youtube_video"
    IMAGE = "image"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


@dataclass
class ArchivedContent:
    """Model for archived content records"""
    ecocert_id: str
    attestation_uid: str
    original_url: str
    content_type: ContentType
    ipfs_hash: str
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    verification_status: str = "pending"
    upload_timestamp: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        return {
            "ecocert_id": self.ecocert_id,
            "attestation_uid": self.attestation_uid,
            "original_url": self.original_url,
            "content_type": self.content_type.value if isinstance(self.content_type,
                                                                  ContentType) else self.content_type,
            "ipfs_hash": self.ipfs_hash,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "metadata": self.metadata,
            "verification_status": self.verification_status,
            "upload_timestamp": self.upload_timestamp,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


@dataclass
class ProcessingStatus:
    """Model for processing status records"""
    ecocert_id: str
    status: str
    total_links: int = 0
    processed_links: int = 0
    failed_links: int = 0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    id: Optional[int] = None

    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage"""
        if self.total_links == 0:
            return 0.0
        return (self.processed_links / self.total_links) * 100

    @property
    def is_complete(self) -> bool:
        """Check if processing is complete"""
        return self.status in ["completed", "failed"]


@dataclass
class ErrorLog:
    """Model for error log records"""
    error_type: str
    error_message: str
    ecocert_id: Optional[str] = None
    url: Optional[str] = None
    stack_trace: Optional[str] = None
    timestamp: Optional[datetime] = None
    id: Optional[int] = None


@dataclass
class ExternalLink:
    """Model for external links extracted from ecocerts"""
    url: str
    description: Optional[str] = None
    link_type: Optional[str] = None
    source_field: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def detect_content_type(self) -> ContentType:
        """Detect content type from URL"""
        url_lower = self.url.lower()

        if "drive.google.com" in url_lower:
            return ContentType.GOOGLE_DRIVE
        elif "docs.google.com" in url_lower:
            return ContentType.GOOGLE_DOCS
        elif any(domain in url_lower for domain in ["youtube.com", "youtu.be"]):
            return ContentType.YOUTUBE_VIDEO
        elif any(ext in url_lower for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"]):
            return ContentType.IMAGE
        elif any(ext in url_lower for ext in [".pdf", ".doc", ".docx", ".txt"]):
            return ContentType.DOCUMENT
        else:
            return ContentType.UNKNOWN


@dataclass
class EcocertData:
    """Model for ecocert data"""
    ecocert_id: str
    attestation_uid: str
    external_links: List[ExternalLink] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None

    @property
    def total_links(self) -> int:
        """Get total number of external links"""
        return len(self.external_links)
