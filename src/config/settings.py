"""
Configuration settings for the GainForest Archival Pipeline
"""
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import List, Optional, Dict, Any
from pathlib import Path
import os
from functools import lru_cache


class Settings(BaseSettings):
    """Main configuration settings using Pydantic for validation"""

    PROJECT_ROOT: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent
    )
    DATA_DIR: Path = Field(default_factory=lambda: Path("data"))
    LOGS_DIR: Path = Field(default_factory=lambda: Path("logs"))

    DATABASE_URL: str = Field(
        default="sqlite:///data/archive.db",
        description="SQLite database connection URL"
    )
    DATABASE_ECHO: bool = Field(default=False, description="Echo SQL statements")

    PINATA_API_KEY: Optional[str] = Field(
        default=None,
        description="Pinata API key for IPFS uploads"
    )
    PINATA_SECRET_API_KEY: Optional[str] = Field(
        default=None,
        description="Pinata secret API key"
    )
    IPFS_GATEWAY_URL: str = Field(
        default="https://gateway.pinata.cloud/ipfs/",
        description="IPFS gateway URL for content retrieval"
    )
    PINATA_API_URL: str = Field(
        default="https://api.pinata.cloud",
        description="Pinata API base URL"
    )

    HYPERCERTS_API_URL: str = Field(
        default="https://api.hypercerts.org/v2/graphql",
        description="Hypercerts GraphQL API endpoint"
    )
    EAS_GRAPHQL_URL: str = Field(
        default="https://celo.easscan.org/graphql",
        description="EAS GraphQL endpoint for attestations"
    )

    EAS_CHAIN_ID: int = Field(default=42220, description="Celo Mainnet chain ID")
    EAS_CONTRACT_ADDRESS: str = Field(
        default="0x72E1d8ccf5299fb36fEfD8CC4394B8ef7e98Af92",
        description="EAS contract address on Celo"
    )
    EAS_SCHEMA_UID: str = Field(
        default="0x48e3e1be1e08084b408a7035ac889f2a840b440bbf10758d14fb722831a200c3",
        description="Schema UID for ecocerts"
    )

    MAX_FILE_SIZE: int = Field(
        default=100 * 1024 * 1024,
        description="Maximum file size in bytes"
    )
    ALLOWED_DOMAINS: List[str] = Field(
        default_factory=lambda: [
            "drive.google.com",
            "youtube.com",
            "www.youtube.com",
            "youtu.be",
            "docs.google.com",
            "sheets.google.com"
        ],
        description="Whitelisted domains for content download"
    )
    VIRUS_SCAN_ENABLED: bool = Field(
        default=False,
        description="Enable virus scanning (requires ClamAV)"
    )
    REQUEST_TIMEOUT: int = Field(default=30, description="HTTP request timeout in seconds")

    MAX_RETRIES: int = Field(default=3, description="Maximum retry attempts")
    RETRY_DELAY: int = Field(default=5, description="Initial retry delay in seconds")
    RETRY_BACKOFF: float = Field(default=2.0, description="Exponential backoff multiplier")

    BATCH_SIZE: int = Field(default=10, description="Batch size for processing")
    CONCURRENT_DOWNLOADS: int = Field(default=3, description="Max concurrent downloads")

    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format"
    )
    LOG_FILE_MAX_BYTES: int = Field(
        default=10 * 1024 * 1024,
        description="Maximum log file size"
    )
    LOG_FILE_BACKUP_COUNT: int = Field(
        default=5,
        description="Number of backup log files to keep"
    )

    APP_NAME: str = Field(
        default="GainForest Archival Pipeline",
        description="Application name"
    )
    APP_VERSION: str = Field(default="1.0.0", description="Application version")

    @validator("DATA_DIR", "LOGS_DIR", pre=True)
    def resolve_paths(cls, v, values):
        """Resolve relative paths to absolute paths"""
        if isinstance(v, str):
            v = Path(v)
        if not v.is_absolute() and "PROJECT_ROOT" in values:
            return values["PROJECT_ROOT"] / v
        return v

    @validator("ALLOWED_DOMAINS", pre=True)
    def parse_domains(cls, v):
        """Parse comma-separated domains if provided as string"""
        if isinstance(v, str):
            return [d.strip() for d in v.split(",")]
        return v

    def create_directories(self):
        """Create necessary directories if they don't exist"""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    class Config:
        """Pydantic configuration"""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary for logging"""
        return {
            k: str(v) if isinstance(v, Path) else v
            for k, v in self.dict().items()
            if not k.endswith("_KEY")
        }


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance (singleton pattern)

    Returns:
        Settings: Application settings instance
    """
    settings = Settings()
    settings.create_directories()
    return settings
