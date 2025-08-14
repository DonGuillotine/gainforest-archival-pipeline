"""
IPFS client using Pinata API for content storage
"""
import hashlib
import json
import mimetypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

import requests

from src.config import get_settings
from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class PinataResponse:
    """Response from Pinata API"""
    success: bool
    ipfs_hash: Optional[str] = None
    pin_size: Optional[int] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None
    gateway_url: Optional[str] = None


@dataclass
class IPFSUploadResult:
    """Result of IPFS upload operation"""
    success: bool
    ipfs_hash: Optional[str] = None
    pin_size: Optional[int] = None
    gateway_url: Optional[str] = None
    upload_time: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None


class PinataClient:
    """
    Client for Pinata IPFS pinning service
    Uses Pinata API for uploading and pinning content to IPFS
    """

    def __init__(self, api_key: Optional[str] = None, secret_key: Optional[str] = None):
        """
        Initialize Pinata client

        Args:
            api_key: Pinata API key
            secret_key: Pinata secret API key
        """
        settings = get_settings()

        self.api_key = api_key or settings.PINATA_API_KEY
        self.secret_key = secret_key or settings.PINATA_SECRET_API_KEY
        self.base_url = settings.PINATA_API_URL
        self.gateway_url = settings.IPFS_GATEWAY_URL

        if not self.api_key or not self.secret_key:
            logger.warning("Pinata API keys not configured - IPFS uploads will fail")

        # Setup session with authentication
        self.session = requests.Session()
        self.session.headers.update({
            'pinata_api_key': self.api_key,
            'pinata_secret_api_key': self.secret_key
        })

        logger.info("Initialized Pinata client")

    def test_authentication(self) -> bool:
        """
        Test Pinata API authentication

        Returns:
            bool: True if authentication is successful
        """
        try:
            response = self.session.get(f"{self.base_url}/data/testAuthentication")
            if response.status_code == 200:
                result = response.json()
                message = result.get('message', '')
                if "Congratulations!" in message:
                    logger.info("Pinata authentication successful")
                    return True

            logger.error(f"Pinata authentication failed: {response.text}")
            return False

        except Exception as e:
            logger.error(f"Failed to test Pinata authentication: {e}")
            return False

    def pin_file_to_ipfs(
            self,
            file_path: Path,
            pin_name: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> PinataResponse:
        """
        Pin a file to IPFS using Pinata

        Args:
            file_path: Path to file to upload
            pin_name: Optional name for the pin
            metadata: Optional metadata to attach

        Returns:
            PinataResponse: Upload response
        """
        if not file_path.exists():
            return PinataResponse(
                success=False,
                error=f"File not found: {file_path}"
            )

        try:
            # Prepare the file
            with open(file_path, 'rb') as file:
                files = {
                    'file': (
                        file_path.name,
                        file,
                        self._get_mime_type(file_path)
                    )
                }

                # Prepare pinata options
                pinata_options = {
                    "cidVersion": 1  # Use CIDv1 for better compatibility
                }

                # Prepare pinata metadata with limited keyvalues (max 9 for Pinata)
                keyvalues = dict(metadata or {})  # Create copy to avoid modifying original
                
                # Only add essential metadata to stay under 9-key limit
                keyvalues["upload_timestamp"] = datetime.now(timezone.utc).isoformat()
                keyvalues["file_name"] = file_path.name
                
                # If we're over 9 keys, keep only the most important ones (Pinata actually enforces 9, not 10)
                if len(keyvalues) > 9:
                    essential_keys = ["ecocert_id", "attestation_uid", "platform", "content_type", "upload_timestamp", "file_name"]
                    filtered_keyvalues = {}
                    
                    # First add essential keys
                    for key in essential_keys:
                        if key in keyvalues:
                            filtered_keyvalues[key] = keyvalues[key]
                    
                    # Add remaining keys up to limit of 9  
                    remaining_slots = 9 - len(filtered_keyvalues)
                    for key, value in keyvalues.items():
                        if key not in essential_keys and remaining_slots > 0:
                            filtered_keyvalues[key] = value
                            remaining_slots -= 1
                    
                    keyvalues = filtered_keyvalues

                pinata_metadata = {
                    "name": pin_name or file_path.name,
                    "keyvalues": keyvalues
                }

                # Debug: Log the actual keyvalues being sent
                logger.info(f"Pinata keyvalues ({len(keyvalues)} keys): {list(keyvalues.keys())}")
                logger.debug(f"Full keyvalues: {keyvalues}")

                data = {
                    'pinataOptions': json.dumps(pinata_options),
                    'pinataMetadata': json.dumps(pinata_metadata)
                }

                logger.info(f"Uploading file to IPFS: {file_path.name}")

                # Upload to Pinata
                response = self.session.post(
                    f"{self.base_url}/pinning/pinFileToIPFS",
                    files=files,
                    data=data,
                    timeout=300  # 5 minute timeout for large files
                )

                if response.status_code == 200:
                    result = response.json()
                    ipfs_hash = result.get('IpfsHash')
                    pin_size = result.get('PinSize')
                    timestamp = result.get('Timestamp')

                    logger.info(f"Successfully pinned to IPFS: {ipfs_hash}")

                    return PinataResponse(
                        success=True,
                        ipfs_hash=ipfs_hash,
                        pin_size=pin_size,
                        timestamp=timestamp,
                        gateway_url=f"{self.gateway_url}{ipfs_hash}"
                    )
                else:
                    error_msg = f"Pinata API error: {response.status_code} - {response.text}"
                    logger.error(error_msg)
                    return PinataResponse(
                        success=False,
                        error=error_msg
                    )

        except Exception as e:
            error_msg = f"Failed to pin file to IPFS: {e}"
            logger.error(error_msg)
            return PinataResponse(
                success=False,
                error=error_msg
            )

    def pin_json_to_ipfs(
            self,
            json_data: Dict[str, Any],
            pin_name: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> PinataResponse:
        """
        Pin JSON data to IPFS using Pinata

        Args:
            json_data: JSON data to upload
            pin_name: Optional name for the pin
            metadata: Optional metadata to attach

        Returns:
            PinataResponse: Upload response
        """
        try:
            # Prepare pinata metadata
            pinata_metadata = {
                "name": pin_name or "json_data",
                "keyvalues": metadata or {}
            }

            # Add upload timestamp
            pinata_metadata["keyvalues"]["upload_timestamp"] = datetime.now(timezone.utc).isoformat()
            pinata_metadata["keyvalues"]["content_type"] = "application/json"

            # Prepare request body
            body = {
                "pinataContent": json_data,
                "pinataMetadata": pinata_metadata,
                "pinataOptions": {
                    "cidVersion": 1
                }
            }

            logger.info(f"Uploading JSON to IPFS: {pin_name}")

            # Upload to Pinata
            response = self.session.post(
                f"{self.base_url}/pinning/pinJSONToIPFS",
                json=body,
                timeout=60
            )

            if response.status_code == 200:
                result = response.json()
                ipfs_hash = result.get('IpfsHash')
                pin_size = result.get('PinSize')
                timestamp = result.get('Timestamp')

                logger.info(f"Successfully pinned JSON to IPFS: {ipfs_hash}")

                return PinataResponse(
                    success=True,
                    ipfs_hash=ipfs_hash,
                    pin_size=pin_size,
                    timestamp=timestamp,
                    gateway_url=f"{self.gateway_url}{ipfs_hash}"
                )
            else:
                error_msg = f"Pinata API error: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return PinataResponse(
                    success=False,
                    error=error_msg
                )

        except Exception as e:
            error_msg = f"Failed to pin JSON to IPFS: {e}"
            logger.error(error_msg)
            return PinataResponse(
                success=False,
                error=error_msg
            )

    def get_pin_by_hash(self, ipfs_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get pin details by IPFS hash

        Args:
            ipfs_hash: IPFS hash to query

        Returns:
            Optional[Dict]: Pin details if found
        """
        try:
            params = {
                'hashContains': ipfs_hash,
                'status': 'pinned'
            }

            response = self.session.get(
                f"{self.base_url}/data/pinList",
                params=params
            )

            if response.status_code == 200:
                result = response.json()
                rows = result.get('rows', [])

                if rows:
                    return rows[0]  # Return first matching pin

            return None

        except Exception as e:
            logger.error(f"Failed to get pin details: {e}")
            return None

    def verify_pin(self, ipfs_hash: str) -> bool:
        """
        Verify that content is pinned on IPFS

        Args:
            ipfs_hash: IPFS hash to verify

        Returns:
            bool: True if content is pinned
        """
        pin_details = self.get_pin_by_hash(ipfs_hash)
        return pin_details is not None

    def unpin_from_ipfs(self, ipfs_hash: str) -> bool:
        """
        Unpin content from IPFS (use with caution)

        Args:
            ipfs_hash: IPFS hash to unpin

        Returns:
            bool: True if unpinned successfully
        """
        try:
            response = self.session.delete(
                f"{self.base_url}/pinning/unpin/{ipfs_hash}"
            )

            if response.status_code == 200:
                logger.info(f"Successfully unpinned from IPFS: {ipfs_hash}")
                return True
            else:
                logger.error(f"Failed to unpin: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to unpin from IPFS: {e}")
            return False

    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get Pinata account usage statistics

        Returns:
            Optional[Dict]: Usage statistics
        """
        try:
            response = self.session.get(f"{self.base_url}/data/userPinnedDataTotal")

            if response.status_code == 200:
                return response.json()

            return None

        except Exception as e:
            logger.error(f"Failed to get usage stats: {e}")
            return None

    def _get_mime_type(self, file_path: Path) -> str:
        """
        Get MIME type for file

        Args:
            file_path: Path to file

        Returns:
            str: MIME type
        """
        mime_type, _ = mimetypes.guess_type(str(file_path))

        if not mime_type:
            # Use python-magic for better detection
            try:
                import magic
                mime_type = magic.from_file(str(file_path), mime=True)
            except:
                pass

        return mime_type or 'application/octet-stream'


class IPFSUploadManager:
    """
    Manages IPFS uploads with content type handling
    """

    def __init__(self, pinata_client: Optional[PinataClient] = None):
        """
        Initialize IPFS upload manager

        Args:
            pinata_client: Optional Pinata client instance
        """
        self.pinata = pinata_client or PinataClient()

        # Test authentication on initialization
        if not self.pinata.test_authentication():
            logger.warning("Pinata authentication failed - uploads will not work")

        logger.info("Initialized IPFSUploadManager")

    def upload_file(
            self,
            file_path: Path,
            content_type: str,
            metadata: Optional[Dict[str, Any]] = None
    ) -> IPFSUploadResult:
        """
        Upload file to IPFS with content type handling

        Args:
            file_path: Path to file to upload
            content_type: Type of content (google_drive, youtube, etc.)
            metadata: Optional metadata

        Returns:
            IPFSUploadResult: Upload result
        """
        import time
        start_time = time.time()

        try:
            # Validate file
            if not file_path.exists():
                return IPFSUploadResult(
                    success=False,
                    error=f"File not found: {file_path}"
                )

            file_size = file_path.stat().st_size

            # Check file size
            settings = get_settings()
            if file_size > settings.MAX_FILE_SIZE:
                return IPFSUploadResult(
                    success=False,
                    error=f"File too large: {file_size} bytes"
                )

            # Use the metadata as-is, don't add duplicates since they're handled in pin_file_to_ipfs
            upload_metadata = metadata or {}

            # Generate pin name
            pin_name = f"{content_type}_{file_path.stem}"

            # Upload to IPFS
            logger.info(f"Uploading {file_path.name} to IPFS ({file_size} bytes)")

            response = self.pinata.pin_file_to_ipfs(
                file_path=file_path,
                pin_name=pin_name,
                metadata=upload_metadata
            )

            if response.success:
                upload_time = time.time() - start_time

                # Verify the pin
                if self.pinata.verify_pin(response.ipfs_hash):
                    logger.info(f"Pin verified: {response.ipfs_hash}")
                else:
                    logger.warning(f"Pin verification failed for: {response.ipfs_hash}")

                return IPFSUploadResult(
                    success=True,
                    ipfs_hash=response.ipfs_hash,
                    pin_size=response.pin_size,
                    gateway_url=response.gateway_url,
                    upload_time=upload_time,
                    metadata=upload_metadata
                )
            else:
                return IPFSUploadResult(
                    success=False,
                    error=response.error,
                    upload_time=time.time() - start_time
                )

        except Exception as e:
            error_msg = f"Upload failed: {e}"
            logger.error(error_msg)
            return IPFSUploadResult(
                success=False,
                error=error_msg,
                upload_time=time.time() - start_time
            )

    def upload_metadata(
            self,
            metadata: Dict[str, Any],
            name: str
    ) -> IPFSUploadResult:
        """
        Upload metadata JSON to IPFS

        Args:
            metadata: Metadata dictionary
            name: Name for the metadata

        Returns:
            IPFSUploadResult: Upload result
        """
        import time
        start_time = time.time()

        try:
            logger.info(f"Uploading metadata to IPFS: {name}")

            response = self.pinata.pin_json_to_ipfs(
                json_data=metadata,
                pin_name=f"metadata_{name}",
                metadata={"type": "metadata", "name": name}
            )

            if response.success:
                return IPFSUploadResult(
                    success=True,
                    ipfs_hash=response.ipfs_hash,
                    pin_size=response.pin_size,
                    gateway_url=response.gateway_url,
                    upload_time=time.time() - start_time,
                    metadata={"type": "metadata"}
                )
            else:
                return IPFSUploadResult(
                    success=False,
                    error=response.error,
                    upload_time=time.time() - start_time
                )

        except Exception as e:
            error_msg = f"Metadata upload failed: {e}"
            logger.error(error_msg)
            return IPFSUploadResult(
                success=False,
                error=error_msg,
                upload_time=time.time() - start_time
            )

    def batch_upload(
            self,
            files: List[tuple[Path, str, Dict[str, Any]]]
    ) -> Dict[str, IPFSUploadResult]:
        """
        Upload multiple files to IPFS

        Args:
            files: List of (file_path, content_type, metadata) tuples

        Returns:
            Dict: Map of file path to upload result
        """
        results = {}

        for file_path, content_type, metadata in files:
            logger.info(f"Uploading {file_path.name} ({content_type})")

            result = self.upload_file(
                file_path=file_path,
                content_type=content_type,
                metadata=metadata
            )

            results[str(file_path)] = result

            if result.success:
                logger.info(f"✓ Uploaded: {result.ipfs_hash}")
            else:
                logger.error(f"✗ Failed: {result.error}")

        # Summary
        successful = sum(1 for r in results.values() if r.success)
        total = len(results)
        logger.info(f"Batch upload complete: {successful}/{total} successful")

        return results

    def verify_upload(self, ipfs_hash: str) -> bool:
        """
        Verify that content is accessible via IPFS

        Args:
            ipfs_hash: IPFS hash to verify

        Returns:
            bool: True if content is accessible
        """
        try:
            # Check if pinned
            if not self.pinata.verify_pin(ipfs_hash):
                logger.warning(f"Content not pinned: {ipfs_hash}")
                return False

            # Try to access via gateway (HEAD request)
            gateway_url = f"{self.pinata.gateway_url}{ipfs_hash}"
            response = requests.head(gateway_url, timeout=10)

            if response.status_code == 200:
                logger.info(f"Content accessible via gateway: {ipfs_hash}")
                return True
            else:
                logger.warning(f"Content not accessible via gateway: {ipfs_hash}")
                return False

        except Exception as e:
            logger.error(f"Failed to verify upload: {e}")
            return False

    def calculate_ipfs_hash_locally(self, file_path: Path) -> str:
        """
        Calculate what the IPFS hash would be locally (for verification)
        Note: This is an approximation, actual IPFS hash depends on chunking

        Args:
            file_path: Path to file

        Returns:
            str: Calculated hash
        """
        sha256_hash = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()
