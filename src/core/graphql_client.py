"""
GraphQL client for querying Hypercerts and EAS APIs
"""
import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.config import get_settings
from src.config.logging_config import get_logger
from src.core.models import ExternalLink, EcocertData

logger = get_logger(__name__)


class GraphQLError(Exception):
    """Custom exception for GraphQL errors"""
    pass


class GraphQLClient:
    """
    GraphQL client with retry logic and error handling
    """

    def __init__(
            self,
            endpoint: str,
            headers: Optional[Dict[str, str]] = None,
            timeout: int = 30,
            max_retries: int = 3
    ):
        """
        Initialize GraphQL client

        Args:
            endpoint: GraphQL API endpoint
            headers: Optional headers for requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.endpoint = endpoint
        self.headers = headers or {}
        self.timeout = timeout

        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Add default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.headers
        })

    def execute_query(
            self,
            query: str,
            variables: Optional[Dict[str, Any]] = None,
            operation_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query

        Args:
            query: GraphQL query string
            variables: Query variables
            operation_name: Optional operation name

        Returns:
            Dict: Query response data

        Raises:
            GraphQLError: If query fails
        """
        payload = {
            "query": query,
            "variables": variables or {},
        }

        if operation_name:
            payload["operationName"] = operation_name

        try:
            logger.debug(f"Executing GraphQL query to {self.endpoint}")
            logger.debug(f"Query: {query[:200]}...")

            response = self.session.post(
                self.endpoint,
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()
            result = response.json()

            if "errors" in result:
                error_messages = [e.get("message", str(e)) for e in result["errors"]]
                raise GraphQLError(f"GraphQL errors: {'; '.join(error_messages)}")

            return result.get("data", {})

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.text
                    logger.error(f"Response content: {error_detail}")
                except:
                    pass
            raise GraphQLError(f"Request failed: {e}") from e
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {e}")
            raise GraphQLError(f"Invalid JSON response: {e}") from e


class HypercertsClient:
    """
    Client for interacting with Hypercerts GraphQL API
    """

    def __init__(self, api_url: Optional[str] = None):
        """
        Initialize Hypercerts client

        Args:
            api_url: Optional API URL override
        """
        settings = get_settings()
        self.api_url = api_url or settings.HYPERCERTS_API_URL
        self.client = GraphQLClient(self.api_url)
        logger.info(f"Initialized Hypercerts client with endpoint: {self.api_url}")

    def get_attestation_uid_from_ecocert(self, ecocert_id: str) -> Optional[str]:
        """
        Extract attestation UID from ecocert ID or query it

        Args:
            ecocert_id: Ecocert identifier

        Returns:
            Optional[str]: Attestation UID if found
        """
        # Parse ecocert ID format: chainId-contractAddress-tokenId
        parts = ecocert_id.split("-")

        if len(parts) != 3:
            logger.error(f"Invalid ecocert ID format: {ecocert_id}")
            return None

        chain_id, contract_address, token_id = parts

        try:
            # Validate and convert token_id to ensure it's numeric
            try:
                # Try to convert to int to validate it's numeric (no hex chars)
                if token_id.isdigit():
                    numeric_token_id = token_id
                elif token_id.startswith("0x"):
                    # Parse hex with 0x prefix
                    numeric_token_id = str(int(token_id, 16))
                else:
                    # Try to parse as hex without 0x prefix
                    try:
                        numeric_token_id = str(int(token_id, 16))
                    except ValueError:
                        logger.error(f"Invalid token_id format: {token_id} - not numeric and not valid hex")
                        return None
            except ValueError:
                logger.error(f"Invalid token_id format: {token_id} - cannot be converted to numeric value")
                return None

            # Query for the hypercert/attestation
            query = f"""
            query GetHypercert {{
                hypercerts(
                    where: {{
                        token_id: {{eq: "{numeric_token_id}"}}
                    }}
                ) {{
                    data {{
                        id
                        uri
                        metadata {{
                            name
                            description
                            image
                            external_url
                        }}
                        attestations {{
                            data {{
                                uid
                                data
                                schema_uid
                                attester
                                recipient
                                creation_block_timestamp
                            }}
                        }}
                    }}
                }}
            }}
            """
            
            result = self.client.execute_query(query)

            if result and "hypercerts" in result:
                hypercerts_data = result["hypercerts"].get("data", [])
                logger.debug(f"Found {len(hypercerts_data)} hypercerts for token_id {numeric_token_id}")

                if hypercerts_data and len(hypercerts_data) > 0:
                    # Check all hypercerts for attestations, not just the first one
                    for i, hypercert in enumerate(hypercerts_data):
                        attestations = hypercert.get("attestations", {}).get("data", [])
                        logger.debug(f"Hypercert {i}: {len(attestations)} attestations")
                        
                        if attestations:
                            # Return the first attestation UID found
                            attestation_uid = attestations[0].get("uid")
                            logger.info(f"Found attestation UID for {ecocert_id}: {attestation_uid}")
                            return attestation_uid
                    
                    logger.warning(f"No attestations found for ecocert {ecocert_id}")
                else:
                    logger.warning(f"No hypercert found for {ecocert_id}")

            return None

        except GraphQLError as e:
            logger.error(f"Failed to query hypercert {ecocert_id}: {e}")
            return None

    def get_hypercert_metadata(self, ecocert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get full hypercert metadata

        Args:
            ecocert_id: Ecocert identifier

        Returns:
            Optional[Dict]: Hypercert metadata if found
        """
        parts = ecocert_id.split("-")
        if len(parts) != 3:
            return None

        chain_id, contract_address, token_id = parts

        try:
            # Validate and convert token_id to ensure it's numeric
            try:
                # Try to convert to int to validate it's numeric (no hex chars)
                if token_id.isdigit():
                    numeric_token_id = token_id
                elif token_id.startswith("0x"):
                    # Parse hex with 0x prefix
                    numeric_token_id = str(int(token_id, 16))
                else:
                    # Try to parse as hex without 0x prefix
                    try:
                        numeric_token_id = str(int(token_id, 16))
                    except ValueError:
                        logger.error(f"Invalid token_id format: {token_id} - not numeric and not valid hex")
                        return None
            except ValueError:
                logger.error(f"Invalid token_id format: {token_id} - cannot be converted to numeric value")
                return None

            query = f"""
            query GetHypercertMetadata {{
                hypercerts(
                    where: {{
                        token_id: {{eq: "{numeric_token_id}"}}
                    }}
                ) {{
                    data {{
                        id
                        uri
                        creation_block_timestamp
                        creator_address
                        metadata {{
                            name
                            description
                            image
                            external_url
                        }}
                        attestations {{
                            data {{
                                uid
                                data
                                schema_uid
                                creation_block_timestamp
                            }}
                        }}
                        fractions {{
                            data {{
                                id
                                owner_address
                            }}
                        }}
                    }}
                }}
            }}
            """
            
            result = self.client.execute_query(query)

            if result and "hypercerts" in result:
                hypercerts_data = result["hypercerts"].get("data", [])
                if hypercerts_data:
                    return hypercerts_data[0]

            return None

        except GraphQLError as e:
            logger.error(f"Failed to get metadata for {ecocert_id}: {e}")
            return None


class EASClient:
    """
    Client for interacting with EAS (Ethereum Attestation Service) GraphQL API
    """

    def __init__(self, graphql_url: Optional[str] = None):
        """
        Initialize EAS client

        Args:
            graphql_url: Optional GraphQL URL override
        """
        settings = get_settings()
        self.graphql_url = graphql_url or settings.EAS_GRAPHQL_URL
        self.schema_uid = settings.EAS_SCHEMA_UID
        self.client = GraphQLClient(self.graphql_url)
        logger.info(f"Initialized EAS client with endpoint: {self.graphql_url}")

    def get_attestation_by_uid(self, attestation_uid: str) -> Optional[Dict[str, Any]]:
        """
        Get attestation data by UID

        Args:
            attestation_uid: Attestation UID

        Returns:
            Optional[Dict]: Attestation data if found
        """
        query = """
        query GetAttestation($id: String!) {
            getAttestation(where: {id: $id}) {
                id
                attester
                recipient
                refUID
                revocable
                revocationTime
                expirationTime
                time
                txid
                data
                schemaId
                schema {
                    id
                    schema
                }
                decodedDataJson
            }
        }
        """

        try:
            variables = {"id": attestation_uid}
            result = self.client.execute_query(query, variables)

            if result and "getAttestation" in result:
                attestation = result["getAttestation"]
                if attestation:
                    logger.info(f"Retrieved attestation {attestation_uid}")
                    # Map decodedDataJson to decodedData for compatibility
                    if "decodedDataJson" in attestation:
                        attestation["decodedData"] = attestation["decodedDataJson"]
                    # Map id to uid for compatibility with existing code
                    if "id" in attestation:
                        attestation["uid"] = attestation["id"]
                    return attestation

            logger.warning(f"No attestation found for UID {attestation_uid}")
            return None

        except GraphQLError as e:
            logger.error(f"Failed to get attestation {attestation_uid}: {e}")
            return None

    def get_attestations_by_schema(
            self,
            schema_uid: Optional[str] = None,
            limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get attestations by schema UID

        Args:
            schema_uid: Schema UID (uses default if not provided)
            limit: Maximum number of attestations to retrieve

        Returns:
            List[Dict]: List of attestations
        """
        schema_uid = schema_uid or self.schema_uid

        query = """
        query GetAttestationsBySchema($schemaId: String!, $limit: Int!) {
            getAttestations(
                where: {schema_id: $schemaId},
                first: $limit,
                orderBy: "time",
                orderDirection: "desc"
            ) {
                data {
                    uid
                    attester
                    recipient
                    data
                    time
                    decodedDataJson
                }
            }
        }
        """

        try:
            variables = {
                "schemaId": schema_uid,
                "limit": limit
            }

            result = self.client.execute_query(query, variables)

            if result and "getAttestations" in result:
                attestations_data = result["getAttestations"].get("data", [])
                # Map fields for compatibility
                for attestation in attestations_data:
                    if "decodedDataJson" in attestation:
                        attestation["decodedData"] = attestation["decodedDataJson"]
                    if "uid" in attestation:
                        attestation["id"] = attestation["uid"]
                logger.info(f"Retrieved {len(attestations_data)} attestations for schema {schema_uid}")
                return attestations_data

            return []

        except GraphQLError as e:
            logger.error(f"Failed to get attestations for schema {schema_uid}: {e}")
            return []


class LinkExtractor:
    """
    Extract and validate external links from attestation data
    """

    def __init__(self):
        """Initialize link extractor"""
        settings = get_settings()
        self.allowed_domains = settings.ALLOWED_DOMAINS

        # Compile regex patterns for different link types
        self.patterns = {
            "google_drive": re.compile(
                r'https?://(?:drive\.google\.com/(?:file/d/|open\?id=)|docs\.google\.com/(?:document|spreadsheets|presentation)/d/)([a-zA-Z0-9_-]+)',
                re.IGNORECASE
            ),
            "youtube": re.compile(
                r'https?://(?:www\.)?(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})',
                re.IGNORECASE
            ),
            "generic_url": re.compile(
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                re.IGNORECASE
            )
        }

    def extract_links_from_attestation(
            self,
            attestation_data: Dict[str, Any]
    ) -> List[ExternalLink]:
        """
        Extract external links from attestation data

        Args:
            attestation_data: Attestation data dictionary

        Returns:
            List[ExternalLink]: Extracted and validated links
        """
        links = []

        # Try to parse the data field
        data_field = attestation_data.get("data", "")
        decoded_data = attestation_data.get("decodedData")
        
        # Debug logging to understand the structure (can be removed later)
        logger.debug(f"Attestation data keys: {list(attestation_data.keys())}")
        logger.debug(f"decodedData type: {type(decoded_data)}")
        if decoded_data:
            logger.debug(f"decodedData preview: {str(decoded_data)[:200]}...")

        # Method 1: Check decodedData if available
        if decoded_data:
            links.extend(self._extract_from_decoded_data(decoded_data))

        # Method 2: Parse raw data field (hex string)
        if data_field and data_field.startswith("0x"):
            links.extend(self._extract_from_hex_data(data_field))

        # Method 3: Check for JSON structure in data
        if isinstance(data_field, str) and not data_field.startswith("0x"):
            links.extend(self._extract_from_json_string(data_field))

        # Deduplicate links
        unique_links = self._deduplicate_links(links)

        logger.info(f"Extracted {len(unique_links)} unique links from attestation")
        return unique_links

    def _extract_from_decoded_data(self, decoded_data: Any) -> List[ExternalLink]:
        """
        Extract links from decoded attestation data

        Args:
            decoded_data: Decoded attestation data

        Returns:
            List[ExternalLink]: Extracted links
        """
        links = []

        try:
            # Handle different decoded data structures
            if isinstance(decoded_data, str):
                # Try to parse as JSON
                try:
                    decoded_data = json.loads(decoded_data)
                except json.JSONDecodeError:
                    # If not JSON, search for URLs in the string
                    urls = self.patterns["generic_url"].findall(decoded_data)
                    for url in urls:
                        if self._is_valid_url(url):
                            links.append(ExternalLink(url=url))
                    return links

            # Navigate through the data structure to find sources
            if isinstance(decoded_data, dict):
                # Check for sources field
                sources = decoded_data.get("sources", [])
                if not sources and "data" in decoded_data:
                    sources = decoded_data["data"].get("sources", [])

                # Process sources
                for source in sources:
                    if isinstance(source, dict):
                        url = source.get("src") or source.get("url")
                        if url and self._is_valid_url(url):
                            links.append(ExternalLink(
                                url=url,
                                description=source.get("description"),
                                link_type=source.get("type"),
                                source_field="sources"
                            ))
                    elif isinstance(source, str) and self._is_valid_url(source):
                        links.append(ExternalLink(url=source, source_field="sources"))

                # Also check for direct URL fields
                for field in ["url", "link", "href", "source"]:
                    if field in decoded_data:
                        url = decoded_data[field]
                        if isinstance(url, str) and self._is_valid_url(url):
                            links.append(ExternalLink(url=url, source_field=field))

            elif isinstance(decoded_data, list):
                # Process list of items
                for item in decoded_data:
                    links.extend(self._extract_from_decoded_data(item))

        except Exception as e:
            logger.error(f"Error extracting from decoded data: {e}")

        return links

    def _extract_from_hex_data(self, hex_data: str) -> List[ExternalLink]:
        """
        Extract links from hex-encoded data

        Args:
            hex_data: Hex string starting with 0x

        Returns:
            List[ExternalLink]: Extracted links
        """
        links = []

        try:
            # Remove 0x prefix and decode
            hex_string = hex_data[2:] if hex_data.startswith("0x") else hex_data

            # Try to decode as UTF-8
            try:
                decoded_bytes = bytes.fromhex(hex_string)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

                # Look for URLs in the decoded string
                urls = self.patterns["generic_url"].findall(decoded_str)
                for url in urls:
                    if self._is_valid_url(url):
                        links.append(ExternalLink(url=url, source_field="hex_data"))

                # Try to parse as JSON
                try:
                    json_data = json.loads(decoded_str)
                    links.extend(self._extract_from_decoded_data(json_data))
                except json.JSONDecodeError:
                    pass

            except (ValueError, UnicodeDecodeError) as e:
                logger.debug(f"Could not decode hex data: {e}")

        except Exception as e:
            logger.error(f"Error extracting from hex data: {e}")

        return links

    def _extract_from_json_string(self, json_string: str) -> List[ExternalLink]:
        """
        Extract links from JSON string

        Args:
            json_string: JSON formatted string

        Returns:
            List[ExternalLink]: Extracted links
        """
        links = []

        try:
            data = json.loads(json_string)
            links.extend(self._extract_from_decoded_data(data))
        except json.JSONDecodeError:
            # If not valid JSON, search for URLs directly
            urls = self.patterns["generic_url"].findall(json_string)
            for url in urls:
                if self._is_valid_url(url):
                    links.append(ExternalLink(url=url))
        except Exception as e:
            logger.error(f"Error extracting from JSON string: {e}")

        return links

    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL against allowed domains

        Args:
            url: URL to validate

        Returns:
            bool: True if valid
        """
        try:
            parsed = urlparse(url)

            # Check if it's a valid URL
            if not parsed.scheme or not parsed.netloc:
                return False

            # Only allow HTTP and HTTPS schemes
            if parsed.scheme.lower() not in ['http', 'https']:
                return False

            # Check against allowed domains
            domain = parsed.netloc.lower()
            # Remove www. prefix for comparison
            domain = domain.replace("www.", "")

            for allowed_domain in self.allowed_domains:
                allowed_domain = allowed_domain.lower().replace("www.", "")
                if domain == allowed_domain or domain.endswith(f".{allowed_domain}"):
                    return True

            logger.debug(f"URL domain not in allowed list: {domain}")
            return False

        except Exception as e:
            logger.error(f"Error validating URL {url}: {e}")
            return False

    def _deduplicate_links(self, links: List[ExternalLink]) -> List[ExternalLink]:
        """
        Remove duplicate links

        Args:
            links: List of links

        Returns:
            List[ExternalLink]: Deduplicated links
        """
        seen_urls = set()
        unique_links = []

        for link in links:
            # Normalize URL for comparison
            normalized_url = self._normalize_url(link.url)

            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                unique_links.append(link)

        return unique_links

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for deduplication

        Args:
            url: URL to normalize

        Returns:
            str: Normalized URL
        """
        # Remove trailing slashes
        url = url.rstrip("/")

        # Convert to lowercase for domain
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"

        if parsed.query:
            normalized += f"?{parsed.query}"

        return normalized

    def validate_and_classify_link(self, link: ExternalLink) -> ExternalLink:
        """
        Validate and classify link type

        Args:
            link: External link to validate

        Returns:
            ExternalLink: Validated and classified link
        """
        # Detect content type if not already set
        if not link.link_type:
            link.link_type = link.detect_content_type().value

        # Additional validation based on type
        url_lower = link.url.lower()

        if "drive.google.com" in url_lower or "docs.google.com" in url_lower:
            # Extract Google Drive file ID
            match = self.patterns["google_drive"].search(link.url)
            if match:
                file_id = match.group(1)
                link.metadata = {"google_file_id": file_id}

        elif "youtube.com" in url_lower or "youtu.be" in url_lower:
            # Extract YouTube video ID
            match = self.patterns["youtube"].search(link.url)
            if match:
                video_id = match.group(1)
                link.metadata = {"youtube_video_id": video_id}

        return link

    def extract_links_from_hypercert_metadata(
            self,
            hypercert_metadata: Dict[str, Any]
    ) -> List[ExternalLink]:
        """
        Extract external links from hypercert metadata
        
        Args:
            hypercert_metadata: Hypercert metadata dictionary
            
        Returns:
            List[ExternalLink]: Extracted and validated links
        """
        links = []
        
        if not hypercert_metadata:
            return links
            
        # Extract external_url from metadata
        metadata = hypercert_metadata.get("metadata", {})
        if metadata and isinstance(metadata, dict):
            external_url = metadata.get("external_url")
            if external_url and isinstance(external_url, str) and self._is_valid_url(external_url):
                links.append(ExternalLink(
                    url=external_url,
                    source_field="hypercert_metadata.external_url",
                    description="Hypercert external URL"
                ))
                
        # Check for other potential URL fields in metadata
        for field in ["uri", "image", "source"]:
            if metadata and field in metadata:
                url = metadata[field]
                if isinstance(url, str) and self._is_valid_url(url):
                    links.append(ExternalLink(
                        url=url,
                        source_field=f"hypercert_metadata.{field}",
                        description=f"Hypercert {field}"
                    ))
                    
        logger.info(f"Extracted {len(links)} links from hypercert metadata")
        return links


class EcocertQueryService:
    """
    Main service for querying ecocert data and extracting links
    """

    def __init__(self):
        """Initialize the query service"""
        self.hypercerts_client = HypercertsClient()
        self.eas_client = EASClient()
        self.link_extractor = LinkExtractor()
        logger.info("Initialized EcocertQueryService")

    def query_ecocert(self, ecocert_id: str) -> Optional[EcocertData]:
        """
        Query complete ecocert data with external links

        Args:
            ecocert_id: Ecocert identifier

        Returns:
            Optional[EcocertData]: Complete ecocert data with links
        """
        logger.info(f"Querying ecocert: {ecocert_id}")

        # Step 1: Get attestation UID from Hypercerts
        attestation_uid = self.hypercerts_client.get_attestation_uid_from_ecocert(ecocert_id)

        if not attestation_uid:
            logger.error(f"No attestation found for ecocert {ecocert_id}")
            return None

        # Step 2: Get attestation data from EAS
        attestation_data = self.eas_client.get_attestation_by_uid(attestation_uid)

        if not attestation_data:
            logger.error(f"Failed to get attestation data for UID {attestation_uid}")
            return None

        # Step 3: Get additional metadata from Hypercerts
        hypercert_metadata = self.hypercerts_client.get_hypercert_metadata(ecocert_id)

        # Step 4: Extract external links from both attestations and hypercert metadata
        external_links = []
        
        # Extract from attestation data
        attestation_links = self.link_extractor.extract_links_from_attestation(attestation_data)
        external_links.extend(attestation_links)
        
        # Extract from hypercert metadata
        hypercert_links = self.link_extractor.extract_links_from_hypercert_metadata(hypercert_metadata)
        external_links.extend(hypercert_links)

        # Step 5: Validate and classify all links
        validated_links = []
        for link in external_links:
            validated_link = self.link_extractor.validate_and_classify_link(link)
            validated_links.append(validated_link)

        # Create EcocertData object
        ecocert_data = EcocertData(
            ecocert_id=ecocert_id,
            attestation_uid=attestation_uid,
            external_links=validated_links,
            metadata={
                "attestation": attestation_data,
                "hypercert": hypercert_metadata
            },
            created_at=datetime.now(timezone.utc)
        )

        logger.info(
            f"Successfully queried ecocert {ecocert_id}: "
            f"found {len(validated_links)} external links"
        )

        return ecocert_data

    def batch_query_ecocerts(
            self,
            ecocert_ids: List[str]
    ) -> Dict[str, EcocertData]:
        """
        Query multiple ecocerts

        Args:
            ecocert_ids: List of ecocert identifiers

        Returns:
            Dict[str, EcocertData]: Map of ecocert ID to data
        """
        results = {}

        for ecocert_id in ecocert_ids:
            try:
                ecocert_data = self.query_ecocert(ecocert_id)
                if ecocert_data:
                    results[ecocert_id] = ecocert_data
                else:
                    logger.warning(f"No data retrieved for {ecocert_id}")

                # Small delay to avoid rate limiting
                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Failed to query {ecocert_id}: {e}")

        logger.info(f"Batch query completed: {len(results)}/{len(ecocert_ids)} successful")
        return results
