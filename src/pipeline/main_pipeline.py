"""
Main pipeline to process all ecocerts
"""
import time
from datetime import datetime, timezone
from typing import Dict, Any


from src.config import get_settings
from src.config.logging_config import get_logger
from src.core.database_operations import DatabaseOperations
from src.core.graphql_client import EcocertQueryService
from src.storage.archive_manager import ArchiveManager

logger = get_logger(__name__)

# The 9 ecocert IDs to process
ECOCERT_IDS = [
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31305977756726338638630463883722675453952",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31646260123647277102093838491154443665408",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-31986542490568215565557213098586211876864",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-42875578232038246396385200536402794643456",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-32326824857489154029020587706017980088320",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-32667107224410092492483962313449748299776",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-33007389591331030955947336920881516511232",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-33687954325172907882874086135745052934144",
    "42220-0x16bA53B74c234C870c61EFC04cD418B8f2865959-35389366159777600200190959172903893991424",
]


class MainPipeline:
    """
    Main pipeline orchestrator for processing ecocerts
    """

    def __init__(self):
        """Initialize pipeline components"""
        self.settings = get_settings()
        self.query_service = EcocertQueryService()
        self.archive_manager = ArchiveManager()
        self.db_ops = DatabaseOperations()

        logger.info("Initialized MainPipeline")

    def process_ecocert(self, ecocert_id: str) -> Dict[str, Any]:
        """
        Process a single ecocert

        Args:
            ecocert_id: Ecocert ID to process

        Returns:
            Dict: Processing results
        """
        result = {
            'ecocert_id': ecocert_id,
            'success': False,
            'links_found': 0,
            'links_archived': 0,
            'links_failed': 0,
            'ipfs_hashes': [],
            'error': None
        }

        try:
            # Step 1: Query ecocert data
            logger.info(f"Querying ecocert: {ecocert_id}")
            ecocert_data = self.query_service.query_ecocert(ecocert_id)

            if not ecocert_data:
                result['error'] = "Failed to query ecocert data"
                return result

            result['links_found'] = len(ecocert_data.external_links)

            # Step 2: Archive links
            logger.info(f"Archiving {len(ecocert_data.external_links)} links for {ecocert_id}")
            archive_results = self.archive_manager.archive_ecocert_links(
                ecocert_id=ecocert_data.ecocert_id,
                attestation_uid=ecocert_data.attestation_uid,
                links=ecocert_data.external_links
            )

            # Step 3: Record results
            result['links_archived'] = archive_results['successful']
            result['links_failed'] = archive_results['failed']
            result['ipfs_hashes'] = [
                content['ipfs_hash']
                for content in archive_results['archived_content']
            ]

            # Mark as successful if at least one link was archived
            result['success'] = result['links_archived'] > 0

            # Step 4: Update database
            self.db_ops.mark_ecocert_complete(ecocert_id, {
                'total': result['links_found'],
                'processed': result['links_archived'],
                'failed': result['links_failed']
            })

        except Exception as e:
            logger.error(f"Failed to process ecocert {ecocert_id}: {e}")
            result['error'] = str(e)

        return result

    def run_all_ecocerts(self) -> Dict[str, Any]:
        """
        Process all 9 ecocerts

        Returns:
            Dict: Complete pipeline results
        """
        start_time = time.time()
        results = {
            'start_time': datetime.now(timezone.utc).isoformat(),
            'ecocerts_processed': [],
            'total_ecocerts': len(ECOCERT_IDS),
            'successful_ecocerts': 0,
            'failed_ecocerts': 0,
            'total_links_found': 0,
            'total_links_archived': 0,
            'total_links_failed': 0,
            'all_ipfs_hashes': []
        }

        logger.info(f"Starting pipeline for {len(ECOCERT_IDS)} ecocerts")

        for i, ecocert_id in enumerate(ECOCERT_IDS, 1):
            logger.info(f"Processing ecocert {i}/{len(ECOCERT_IDS)}: {ecocert_id}")

            # Process ecocert
            ecocert_result = self.process_ecocert(ecocert_id)
            results['ecocerts_processed'].append(ecocert_result)

            # Update totals
            if ecocert_result['success']:
                results['successful_ecocerts'] += 1
            else:
                results['failed_ecocerts'] += 1

            results['total_links_found'] += ecocert_result['links_found']
            results['total_links_archived'] += ecocert_result['links_archived']
            results['total_links_failed'] += ecocert_result['links_failed']
            results['all_ipfs_hashes'].extend(ecocert_result['ipfs_hashes'])

            # Small delay between ecocerts
            if i < len(ECOCERT_IDS):
                time.sleep(2)

        # Get final statistics
        results['database_summary'] = self.db_ops.get_processing_summary()
        results['end_time'] = datetime.now(timezone.utc).isoformat()
        results['total_time_seconds'] = time.time() - start_time

        # Log summary
        logger.info(
            f"Pipeline complete: {results['successful_ecocerts']}/{results['total_ecocerts']} "
            f"ecocerts successful, {results['total_links_archived']} links archived"
        )

        return results
