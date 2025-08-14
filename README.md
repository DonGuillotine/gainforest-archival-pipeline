# GainForest Archival Pipeline

## Immutable Proof of Impact Storage System

A Python pipeline for archiving external content from GainForest ecocerts to IPFS, ensuring permanent and immutable storage of environmental impact data.

## Features

- 🔍 **GraphQL Integration**: Query ecocerts from Hypercerts and EAS APIs
- 📥 **Multi-Source Support**: Handle Google Drive/Docs and YouTube content
- 🔒 **Security First**: Comprehensive validation and sanitization
- 🗄️ **IPFS Storage**: Permanent archival using Pinata API
- 📊 **SQLite Tracking**: Complete audit trail of archived content
- 🔄 **Retry Logic**: Resilient error handling with exponential backoff
- 📈 **Progress Tracking**: Real-time status updates and statistics
- 🎨 **Rich CLI**: Beautiful terminal interface with color output

## Installation

### Prerequisites

- Python 3.9 or higher
- SQLite3
- Git

### Setup

1. Clone the repository:
```bash
git clone https://github.com/DonGuillotine/gainforest-archival-pipeline.git
cd gainforest-archival-pipeline

```

2.  Create virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

```

3.  Install dependencies:

```bash
pip install -r requirements.txt

```

4.  Configure environment:

```bash
cp .env.example .env
# Edit .env with your Pinata API keys and other settings

```

5.  Initialize the system:

```bash
python -m src.main init

```
<img width="1353" height="843" alt="Screenshot 2025-08-11 102048" src="https://github.com/user-attachments/assets/2f5b4fd4-c2ae-46d7-915a-f8bd97d0a869" />

## Usage

### Process all 9 ecocerts (Main Command)

```bash
python -m src.main run-all
```

<img width="1821" height="907" alt="image" src="https://github.com/user-attachments/assets/4a090b63-427f-417f-96a1-75ce788490ce" />


This will:
1. Query each ecocert from Hypercerts/EAS
2. Extract external links from attestations
3. Download content from Google Drive/YouTube
4. Upload to IPFS via Pinata
5. Store IPFS hashes in database

### Archive Ecocerts

```bash
# Process default 9 ecocerts
python -m src.main archive --use-defaults

# Process specific ecocerts
python -m src.main archive --ecocert-ids "ID1" --ecocert-ids "ID2"

# Dry run mode
python -m src.main archive --use-defaults --dry-run

```

### Check Status

```bash
# Overall statistics
python -m src.main status

# Specific ecocert status
python -m src.main status --ecocert-id "YOUR_ECOCERT_ID"

```
<img width="987" height="213" alt="Screenshot 2025-08-11 104012" src="https://github.com/user-attachments/assets/cf020f63-80fe-48ae-8d7c-4104b795e87b" />


### Run Tests

```bash
python -m src.main test

```
<img width="989" height="294" alt="Screenshot 2025-08-11 104036" src="https://github.com/user-attachments/assets/351fcc98-6133-4e72-aa9f-149668bb0a0d" />

### Unit Run Tests

```bash
pytest tests -v

```
<img width="1839" height="817" alt="image" src="https://github.com/user-attachments/assets/1d435b69-6838-4dd0-abd2-e976a2f9af97" />


## Configuration

Key settings in `.env`:

-   `PINATA_API_KEY`: Your Pinata API key for IPFS uploads
-   `PINATA_SECRET_API_KEY`: Your Pinata secret key
-   `MAX_FILE_SIZE`: Maximum file size limit (default: 100MB)
-   `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)
-   `MAX_RETRIES`: Number of retry attempts for failed operations

## Project Structure

```
gainforest-archival-pipeline/
├── src/
│   ├── config/              # Configuration and settings
│   │   ├── settings.py      # Pydantic settings management
│   │   └── logging_config.py # Logging configuration
│   ├── core/                # Core functionality
│   │   ├── database.py      # Database management
│   │   ├── graphql_client.py # GraphQL queries for Hypercerts/EAS
│   │   └── models.py        # Data models
│   ├── handlers/            # Content download handlers
│   │   ├── google_drive.py  # Google Drive/Docs downloader
│   │   └── youtube.py       # YouTube video downloader
│   ├── security/            # Security validation
│   │   ├── validator.py     # URL validation
│   │   └── sanitizer.py     # Input sanitization
│   ├── storage/             # IPFS integration
│   │   └── ipfs_client.py   # Pinata API client
│   ├── pipeline/            # Main pipeline
│   │   └── main_pipeline.py # Orchestrates entire process
│   └── main.py              # CLI entry point
├── data/
│   └── archive.db           # SQLite database
├── downloads/               # Downloaded content
│   ├── temp/               # Temporary files
│   └── completed/          # Validated content
├── logs/                   # Application logs
├── .env                    # Environment variables (create from .env.example)
├── requirements.txt        # Python dependencies
└── README.md              # This file

```

## Database Schema

The system uses SQLite with three main tables:

-   **archived_content**: Stores IPFS hashes and metadata
-   **processing_status**: Tracks progress per ecocert
-   **error_log**: Captures and persists errors

## Security Features

-   URL whitelist validation
-   File size limits
-   Content type verification
-   Input sanitization
-   Optional virus scanning
-   Secure credential handling

## Development

### Running Tests

```bash
pytest tests/

```

### Debug Mode

```bash
python -m src.main --debug archive --use-defaults

```

## License

MIT License - See LICENSE file for details

## Support

For issues or questions, please open an issue or contact me on [infect3dlab@gmail.com](mailto:infect3dlab@gmail.com)
