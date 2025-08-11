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

## Usage

### Initialize Database

```bash
python -m src.main init

```

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

### Run Tests

```bash
python -m src.main test

```

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
│   ├── config/          # Configuration and settings
│   ├── core/            # Database and models
│   ├── handlers/        # Content handlers
│   ├── security/        # Validation and sanitization
│   ├── storage/         # IPFS integration
│   └── main.py          # CLI entry point
├── data/                # SQLite database
├── logs/                # Application logs
└── tests/               # Test suite

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
