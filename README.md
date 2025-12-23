# PulseLens - IOC Analysis System

A comprehensive threat intelligence platform for analyzing Indicators of Compromise (IOCs) with enrichment, classification, and reporting capabilities.

## Features

- **Multi-format IOC Input**: Support for TXT, JSON, and CSV formats
- **Validation & Normalization**: Automatic IOC validation and standardization
- **Threat Intelligence Enrichment**: OTX API integration for reputation data
- **Rule-based Classification**: Automated severity scoring and classification
- **SQLite Caching**: Local caching and history tracking
- **Comprehensive Reporting**: JSON and HTML report generation
- **Command-line Interface**: Easy-to-use CLI for batch processing

## Quick Start

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd pulselens
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure OTX API key (optional but recommended):
   ```
   # Edit config.py and set your OTX_API_KEY
   # Or set as environment variable:
   export OTX_API_KEY=your_api_key_here
   ```

## Architecture

PulseLens follows a modular architecture with distinct processing layers:

1. **Input Layer**: Read and validate IOCs from various sources
2. **Normalization Layer**: Standardize IOC formats and remove duplicates
3. **Enrichment Layer**: Add threat intelligence data from external sources
4. **Classification Layer**: Assign severity scores based on rules
5. **Storage Layer**: Cache results and maintain history
6. **Reporting Layer**: Generate actionable reports

## Supported IOC Types

- **IP Addresses**: IPv4 and IPv6 addresses
- **Domains**: Domain names with subdomain analysis
- **URLs**: Complete URLs with path and query analysis
- **File Hashes**: MD5, SHA1, SHA256, SHA512
- **Email Addresses**: Email format validation

## Configuration

Edit \config.py\ to customize:

- OTX API settings and rate limits
- Severity classification thresholds
- IOC type weights
- Database paths and cache settings
- Reporting preferences

## Reports

PulseLens generates two types of reports:

### JSON Report
Machine-readable format with complete IOC data, including:
- Normalized IOC values
- Enrichment data from OTX
- Severity classification
- Recommended actions
- Analysis metadata

### HTML Report
Human-readable format with:
- Executive summary
- Interactive tables
- Visual severity indicators
- Actionable recommendations
- Responsive design

## Severity Levels

- **Critical**: Immediate action required (e.g., known malware)
- **High**: Priority investigation (e.g., suspicious indicators)
- **Medium**: Monitor and investigate (e.g., suspicious patterns)
- **Low**: Log and review (e.g., low-risk indicators)
- **Info**: Informational only

## API Integration

### OTX (AlienVault Open Threat Exchange)
- Reputation data
- Pulse information
- Malware sample associations
- Historical threat data

## Database Schema

The SQLite database stores:
- IOC metadata and classifications
- Cached API responses
- Analysis history
- Statistics and metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the documentation
- Review existing issues
- Create a new issue with detailed information

## Version History

### v1.0.0
- Initial release
- Core IOC analysis functionality
- OTX integration
- JSON and HTML reporting
- SQLite caching
- CLI interface
