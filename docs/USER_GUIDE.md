# PulseLens User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Web Dashboard](#web-dashboard)
5. [Command Line Usage](#command-line-usage)
6. [Python API](#python-api)
7. [Configuration](#configuration)
8. [IOC Analysis](#ioc-analysis)
9. [Reports](#reports)
10. [Automation](#automation)
11. [Troubleshooting](#troubleshooting)

## Introduction

PulseLens is an open-source threat intelligence platform that analyzes Indicators of Compromise (IOCs) using multiple data sources and machine learning techniques. It provides:

- **IOC Normalization**: Standardizes different IOC formats
- **Threat Intelligence Enrichment**: Integrates with OTX and other feeds
- **Severity Classification**: Automated risk assessment
- **Correlation Analysis**: Identifies relationships between IOCs
- **Comprehensive Reporting**: JSON, HTML, and PDF reports
- **Web Dashboard**: Interactive analysis interface
- **Automation**: Scheduled analysis and alerting

## Installation

### Prerequisites
- Python 3.8+ (3.10+ recommended)
- pip package manager
- 2GB+ RAM for processing large IOC lists
- Internet connection for threat intelligence feeds

### Step 1: Clone Repository
```bash
git clone https://github.com/your-org/pulselens.git
cd pulselens
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment
```bash
# Copy sample configuration
cp config_sample.py config.py

# Edit configuration with your settings
nano config.py
```

### Step 4: Setup Database
```bash
python scripts/setup_validation.py --mode setup
```

### Step 5: Verify Installation
```bash
python scripts/setup_validation.py --mode validate
```

## Quick Start

### 1. Start the Web Dashboard
```bash
python dashboard_runner.py
```

The dashboard will be available at `http://127.0.0.1:4000`

### 2. Analyze Your First IOCs
Create a file `test_iocs.txt` with some IOCs:
```
192.168.1.1
malicious.com
http://suspicious-site.com
test@example.com
```

Run analysis:
```bash
python main.py test_iocs.txt
```

### 3. View Results
- Open the web dashboard
- Navigate to "Reports" section
- View the generated analysis report

## Web Dashboard

### Accessing the Dashboard
1. Start the dashboard: `python dashboard_runner.py`
2. Open browser to: `http://127.0.0.1:4000`

### Dashboard Features

#### Home Page
- System statistics
- Recent analysis results
- Quick IOC analysis form

#### IOC Management
- **IOC List**: View all IOCs in database
- **Add IOCs**: Upload files or paste IOC lists
- **IOC Details**: View enrichment and classification data

#### Analysis
- **Analyze IOCs**: Submit new IOC lists for analysis
- **Analysis Results**: View detailed analysis reports
- **Export Data**: Download results in various formats

#### Reports
- **Report Library**: View all generated reports
- **Report Details**: Interactive report viewer
- **Download Reports**: Export individual or batch reports

#### Settings
- **Configuration**: API keys and system settings
- **Database Management**: Cache cleanup and maintenance
- **System Status**: Health checks and diagnostics

### Using the IOC Analysis Form

1. **Input Method**:
   - **File Upload**: Select a file with IOCs
   - **Text Input**: Paste IOC list directly
   - **API Input**: Use REST endpoint

2. **Analysis Options**:
   - **Enrichment**: Enable threat intelligence lookup
   - **Cache**: Use cached enrichment data
   - **Save Results**: Store in database

3. **IOC Formats Supported**:
   - **IP Addresses**: `192.168.1.1`, `10.0.0.1`
   - **Domains**: `example.com`, `malicious-site.org`
   - **URLs**: `http://example.com/path`
   - **Emails**: `test@example.com`
   - **Hashes**: MD5, SHA1, SHA256

## Command Line Usage

### Basic IOC Analysis
```bash
# Analyze IOCs from file
python main.py input.txt

# Analyze with specific options
python main.py input.txt --no-cache --no-save --output-dir custom_reports
```

### Automated Analysis Scripts
```bash
# Analyze directory of IOC files
python scripts/automated_analysis.py --mode directory --input ioc_files/

# Analyze recent threat feeds
python scripts/automated_analysis.py --mode recent --hours 24

# Analyze single file
python scripts/automated_analysis.py --mode file --input threats.txt
```

### Configuration and Setup
```bash
# Validate configuration
python scripts/setup_validation.py --mode validate

# Fix configuration issues
python scripts/setup_validation.py --mode setup --fix

# Generate sample configuration
python scripts/setup_validation.py --mode setup
```

### Cron Job Setup
```bash
# Setup daily analysis
python scripts/setup_cron.py --mode daily --input-dir /path/to/iocs --install

# Setup recent feeds analysis
python scripts/setup_cron.py --mode recent --interval hourly --install

# Setup weekly comprehensive analysis
python scripts/setup_cron.py --mode weekly --input-dir /path/to/iocs --day sunday --install
```

### Testing
```bash
# Run all tests
python -m pytest tests/

# Run specific tests
python -m pytest tests/test_input_layer.py

# Run with coverage report
python -m pytest --cov=pulselens tests/
```

## Python API

### Basic Usage
```python
from pulselens.main import PulseLens

# Initialize with configuration
config = {
    'DATABASE_PATH': 'data/cache.db',
    'OTX_API_KEY': 'your-api-key',
    'CACHE_EXPIRY_HOURS': 24
}
pulselens = PulseLens(config)

# Analyze IOCs
result = pulselens.analyze_iocs('input.txt')

# Check results
if result['status'] == 'success':
    print(f"Analyzed {result['classified_ioc_count']} IOCs")
    print(f"High risk IOCs: {result['severity_summary']['high']}")
```

### Advanced Usage
```python
# Process IOC list programmatically
ioc_list = ['192.168.1.1', 'malicious.com', 'test@example.com']
result = pulselens.analyze_iocs_list(ioc_list)

# Custom analysis options
result = pulselens.analyze_iocs(
    input_file='threats.txt',
    use_cache=True,
    save_to_db=True,
    enrich=True
)

# Generate specific reports
if result['status'] == 'success':
    # JSON report
    json_report = pulselens.json_reporter.generate_report(result)
    
    # HTML report
    html_report = pulselens.html_reporter.generate_report(result)
    
    # PDF report (if available)
    if pulselens.pdf_reporter:
        pdf_report = pulselens.pdf_reporter.generate_report(result)
```

### Component-Level Usage
```python
# IOC Reading and Validation
from pulselens.input.reader import IOCReader
from pulselens.input.validator import IOCValidator

reader = IOCReader()
validator = IOCValidator()

# Read IOCs from various sources
iocs = reader.read_from_file('input.txt')
iocs = reader.read_from_text('192.168.1.1, malicious.com')

# Validate and normalize
for ioc in iocs:
    ioc_type = validator.detect_ioc_type(ioc)
    if validator.is_valid_ioc(ioc, ioc_type):
        normalized = validator.normalize_ioc(ioc)
        print(f"Valid IOC: {normalized} ({ioc_type})")

# Threat Intelligence Enrichment
from pulselens.enrichment.otx import OTXEnricher

enricher = OTXEnricher(api_key='your-key')
enrichment = enricher.enrich_ioc('malicious.com', 'domain')
print(f"Reputation: {enrichment.get('reputation', 'unknown')}")

# Severity Classification
from pulselens.classification.severity import SeverityClassifier

classifier = SeverityClassifier()
severity = classifier.classify_ioc(ioc_data, enrichment_data)
print(f"Severity: {severity['level']} (Score: {severity['score']})")
```

## Configuration

### Main Configuration File (config.py)

```python
# Database Configuration
DATABASE_PATH = "data/cache.db"
CACHE_EXPIRY_HOURS = 24

# Flask Dashboard
FLASK_SECRET_KEY = "change-this-secret-key"
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 4000
DASHBOARD_DEBUG = False

# OTX API Configuration
OTX_API_KEY = "your-otx-api-key"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_RATE_LIMIT = 60

# Severity Classification
SEVERITY_THRESHOLDS = {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.0
}

# IOC Type Weights
IOC_TYPE_WEIGHTS = {
    "ip": 1.0,
    "domain": 0.9,
    "url": 0.8,
    "hash": 0.7,
    "email": 0.6
}

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/pulselens.log"
```

### Environment Variables
```bash
export OTX_API_KEY="your-api-key"
export DATABASE_PATH="custom/path/cache.db"
export LOG_LEVEL="DEBUG"
export FLASK_SECRET_KEY="production-secret-key"
```

### OTX API Setup
1. Visit [OTX Portal](https://otx.alienvault.com)
2. Create account or login
3. Navigate to API Keys section
4. Generate new API key
5. Add key to configuration

## IOC Analysis

### Supported IOC Types

#### IP Addresses
- **Format**: `192.168.1.1`, `10.0.0.1`
- **Validation**: IPv4 address format checking
- **Enrichment**: Geolocation, reputation, ASN info

#### Domain Names
- **Format**: `example.com`, `sub.domain.org`
- **Validation**: DNS format checking
- **Enrichment**: WHOIS, DNS records, reputation

#### URLs
- **Format**: `http://example.com/path`, `https://site.com`
- **Validation**: URL format checking
- **Enrichment**: URL analysis, domain reputation

#### Email Addresses
- **Format**: `user@domain.com`
- **Validation**: Email format checking
- **Enrichment**: Domain reputation, email validation

#### File Hashes
- **Format**: MD5, SHA1, SHA256 hashes
- **Validation**: Hash format checking
- **Enrichment**: VirusTotal integration (if available)

### Analysis Process

1. **Input Validation**: Check IOC format and type
2. **Normalization**: Standardize IOC format
3. **Enrichment**: Query threat intelligence feeds
4. **Classification**: Apply severity scoring rules
5. **Correlation**: Identify relationships with other IOCs
6. **Reporting**: Generate analysis reports

### Severity Levels

- **Critical** (8.0+): Immediate action required
- **High** (6.0-7.9): Investigate urgently
- **Medium** (4.0-5.9): Monitor and investigate
- **Low** (2.0-3.9): Informational
- **Info** (0.0-1.9): Background information

## Reports

### Report Types

#### JSON Reports
- **Format**: Structured JSON data
- **Use Case**: API integration, automated processing
- **Features**: Complete analysis data, machine-readable

#### HTML Reports
- **Format**: Interactive HTML page
- **Use Case**: Human review, presentation
- **Features**: Charts, tables, filtering

#### PDF Reports
- **Format**: PDF document
- **Use Case**: Executive summaries, archival
- **Features**: Professional formatting, printable

### Report Content

#### Executive Summary
- Total IOCs analyzed
- Risk distribution
- Key findings
- Recommendations

#### IOC Details
- IOC value and type
- Severity classification
- Threat intelligence data
- Confidence scores

#### Recommendations
- Immediate actions
- Investigation steps
- Monitoring guidelines
- Prevention measures

#### Technical Appendix
- Data sources used
- Classification rules applied
- Processing statistics
- Glossary of terms

### Report Management

#### Viewing Reports
1. Access web dashboard
2. Navigate to "Reports" section
3. Click on report title
4. Use interactive features

#### Downloading Reports
1. Select report(s) from list
2. Choose download format
3. Click "Download Selected"
4. Save to local system

#### Report Automation
```bash
# Generate scheduled reports
python scripts/automated_analysis.py --mode directory --input iocs/

# Export all reports
curl -X POST http://127.0.0.1:4000/api/reports/download
```

## Automation

### Scheduled Analysis

#### Cron Jobs
```bash
# Daily IOC analysis
0 2 * * * cd /path/to/pulselens && python scripts/automated_analysis.py --mode directory --input /path/to/iocs

# Hourly recent feeds analysis
0 * * * * cd /path/to/pulselens && python scripts/automated_analysis.py --mode recent --hours 1

# Weekly comprehensive analysis
0 3 * * 0 cd /path/to/pulselens && python scripts/automated_analysis.py --mode directory --input /path/to/iocs --pattern "*.txt"
```

#### Setup Automation
```bash
# Install cron jobs
python scripts/setup_cron.py --mode daily --input-dir /path/to/iocs --install

# Verify cron jobs
crontab -l
```

### API Integration

#### Webhook Integration
```python
import requests

# Submit IOCs for analysis
response = requests.post('http://127.0.0.1:4000/api/analyze', json={
    'iocs': ['192.168.1.1', 'malicious.com'],
    'enrich': True,
    'save_to_db': True
})

result = response.json()
if result['status'] == 'success':
    analysis_id = result['data']['analysis_id']
```

#### SIEM Integration
```python
# Export to SIEM format
def export_to_siem(analysis_data):
    siem_events = []
    for ioc in analysis_data['iocs']:
        if ioc['severity']['level'] in ['critical', 'high']:
            event = {
                'timestamp': ioc['last_seen'],
                'ioc_value': ioc['ioc_value'],
                'ioc_type': ioc['ioc_type'],
                'severity': ioc['severity']['level'],
                'source': 'pulselens'
            }
            siem_events.append(event)
    return siem_events
```

### Monitoring and Alerting

#### Log Monitoring
```bash
# Monitor analysis logs
tail -f logs/pulselens.log | grep "ERROR\|WARNING"

# Check analysis statistics
grep "IOC Processing" logs/pulselens.log | tail -10
```

#### Health Checks
```python
import requests

# Check dashboard status
response = requests.get('http://127.0.0.1:4000/api/dashboard/stats')
if response.status_code == 200:
    stats = response.json()
    print(f"System healthy: {stats['data']['total_iocs']} IOCs in database")
```

## Troubleshooting

### Common Issues

#### Installation Problems
**Issue**: Import errors for missing packages
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

**Issue**: Permission denied creating database
```bash
# Solution: Check permissions
mkdir -p data logs reports
chmod 755 data logs reports
```

#### API Key Issues
**Issue**: OTX API not working
```bash
# Solution: Verify API key
curl -H "X-OTX-API-KEY: your-key" https://otx.alienvault.com/api/v1/user/me

# Check rate limits
grep "OTX API" logs/pulselens.log
```

#### Performance Issues
**Issue**: Slow analysis of large IOC lists
```bash
# Solution: Process in smaller batches
python main.py large_ioc_list.txt --batch-size 100

# Clear cache if needed
rm data/cache.db
python scripts/setup_validation.py --mode setup
```

#### Dashboard Issues
**Issue**: Dashboard not accessible
```bash
# Solution: Check if service is running
ps aux | grep python

# Restart dashboard
python dashboard_runner.py

# Check port availability
netstat -an | grep 4000
```

### Debug Mode

#### Enable Debug Logging
```python
# In config.py
LOG_LEVEL = "DEBUG"
DASHBOARD_DEBUG = True
```

#### Run Validation
```bash
# Full system validation
python scripts/setup_validation.py --mode full

# Fix common issues
python scripts/setup_validation.py --mode setup --fix
```

#### Component Testing
```bash
# Test individual components
python -m pytest tests/test_input_layer.py -v
python -m pytest tests/test_normalization.py -v
python -m pytest tests/test_enrichment.py -v
```

### Getting Help

#### Check Logs
```bash
# View recent errors
tail -50 logs/pulselens.log | grep ERROR

# View analysis statistics
grep "IOC Processing" logs/pulselens.log
```

#### System Information
```bash
# Check system status
python scripts/setup_validation.py --mode validate

# View configuration
python -c "import config; print(vars(config))"
```

#### Community Support
- GitHub Issues: Report bugs and feature requests
- Documentation: Check API docs and guides
- Examples: Review sample scripts and configurations

### Performance Optimization

#### Database Optimization
```bash
# Clean up old cache entries
python -c "
from pulselens.storage.db import Database
db = Database()
db.cleanup_old_entries(days=7)
"
```

#### Memory Optimization
```python
# Process large files in chunks
def process_large_file(filename, chunk_size=1000):
    reader = IOCReader()
    with open(filename, 'r') as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk
```

#### Cache Optimization
```python
# Configure cache settings
config = {
    'CACHE_EXPIRY_HOURS': 12,  # Shorter cache for fresh data
    'AUTO_CLEANUP_CACHE': True,
    'MAX_CACHE_SIZE': 1000000  # Limit cache size
}
```

## Best Practices

### IOC Management
1. **Normalize Input**: Use consistent IOC formats
2. **Validate Sources**: Only analyze IOCs from trusted sources
3. **Regular Cleanup**: Remove outdated IOCs from database
4. **Tagging**: Use descriptive tags for IOC categorization

### Analysis Workflow
1. **Start Small**: Test with small IOC lists first
2. **Review Results**: Validate analysis accuracy
3. **Tune Thresholds**: Adjust severity scoring as needed
4. **Document Settings**: Keep configuration changes documented

### Security Considerations
1. **API Keys**: Store securely, rotate regularly
2. **Network Access**: Limit outbound connections
3. **Data Privacy**: Handle sensitive IOCs appropriately
4. **Access Control**: Implement authentication in production

### Operational Excellence
1. **Monitoring**: Set up log monitoring and alerts
2. **Backups**: Regular database and configuration backups
3. **Testing**: Run tests after configuration changes
4. **Documentation**: Maintain operational procedures

This guide provides comprehensive information for using PulseLens effectively. For technical details and API references, see the [API Documentation](API_DOCUMENTATION.md).
