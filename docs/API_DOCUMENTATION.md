# PulseLens API Documentation

## Overview

PulseLens provides both REST API endpoints and Python APIs for IOC analysis, enrichment, and reporting.

## REST API Endpoints

### Base URL
```
http://127.0.0.1:4000/api
```

### Authentication
Currently no authentication required (development mode).

### Response Format
All API responses use JSON format:
```json
{
  "status": "success|error",
  "message": "Description",
  "data": {...},
  "timestamp": "2025-12-21T12:00:00Z"
}
```

## IOC Management

### GET /api/iocs
List all IOCs in the database.

**Query Parameters:**
- `type` (optional): Filter by IOC type (ip, domain, url, email, hash)
- `severity` (optional): Filter by severity level (critical, high, medium, low, info)
- `limit` (optional): Maximum number of results (default: 100)
- `offset` (optional): Offset for pagination (default: 0)

**Response:**
```json
{
  "status": "success",
  "data": {
    "iocs": [
      {
        "ioc_value": "192.168.1.1",
        "ioc_type": "ip",
        "severity": {"level": "medium", "score": 4.5},
        "confidence": "high",
        "first_seen": "2025-12-21T10:00:00Z",
        "last_seen": "2025-12-21T12:00:00Z",
        "tags": ["malicious", "c2"],
        "enrichment": {...}
      }
    ],
    "total_count": 150,
    "filtered_count": 25
  }
}
```

### POST /api/iocs
Add new IOCs to the database.

**Request Body:**
```json
{
  "iocs": [
    {
      "ioc_value": "malicious.com",
      "ioc_type": "domain",
      "confidence": "medium",
      "tags": ["suspicious"]
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "IOCs added successfully",
  "data": {
    "added_count": 1,
    "duplicate_count": 0
  }
}
```

## IOC Analysis

### POST /api/analyze
Analyze IOCs for threat intelligence.

**Request Body:**
```json
{
  "iocs": ["192.168.1.1", "malicious.com"],
  "enrich": true,
  "save_to_db": true
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "analysis_id": "uuid-analysis-id",
    "status": "completed",
    "classified_ioc_count": 2,
    "duration_seconds": 2.5,
    "iocs": [...],
    "recommendations": [...]
  }
}
```

### GET /api/analysis/{analysis_id}
Get analysis results by ID.

**Response:**
```json
{
  "status": "success",
  "data": {
    "analysis_id": "uuid-analysis-id",
    "status": "completed",
    "iocs": [...],
    "recommendations": [...],
    "generated_at": "2025-12-21T12:00:00Z"
  }
}
```

### GET /api/analysis/{analysis_id}/download
Download analysis report as JSON file.

**Response:** File download with `Content-Disposition: attachment`

## Export Endpoints

### GET /api/export/{format}
Export data in specified format.

**Parameters:**
- `format`: Export format (json, csv, html)

**Response:** File download with appropriate MIME type

### POST /api/reports/download
Download selected reports.

**Request Body:**
```json
{
  "report_ids": ["report1", "report2", "report3"]
}
```

**Response:** Combined JSON file with selected reports

## Dashboard Endpoints

### GET /api/dashboard/stats
Get dashboard statistics.

**Response:**
```json
{
  "status": "success",
  "data": {
    "total_iocs": 1250,
    "high_risk_iocs": 45,
    "recent_analyses": 12,
    "cache_size": "2.5MB"
  }
}
```

## Python API

### Core Classes

#### PulseLens
Main analysis engine.

```python
from pulselens.main import PulseLens

# Initialize
config = {
    'DATABASE_PATH': 'data/cache.db',
    'OTX_API_KEY': 'your-api-key'
}
pulselens = PulseLens(config)

# Analyze IOCs
result = pulselens.analyze_iocs('input.txt', use_cache=True, save_to_db=True)
```

#### IOCReader
Read IOCs from various sources.

```python
from pulselens.input.reader import IOCReader

reader = IOCReader()

# Read from file
iocs = reader.read_from_file('input.txt')

# Read from text
iocs = reader.read_from_text('192.168.1.1, malicious.com')
```

#### IOCValidator
Validate and normalize IOCs.

```python
from pulselens.input.validator import IOCValidator

validator = IOCValidator()

# Validate IOC
is_valid = validator.is_valid_ioc('192.168.1.1', 'ip')

# Detect type
ioc_type = validator.detect_ioc_type('example.com')

# Normalize
normalized = validator.normalize_ioc('EXAMPLE.COM')
```

#### IOCNormalizer
Normalize IOC formats.

```python
from pulselens.normalization.normalize import IOCNormalizer

normalizer = IOCNormalizer()
normalized = normalizer.normalize('EXAMPLE.COM', 'domain')
```

#### OTXEnricher
Threat intelligence enrichment.

```python
from pulselens.enrichment.otx import OTXEnricher

enricher = OTXEnricher(api_key='your-key')
enrichment = enricher.enrich_ioc('malicious.com', 'domain')
```

#### SeverityClassifier
Severity classification.

```python
from pulselens.classification.severity import SeverityClassifier

classifier = SeverityClassifier()
severity = classifier.classify_ioc(ioc_data, enrichment_data)
```

### Reporting

#### JSON Reporter
```python
from pulselens.reporting.json_reporter import JSONReporter

reporter = JSONReporter()
report_path = reporter.generate_report(analysis_data)
```

#### HTML Reporter
```python
from pulselens.reporting.html_reporter import HTMLReporter

reporter = HTMLReporter()
report_path = reporter.generate_report(analysis_data)
```

#### PDF Reporter (Optional)
```python
from pulselens.reporting.pdf_reporter import PDFReporter

reporter = PDFReporter(config)
if reporter.is_available():
    report_path = reporter.generate_report(analysis_data)
```

### Correlation Analysis (Optional)

#### NetworkX Correlation
```python
from pulselens.correlation.networkx_correlation import NetworkXCorrelation

correlation = NetworkXCorrelation(config)
if correlation.is_available():
    graph = correlation.build_correlation_graph(iocs)
    clusters = correlation.find_correlated_clusters()
```

## Error Handling

### HTTP Status Codes
- `200`: Success
- `400`: Bad Request
- `404`: Not Found
- `500`: Internal Server Error

### Error Response Format
```json
{
  "status": "error",
  "message": "Error description",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2025-12-21T12:00:00Z"
}
```

### Common Error Codes
- `VALIDATION_ERROR`: Invalid input data
- `IOC_NOT_FOUND`: IOC not found in database
- `ENRICHMENT_FAILED`: Threat intelligence enrichment failed
- `CLASSIFICATION_ERROR`: Severity classification failed
- `REPORT_GENERATION_FAILED`: Report generation failed

## Rate Limiting

- OTX API: 60 requests per minute
- General API: No rate limiting (development mode)

## Configuration

### Environment Variables
```bash
export DATABASE_PATH="data/cache.db"
export OTX_API_KEY="your-api-key"
export FLASK_SECRET_KEY="your-secret-key"
export LOG_LEVEL="INFO"
```

### Config File
See `config.py` for complete configuration options.

## Examples

### Complete Analysis Workflow
```python
from pulselens.main import PulseLens

# Initialize
config = {
    'DATABASE_PATH': 'data/cache.db',
    'OTX_API_KEY': 'your-api-key'
}
pulselens = PulseLens(config)

# Analyze IOCs
result = pulselens.analyze_iocs(
    input_file='threat_indicators.txt',
    use_cache=True,
    save_to_db=True
)

# Generate reports
if result['status'] == 'success':
    json_report = pulselens.json_reporter.generate_report(result)
    html_report = pulselens.html_reporter.generate_report(result)
    
    print(f"Analysis completed: {result['classified_ioc_count']} IOCs processed")
    print(f"Reports: {json_report}, {html_report}")
```

### Batch Processing
```python
import os
from pulselens.main import PulseLens

pulselens = PulseLens(config)

# Process multiple files
input_dir = 'ioc_files/'
for filename in os.listdir(input_dir):
    if filename.endswith('.txt'):
        filepath = os.path.join(input_dir, filename)
        result = pulselens.analyze_iocs(filepath)
        print(f"Processed {filename}: {result['classified_ioc_count']} IOCs")
```

### Custom IOC Processing
```python
from pulselens.input.reader import IOCReader
from pulselens.input.validator import IOCValidator
from pulselens.normalization.normalize import IOCNormalizer

# Pipeline
reader = IOCReader()
validator = IOCValidator()
normalizer = IOCNormalizer()

# Process IOCs
raw_iocs = reader.read_from_file('input.txt')
processed_iocs = []

for ioc in raw_iocs:
    ioc_type = validator.detect_ioc_type(ioc)
    if validator.is_valid_ioc(ioc, ioc_type):
        normalized = normalizer.normalize(ioc, ioc_type)
        processed_iocs.append((normalized, ioc_type))

print(f"Processed {len(processed_iocs)} valid IOCs")
```

## Integration Examples

### Flask Web Application
```python
from flask import Flask, request, jsonify
from pulselens.main import PulseLens

app = Flask(__name__)
pulselens = PulseLens(config)

@app.route('/api/analyze', methods=['POST'])
def analyze_iocs():
    data = request.get_json()
    iocs = data.get('iocs', [])
    
    result = pulselens.analyze_iocs_list(iocs)
    return jsonify(result)
```

### Command Line Interface
```python
import argparse
from pulselens.main import PulseLens

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', help='IOC input file')
    parser.add_argument('--output', help='Output directory')
    args = parser.parse_args()
    
    pulselens = PulseLens(config)
    result = pulselens.analyze_iocs(args.input_file)
    
    if result['status'] == 'success':
        print(f"Analysis completed: {result['classified_ioc_count']} IOCs")

if __name__ == '__main__':
    main()
```

## Testing

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_input_layer.py

# Run with coverage
python -m pytest --cov=pulselens tests/
```

### Test Examples
```python
import unittest
from pulselens.input.reader import IOCReader

class TestIOCReader(unittest.TestCase):
    def test_read_txt_file(self):
        reader = IOCReader()
        iocs = reader.read_from_file('test_iocs.txt')
        self.assertIsInstance(iocs, list)
```

## Troubleshooting

### Common Issues

1. **OTX API Key Not Working**
   - Verify API key is valid
   - Check rate limits
   - Ensure network connectivity

2. **Database Connection Failed**
   - Check database path
   - Ensure write permissions
   - Verify SQLite installation

3. **Import Errors**
   - Install missing dependencies: `pip install -r requirements.txt`
   - Check Python path configuration

4. **Memory Issues with Large IOC Lists**
   - Process in smaller batches
   - Increase available memory
   - Use streaming for large files

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable debug logging in PulseLens
pulselens = PulseLens(config, debug=True)
```

## Support

For issues and questions:
- Check the logs in `logs/pulselens.log`
- Run validation: `python scripts/setup_validation.py`
- Check configuration: `python scripts/setup_validation.py --mode validate`
