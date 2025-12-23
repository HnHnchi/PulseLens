import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
CACHE_DIR = BASE_DIR / 'data'
REPORTS_DIR = BASE_DIR / 'reports'

# PulseLens Version
PULSELENS_VERSION = "1.0.0"

# OTX API Configuration
OTX_API_KEY = os.getenv('OTX_API_KEY', '')  # Set your OTX API key in .env file
OTX_BASE_URL = 'https://otx.alienvault.com/api/v1'
OTX_RATE_LIMIT = 60  # requests per minute

# VirusTotal API Configuration
VIRUSTOTAL_ENABLED = True
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')  # Set your VirusTotal API key in .env file
VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2'
VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute (free tier limit)

# Keyless Threat Intel (abuse.ch)
URLHAUS_ENABLED = True
URLHAUS_BASE_URL = 'https://urlhaus-api.abuse.ch/v1'
URLHAUS_RATE_LIMIT = 60  # requests per minute
URLHAUS_API_KEY = os.getenv('URLHAUS_API_KEY', '')  # Set your URLhaus API key here or as environment variable

THREATFOX_ENABLED = True
THREATFOX_BASE_URL = 'https://threatfox-api.abuse.ch/api/v1/'
THREATFOX_RATE_LIMIT = 60  # requests per minute
THREATFOX_API_KEY = os.getenv('THREATFOX_API_KEY', '')  # Set your ThreatFox API key in .env file

# Keyless Feed Ingestion (public exports)
URLHAUS_FEED_ENABLED = True
URLHAUS_FEED_CSV_RECENT_URL = 'https://urlhaus.abuse.ch/downloads/csv_recent/'

THREATFOX_FEED_ENABLED = True
THREATFOX_FEED_CSV_RECENT_URL = 'https://threatfox.abuse.ch/export/csv/recent/'

# Severity Classification Thresholds
SEVERITY_THRESHOLDS = {
    'critical': {'pulse_count': 10, 'reputation_weight': 0.9},
    'high': {'pulse_count': 5, 'reputation_weight': 0.7},
    'medium': {'pulse_count': 2, 'reputation_weight': 0.5},
    'low': {'pulse_count': 1, 'reputation_weight': 0.3}
}

# IOC Type Weights for Severity
IOC_TYPE_WEIGHTS = {
    'hash': 1.0,
    'url': 0.8,
    'domain': 0.7,
    'ip': 0.6
}

# Database Configuration
DATABASE_PATH = CACHE_DIR / 'cache.db'
CACHE_EXPIRY_HOURS = 24  # Cache OTX results for 24 hours

# Reporting Configuration
REPORT_FORMATS = ['json', 'html', 'pdf']
HTML_TEMPLATE_PATH = BASE_DIR / 'pulselens' / 'reporting' / 'templates'

# Flask Dashboard Configuration
DASHBOARD_HOST = '127.0.0.1'
DASHBOARD_PORT = 4000  # Backend API port
DASHBOARD_DEBUG = False

# Frontend Configuration
FRONTEND_HOST = '127.0.0.1'
FRONTEND_PORT = 6000  # Frontend development server port

# Logging Configuration
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Validation Settings
MAX_IOC_LENGTH = 1000
SUPPORTED_IOC_TYPES = ['ip', 'url', 'domain', 'hash', 'email']
HASH_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

# Feed Sources (for future expansion)
FEED_SOURCES = {
    'otx': {
        'enabled': True,
        'api_key_required': True,
        'rate_limit': 60
    }
}
