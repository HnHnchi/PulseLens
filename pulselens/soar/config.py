"""
Secure configuration management for SOAR components.
Handles environment variables and secrets.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

class SOARConfig:
    """Secure configuration for SOAR components."""
    
    # Required environment variables
    CHRONICLE_API_KEY = os.getenv("CHRONICLE_API_KEY")
    CHRONICLE_INSTANCE = os.getenv("CHRONICLE_INSTANCE")
    SSH_USERNAME = os.getenv("SOAR_SSH_USER", "soar")
    
    @classmethod
    def validate(cls):
        """Validate that all required environment variables are set."""
        required = {
            'CHRONICLE_API_KEY': cls.CHRONICLE_API_KEY,
            'CHRONICLE_INSTANCE': cls.CHRONICLE_INSTANCE
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
