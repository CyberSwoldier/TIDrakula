# ===========================
# File: run_collection.py
# ===========================
"""
Script to run threat intelligence collection
"""
import os
import sys
import yaml
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from threat_intel_enhanced import ThreatIntelligenceEngine

def load_config():
    """Load configuration from config.yaml"""
    config_file = Path(__file__).parent / "config.yaml"
    
    if not config_file.exists():
        logging.error("Configuration file not found. Run setup.py first.")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def main():
    """Run threat intelligence collection"""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'collection_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.StreamHandler()
        ]
    )
    
    # Load configuration
    config = load_config()
    
    # Initialize engine
    otx_api_key = config['otx'].get('api_key')
    if otx_api_key == 'YOUR_OTX_API_KEY_HERE':
        otx_api_key = os.getenv('OTX_API_KEY')
        if not otx_api_key:
            logging.warning("OTX API key not configured")
    
    db_path = config['database']['path']
    
    engine = ThreatIntelligenceEngine(
        otx_api_key=otx_api_key,
        db_path=db_path
    )
    
    # Run collection
    days_back = config['collection'].get('days_back', 7)
    logging.info(f"Starting collection for last {days_back} days")
    
    engine.run_collection(days_back=days_back)
    
    logging.info("Collection complete!")
