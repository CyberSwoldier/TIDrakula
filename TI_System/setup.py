#!/usr/bin/env python3
"""
Setup script for initializing the Threat Intelligence System
File: setup.py
"""
import os
import sys
import yaml
import sqlite3
import logging
from pathlib import Path
import subprocess

class Setup:
    """Setup and initialization for the Threat Intelligence System"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.config_file = self.base_dir / "config.yaml"
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('setup.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def run(self):
        """Run complete setup process"""
        self.logger.info("Starting Threat Intelligence System setup...")
        
        # Check Python version
        self._check_python_version()
        
        # Create directory structure
        self._create_directories()
        
        # Install dependencies
        self._install_dependencies()
        
        # Setup configuration
        self._setup_configuration()
        
        # Initialize database
        self._initialize_database()
        
        # Download GeoIP database
        self._setup_geoip()
        
        # Download spaCy model (optional)
        self._setup_spacy()
        
        self.logger.info("Setup complete! Run 'python main.py' to start the dashboard.")
    
    def _check_python_version(self):
        """Check if Python version is compatible"""
        if sys.version_info < (3, 8):
            self.logger.error("Python 3.8 or higher is required")
            sys.exit(1)
        self.logger.info(f"Python version: {sys.version}")
    
    def _create_directories(self):
        """Create necessary directory structure"""
        directories = [
            "modules",
            "reports",
            "backups",
            "logs",
            "data"
        ]
        
        for directory in directories:
            path = self.base_dir / directory
            path.mkdir(exist_ok=True)
            self.logger.info(f"Created directory: {directory}")
    
    def _install_dependencies(self):
        """Install required Python packages"""
        self.logger.info("Installing dependencies...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ])
            self.logger.info("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            sys.exit(1)
    
    def _setup_configuration(self):
        """Setup configuration file"""
        if not self.config_file.exists():
            self.logger.info("Creating default configuration file...")
            default_config = self._get_default_config()
            
            with open(self.config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            self.logger.info("Configuration file created: config.yaml")
            self.logger.info("Please update config.yaml with your API keys")
        else:
            self.logger.info("Configuration file already exists")
    
    def _get_default_config(self):
        """Get default configuration"""
        return {
            'database': {
                'path': 'threat_intel.db',
                'backup_enabled': True,
                'backup_path': 'backups/'
            },
            'otx': {
                'api_key': 'YOUR_OTX_API_KEY_HERE',
                'enabled': False,
                'pulse_limit': 100
            },
            'github': {
                'user': 'CyberSwoldier',
                'repo': 'Threat-Intelligence-NIMBLR',
                'branch': 'main',
                'reports_folder': 'reports'
            },
            'collection': {
                'days_back': 7,
                'auto_run': False
            }
        }
    
    def _initialize_database(self):
        """Initialize SQLite database"""
        self.logger.info("Initializing database...")
        
        db_path = self.base_dir / "threat_intel.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                title TEXT,
                published_date DATETIME,
                source TEXT,
                threat_actor TEXT,
                is_human_targeted BOOLEAN,
                content TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER,
                ttp TEXT,
                FOREIGN KEY (article_id) REFERENCES articles (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS countries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER,
                country TEXT,
                FOREIGN KEY (article_id) REFERENCES articles (id)
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_articles_date ON articles(published_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ttps_article ON ttps(article_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_countries_article ON countries(article_id)')
        
        conn.commit()
        conn.close()
        
        self.logger.info("Database initialized successfully")
    
    def _setup_geoip(self):
        """Download and setup GeoIP database"""
        self.logger.info("Setting up GeoIP database...")
        
        # Note: You need to register at MaxMind to get the database
        # https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        
        geoip_path = self.base_dir / "GeoLite2-Country.mmdb"
        if not geoip_path.exists():
            self.logger.warning(
                "GeoIP database not found. Please download GeoLite2-Country.mmdb "
                "from MaxMind and place it in the project directory."
            )
        else:
            self.logger.info("GeoIP database found")
    
    def _setup_spacy(self):
        """Setup spaCy language model"""
        self.logger.info("Setting up spaCy language model...")
        try:
            import spacy
            try:
                spacy.load("en_core_web_sm")
                self.logger.info("spaCy model already installed")
            except:
                subprocess.check_call([
                    sys.executable, "-m", "spacy", "download", "en_core_web_sm"
                ])
                self.logger.info("spaCy model downloaded successfully")
        except ImportError:
            self.logger.warning("spaCy not installed, skipping language model setup")