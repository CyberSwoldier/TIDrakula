# ===========================
# File: scheduler.py
# ===========================
"""
Scheduler for automated threat intelligence collection
"""
import schedule
import time
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime

class ThreatIntelScheduler:
    """Scheduler for automated collection"""
    
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for scheduler"""
        log_file = f'scheduler_{datetime.now().strftime("%Y%m%d")}.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def run_collection(self):
        """Run the collection process"""
        self.logger.info("Starting scheduled collection...")
        
        try:
            # Run collection script
            result = subprocess.run(
                [sys.executable, "run_collection.py"],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.logger.info("Collection completed successfully")
            self.logger.debug(result.stdout)
            
            # Run dashboard update
            self.update_dashboard()
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Collection failed: {e}")
            self.logger.error(e.stderr)
    
    def update_dashboard(self):
        """Update dashboard data"""
        self.logger.info("Updating dashboard data...")
        # Dashboard will automatically pick up new data from database
    
    def start(self):
        """Start the scheduler"""
        # Schedule collection every Friday at 00:00
        schedule.every().friday.at("00:00").do(self.run_collection)
        
        # Optional: Run daily for testing
        # schedule.every().day.at("12:00").do(self.run_collection)
        
        self.logger.info("Scheduler started. Waiting for scheduled tasks...")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
