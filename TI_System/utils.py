# ===========================
# File: utils.py
# ===========================
"""
Utility functions for the Threat Intelligence System
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd

def hash_url(url: str) -> str:
    """Generate hash for URL to avoid duplicates"""
    return hashlib.sha256(url.encode()).hexdigest()[:16]

def parse_date_range(date_str: str) -> tuple:
    """
    Parse date range string
    Examples: 'last_week', 'last_month', '2024-01-01:2024-01-31'
    """
    today = datetime.now()
    
    if date_str == 'last_week':
        start = today - timedelta(days=7)
        end = today
    elif date_str == 'last_month':
        start = today - timedelta(days=30)
        end = today
    elif ':' in date_str:
        parts = date_str.split(':')
        start = datetime.strptime(parts[0], '%Y-%m-%d')
        end = datetime.strptime(parts[1], '%Y-%m-%d')
    else:
        raise ValueError(f"Invalid date range: {date_str}")
    
    return start, end

def export_to_json(data: pd.DataFrame, filename: str):
    """Export DataFrame to JSON"""
    data.to_json(filename, orient='records', date_format='iso', indent=2)

def merge_duplicate_articles(df: pd.DataFrame) -> pd.DataFrame:
    """Merge duplicate articles based on URL"""
    # Group by URL and aggregate
    aggregation = {
        'title': 'first',
        'published_date': 'first',
        'source': 'first',
        'threat_actor': 'first',
        'is_human_targeted': 'first',
        'content': 'first'
    }
    
    # For list columns, combine unique values
    if 'ttps' in df.columns:
        aggregation['ttps'] = lambda x: list(set(','.join(x).split(',')))
    
    if 'countries' in df.columns:
        aggregation['countries'] = lambda x: list(set(','.join(x).split(',')))
    
    return df.groupby('url').agg(aggregation).reset_index()

def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration file"""
    required_keys = ['database', 'otx', 'github', 'collection']
    
    for key in required_keys:
        if key not in config:
            logging.error(f"Missing required config key: {key}")
            return False
    
    return True

def create_backup(db_path: str, backup_dir: str = 'backups'):
    """Create database backup"""
    import shutil
    from pathlib import Path
    
    backup_path = Path(backup_dir)
    backup_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = backup_path / f"threat_intel_{timestamp}.db"
    
    shutil.copy2(db_path, backup_file)
    logging.info(f"Backup created: {backup_file}")
    
    # Keep only last 5 backups
    backups = sorted(backup_path.glob("threat_intel_*.db"))
    if len(backups) > 5:
        for old_backup in backups[:-5]:
            old_backup.unlink()
            logging.info(f"Removed old backup: {old_backup}")


# ===========================
# Main entry points
# ===========================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Threat Intelligence System")
    parser.add_argument('command', choices=['setup', 'collect', 'schedule'],
                       help='Command to run')
    
    args = parser.parse_args()
    
    if args.command == 'setup':
        setup = Setup()
        setup.run()
    elif args.command == 'collect':
        from run_collection import main
        main()
    elif args.command == 'schedule':
        scheduler = ThreatIntelScheduler()
        scheduler.start()