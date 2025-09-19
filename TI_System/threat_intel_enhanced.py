#!/usr/bin/env python3
"""
Enhanced MITRE TTP Web Tracker with OTX integration and SQLite storage
"""
from __future__ import annotations
import re
import requests
import feedparser
import pandas as pd
import sqlite3
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparser
import tldextract
from typing import List, Dict, Optional, Set, Tuple
import warnings
import unicodedata
import ipaddress
import logging

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Import modules
from modules.country_detector import CountryDetector
from modules.ttp_classifier import TTPClassifier
from modules.feed_manager import FeedManager
from modules.otx_client import OTXClient
from modules.database_manager import DatabaseManager
from modules.report_generator import ReportGenerator

class ThreatIntelligenceEngine:
    """Main engine for threat intelligence collection and processing"""
    
    def __init__(self, otx_api_key: Optional[str] = None, db_path: str = "threat_intel.db"):
        """
        Initialize the threat intelligence engine
        
        Args:
            otx_api_key: Optional OTX API key for AlienVault integration
            db_path: Path to SQLite database
        """
        self.db_manager = DatabaseManager(db_path)
        self.country_detector = CountryDetector()
        self.ttp_classifier = TTPClassifier()
        self.feed_manager = FeedManager()
        self.otx_client = OTXClient(otx_api_key) if otx_api_key else None
        self.report_generator = ReportGenerator()
        
        # Initialize database
        self.db_manager.initialize_database()
    
    def run_collection(self, days_back: int = 7):
        """
        Run the complete collection process
        
        Args:
            days_back: Number of days to look back for articles
        """
        since = datetime.now() - timedelta(days=days_back)
        logging.info(f"Starting collection for last {days_back} days")
        
        # Collect from RSS feeds
        feed_items = self.feed_manager.collect_all_feeds(since)
        logging.info(f"Collected {len(feed_items)} items from RSS feeds")
        
        # Collect from OTX if available
        otx_items = []
        if self.otx_client:
            otx_items = self.otx_client.collect_pulses(since)
            logging.info(f"Collected {len(otx_items)} items from OTX")
        
        # Process and store all items
        all_items = feed_items + otx_items
        self._process_and_store_items(all_items)
        
        # Generate reports
        self._generate_reports()
    
    def _process_and_store_items(self, items: List[Dict]):
        """Process items and store in database"""
        for item in items:
            # Classify TTPs
            ttps = self.ttp_classifier.classify(item.get('content', ''))
            
            # Detect countries
            countries = self.country_detector.detect(
                item.get('content', ''),
                item.get('url', '')
            )
            
            # Determine if human-targeted
            is_human_targeted = self._is_human_targeted(ttps)
            
            # Store in database
            self.db_manager.insert_article(
                url=item.get('url', ''),
                title=item.get('title', ''),
                published_date=item.get('published_utc'),
                source=item.get('source', ''),
                ttps=ttps,
                countries=countries,
                threat_actor=item.get('threat_actor', ''),
                is_human_targeted=is_human_targeted,
                content=item.get('content', '')[:5000]  # Store first 5000 chars
            )
    
    def _is_human_targeted(self, ttps: List[str]) -> bool:
        """Determine if attack is human-targeted based on TTPs"""
        human_indicators = [
            'phishing', 'spearphishing', 'social engineering',
            'pretexting', 'baiting', 'impersonation', 'fraud',
            'scam', 'vishing', 'smishing', 'whaling'
        ]
        
        ttps_lower = ' '.join(ttps).lower()
        return any(indicator in ttps_lower for indicator in human_indicators)
    
    def _generate_reports(self):
        """Generate Excel and other format reports"""
        # Get data from database
        human_df = self.db_manager.get_human_targeted_articles()
        general_df = self.db_manager.get_general_articles()
        
        # Generate Excel report
        output_file = f"ttp_reports_{datetime.now().strftime('%d%m%y')}.xlsx"
        self.report_generator.generate_excel_report(human_df, general_df, output_file)
        logging.info(f"Generated report: {output_file}")
    
    def query_database(self, query_params: Dict) -> pd.DataFrame:
        """
        Query the database with specific parameters
        
        Args:
            query_params: Dictionary with query parameters
        
        Returns:
            DataFrame with query results
        """
        return self.db_manager.query_articles(**query_params)


# ===========================
# Module: Country Detector
# ===========================
"""
File: modules/country_detector.py
"""
import re
import pycountry
import tldextract
from typing import List, Optional
import unicodedata

class CountryDetector:
    """Detects countries mentioned in text and URLs"""
    
    def __init__(self):
        self._setup_country_mappings()
        self._setup_geoip()
    
    def _setup_country_mappings(self):
        """Setup country name mappings and aliases"""
        self.aliases = {
            "usa": "United States",
            "us": "United States",
            "uk": "United Kingdom",
            "uae": "United Arab Emirates",
            # Add more aliases as needed
        }
        
        self.native_names = {
            "sverige": "Sweden",
            "deutschland": "Germany",
            "中国": "China",
            # Add more native names
        }
    
    def _setup_geoip(self):
        """Setup GeoIP resolver if available"""
        try:
            import geoip2.database
            self.geoip = geoip2.database.Reader("GeoLite2-Country.mmdb")
        except:
            self.geoip = None
    
    def detect(self, text: str, url: Optional[str] = None) -> List[str]:
        """
        Detect countries in text and URL
        
        Args:
            text: Text to analyze
            url: Optional URL to check TLD
        
        Returns:
            List of detected country names
        """
        countries = set()
        
        # Check text for country mentions
        countries.update(self._detect_in_text(text))
        
        # Check URL TLD
        if url:
            tld_country = self._detect_from_tld(url)
            if tld_country:
                countries.add(tld_country)
        
        # Check for IP addresses and resolve
        if self.geoip:
            countries.update(self._detect_from_ips(text))
        
        return list(countries)
    
    def _detect_in_text(self, text: str) -> Set[str]:
        """Detect countries mentioned in text"""
        countries = set()
        text_lower = text.lower()
        
        # Check aliases
        for alias, country in self.aliases.items():
            if re.search(r'\b' + re.escape(alias) + r'\b', text_lower):
                countries.add(country)
        
        # Check native names
        for native, country in self.native_names.items():
            if native in text:
                countries.add(country)
        
        # Check pycountry database
        try:
            for country in pycountry.countries:
                if country.name.lower() in text_lower:
                    countries.add(country.name)
        except:
            pass
        
        return countries
    
    def _detect_from_tld(self, url: str) -> Optional[str]:
        """Detect country from URL TLD"""
        try:
            ext = tldextract.extract(url)
            suffix = ext.suffix.split('.')[-1]
            if len(suffix) == 2:
                country = pycountry.countries.get(alpha_2=suffix.upper())
                if country:
                    return country.name
        except:
            pass
        return None
    
    def _detect_from_ips(self, text: str) -> Set[str]:
        """Detect countries from IP addresses in text"""
        countries = set()
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for ip in re.findall(ip_pattern, text):
            try:
                response = self.geoip.country(ip)
                countries.add(response.country.name)
            except:
                continue
        
        return countries


# ===========================
# Module: TTP Classifier
# ===========================
"""
File: modules/ttp_classifier.py
"""
import re
from typing import List, Dict

class TTPClassifier:
    """Classifies text into MITRE ATT&CK TTPs"""
    
    def __init__(self):
        self._setup_mappings()
    
    def _setup_mappings(self):
        """Setup TTP pattern mappings"""
        self.mappings = {
            # Social Engineering
            r"\bsocial\s*engineering\b": ["Social Engineering (T1566 / TA0001)"],
            r"\bphishing\b": ["Phishing (T1566.002)"],
            r"\bspear\s*phish": ["Spearphishing (T1566.001)"],
            r"\bransomware\b": ["Data Encrypted for Impact (T1486)"],
            r"\bmalware\b": ["Malware (TA0002/TA0003)"],
            r"\bexploit\b": ["Exploitation (T1203)"],
            r"\bzero[- ]?day\b": ["Zero-Day Exploit (T1203)"],
            r"\bbrute\s*force\b": ["Brute Force (T1110)"],
            r"\bdata\s*breach\b": ["Data Theft (T1005)"],
            r"\bDDoS\b|denial.of.service": ["Network Denial of Service (T1498)"],
            # Add more patterns
        }
    
    def classify(self, text: str) -> List[str]:
        """
        Classify text into TTPs
        
        Args:
            text: Text to classify
        
        Returns:
            List of detected TTPs
        """
        ttps = set()
        
        for pattern, ttp_list in self.mappings.items():
            if re.search(pattern, text, re.IGNORECASE):
                ttps.update(ttp_list)
        
        return sorted(list(ttps))


# ===========================
# Module: OTX Client
# ===========================
"""
File: modules/otx_client.py
"""
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

class OTXClient:
    """Client for AlienVault OTX API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Content-Type": "application/json"
        }
    
    def collect_pulses(self, since: datetime, limit: int = 100) -> List[Dict]:
        """
        Collect pulses from OTX
        
        Args:
            since: Collect pulses since this date
            limit: Maximum number of pulses to collect
        
        Returns:
            List of processed pulse items
        """
        items = []
        
        try:
            # Get subscribed pulses
            endpoint = f"{self.base_url}/pulses/subscribed"
            params = {
                "limit": limit,
                "modified_since": since.isoformat()
            }
            
            response = requests.get(endpoint, headers=self.headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            pulses = data.get("results", [])
            
            for pulse in pulses:
                items.append(self._process_pulse(pulse))
            
            logging.info(f"Collected {len(items)} pulses from OTX")
            
        except Exception as e:
            logging.error(f"Error collecting OTX pulses: {e}")
        
        return items
    
    def _process_pulse(self, pulse: Dict) -> Dict:
        """Process OTX pulse into standard format"""
        # Extract indicators
        indicators = pulse.get("indicators", [])
        countries = set()
        ttps = []
        
        # Extract countries from indicators
        for indicator in indicators:
            if indicator.get("type") == "country":
                countries.add(indicator.get("indicator", ""))
        
        # Extract MITRE ATT&CK references
        for tag in pulse.get("tags", []):
            if "T" in tag and tag[1:].isdigit():  # Simple MITRE ID detection
                ttps.append(f"MITRE {tag}")
        
        return {
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            "title": pulse.get("name", ""),
            "published_utc": datetime.fromisoformat(pulse.get("created", datetime.now().isoformat())),
            "source": "OTX AlienVault",
            "content": pulse.get("description", ""),
            "threat_actor": pulse.get("author_name", ""),
            "countries": list(countries),
            "ttps": ttps
        }


# ===========================
# Module: Database Manager
# ===========================
"""
File: modules/database_manager.py
"""
import sqlite3
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional

class DatabaseManager:
    """Manages SQLite database for threat intelligence"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def initialize_database(self):
        """Create database tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create articles table
        self.cursor.execute('''
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
        
        # Create TTPs table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER,
                ttp TEXT,
                FOREIGN KEY (article_id) REFERENCES articles (id)
            )
        ''')
        
        # Create countries table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS countries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER,
                country TEXT,
                FOREIGN KEY (article_id) REFERENCES articles (id)
            )
        ''')
        
        self.conn.commit()
    
    def insert_article(self, url: str, title: str, published_date: datetime,
                      source: str, ttps: List[str], countries: List[str],
                      threat_actor: str, is_human_targeted: bool, content: str):
        """Insert article with related TTPs and countries"""
        try:
            # Insert article
            self.cursor.execute('''
                INSERT OR IGNORE INTO articles 
                (url, title, published_date, source, threat_actor, is_human_targeted, content)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url, title, published_date, source, threat_actor, is_human_targeted, content))
            
            # Get article ID
            article_id = self.cursor.lastrowid
            if article_id == 0:  # Article already exists
                self.cursor.execute('SELECT id FROM articles WHERE url = ?', (url,))
                article_id = self.cursor.fetchone()[0]
            
            # Insert TTPs
            for ttp in ttps:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO ttps (article_id, ttp)
                    VALUES (?, ?)
                ''', (article_id, ttp))
            
            # Insert countries
            for country in countries:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO countries (article_id, country)
                    VALUES (?, ?)
                ''', (article_id, country))
            
            self.conn.commit()
            
        except Exception as e:
            logging.error(f"Error inserting article: {e}")
            self.conn.rollback()
    
    def get_human_targeted_articles(self) -> pd.DataFrame:
        """Get all human-targeted articles"""
        query = '''
            SELECT a.*, 
                   GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                   GROUP_CONCAT(DISTINCT c.country) as countries
            FROM articles a
            LEFT JOIN ttps t ON a.id = t.article_id
            LEFT JOIN countries c ON a.id = c.article_id
            WHERE a.is_human_targeted = 1
            GROUP BY a.id
            ORDER BY a.published_date DESC
        '''
        
        return pd.read_sql_query(query, self.conn)
    
    def get_general_articles(self) -> pd.DataFrame:
        """Get all general (non-human-targeted) articles"""
        query = '''
            SELECT a.*, 
                   GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                   GROUP_CONCAT(DISTINCT c.country) as countries
            FROM articles a
            LEFT JOIN ttps t ON a.id = t.article_id
            LEFT JOIN countries c ON a.id = c.article_id
            WHERE a.is_human_targeted = 0
            GROUP BY a.id
            ORDER BY a.published_date DESC
        '''
        
        return pd.read_sql_query(query, self.conn)
    
    def query_articles(self, start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       country: Optional[str] = None,
                       ttp: Optional[str] = None,
                       is_human_targeted: Optional[bool] = None) -> pd.DataFrame:
        """Query articles with filters"""
        query = '''
            SELECT DISTINCT a.*, 
                   GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                   GROUP_CONCAT(DISTINCT c.country) as countries
            FROM articles a
            LEFT JOIN ttps t ON a.id = t.article_id
            LEFT JOIN countries c ON a.id = c.article_id
            WHERE 1=1
        '''
        
        params = []
        
        if start_date:
            query += ' AND a.published_date >= ?'
            params.append(start_date)
        
        if end_date:
            query += ' AND a.published_date <= ?'
            params.append(end_date)
        
        if country:
            query += ' AND c.country = ?'
            params.append(country)
        
        if ttp:
            query += ' AND t.ttp LIKE ?'
            params.append(f'%{ttp}%')
        
        if is_human_targeted is not None:
            query += ' AND a.is_human_targeted = ?'
            params.append(is_human_targeted)
        
        query += ' GROUP BY a.id ORDER BY a.published_date DESC'
        
        return pd.read_sql_query(query, self.conn, params=params)
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# ===========================
# Module: Feed Manager
# ===========================
"""
File: modules/feed_manager.py
"""
import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import List, Dict
import logging

class FeedManager:
    """Manages RSS feed collection"""
    
    def __init__(self):
        self.feeds = [
            "https://thecyberexpress.com/feed/",
            "https://cybersecuritynews.com/feed/",
            "https://thehackernews.com/feeds/posts/default?alt=rss",
            # Add more feeds
        ]
        self.headers = {"User-Agent": "ThreatIntel/2.0"}
        self.timeout = 20
    
    def collect_all_feeds(self, since: datetime) -> List[Dict]:
        """Collect articles from all feeds"""
        all_items = []
        
        for feed_url in self.feeds:
            try:
                items = self._collect_feed(feed_url, since)
                all_items.extend(items)
                logging.info(f"Collected {len(items)} items from {feed_url}")
            except Exception as e:
                logging.error(f"Error collecting feed {feed_url}: {e}")
        
        return all_items
    
    def _collect_feed(self, feed_url: str, since: datetime) -> List[Dict]:
        """Collect articles from a single feed"""
        items = []
        parsed = feedparser.parse(feed_url)
        
        for entry in parsed.entries:
            # Parse date
            pub_date = self._parse_date(entry.get("published") or entry.get("updated"))
            
            if not pub_date or pub_date < since:
                continue
            
            # Extract content
            content = self._fetch_article_content(entry.get("link"))
            
            items.append({
                "url": entry.get("link", ""),
                "title": entry.get("title", ""),
                "published_utc": pub_date,
                "source": self._extract_domain(entry.get("link", "")),
                "content": content,
                "threat_actor": ""  # To be extracted from content
            })
        
        return items
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime"""
        try:
            from dateutil import parser
            return parser.parse(date_str)
        except:
            return None
    
    def _fetch_article_content(self, url: str) -> str:
        """Fetch full article content"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Remove unwanted elements
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            
            # Extract text
            text = soup.get_text(" ", strip=True)
            return text[:10000]  # Limit to 10k chars
            
        except Exception as e:
            logging.warning(f"Could not fetch content from {url}: {e}")
            return ""
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            import tldextract
            ext = tldextract.extract(url)
            return ext.domain
        except:
            return ""


# ===========================
# Module: Report Generator
# ===========================
"""
File: modules/report_generator.py
"""
import pandas as pd
from openpyxl.styles import Alignment
from openpyxl.utils import get_column_letter

class ReportGenerator:
    """Generates reports in various formats"""
    
    def generate_excel_report(self, human_df: pd.DataFrame, general_df: pd.DataFrame, output_file: str):
        """Generate Excel report with formatted sheets"""
        # Process dataframes
        human_df = self._process_dataframe(human_df)
        general_df = self._process_dataframe(general_df)
        
        # Write to Excel
        with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
            human_df.to_excel(writer, sheet_name="Human_Attacks", index=False)
            general_df.to_excel(writer, sheet_name="General_Attacks", index=False)
            
            # Format sheets
            for sheet_name in writer.sheets:
                sheet = writer.sheets[sheet_name]
                self._format_sheet(sheet)
        
        logging.info(f"Generated Excel report: {output_file}")
    
    def _process_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process dataframe for export"""
        # Split TTPs and countries into separate columns
        if 'ttps' in df.columns:
            ttp_split = df['ttps'].str.split(',', expand=True)
            for i, col in enumerate(ttp_split.columns):
                df[f'ttp_desc_{i+1}'] = ttp_split[col].str.strip()
            df = df.drop('ttps', axis=1)
        
        if 'countries' in df.columns:
            country_split = df['countries'].str.split(',', expand=True)
            for i, col in enumerate(country_split.columns):
                df[f'country_{i+1}'] = country_split[col].str.strip()
            df = df.drop('countries', axis=1)
        
        return df
    
    def _format_sheet(self, sheet):
        """Format Excel sheet"""
        for col in sheet.columns:
            max_length = max(len(str(cell.value)) if cell.value else 0 for cell in col)
            adjusted_width = min(max_length + 2, 80)
            sheet.column_dimensions[get_column_letter(col[0].column)].width = adjusted_width
            
            for cell in col:
                cell.alignment = Alignment(wrap_text=True, vertical="top")


# ===========================
# Main execution
# ===========================
if __name__ == "__main__":
    # Example usage
    import os
    
    # Get OTX API key from environment or config
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    
    # Initialize engine
    engine = ThreatIntelligenceEngine(otx_api_key=OTX_API_KEY)
    
    # Run collection
    engine.run_collection(days_back=7)
    
    print("Threat intelligence collection complete!")