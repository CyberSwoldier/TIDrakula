#!/usr/bin/env python3
"""
Enhanced Feed Manager Module for Threat Intelligence System
File: modules/feed_manager.py
"""
import feedparser
import requests
import logging
import time
import random
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)

@dataclass
class FeedItem:
    """Data class for feed items"""
    url: str
    title: str
    published_utc: Optional[datetime]
    source: str
    content: str
    summary: str
    tags: List[str]
    author: str
    threat_actor: str = ""
    severity: str = "unknown"

class FeedManager:
    """Enhanced RSS feed manager with robust error handling and content extraction"""
    
    def __init__(self, config: dict = None):
        """Initialize the feed manager with configuration"""
        self.config = config or {}
        self._setup_session()
        self._setup_feeds()
        self._setup_rate_limiting()
        
        # Thread safety
        self._lock = threading.Lock()
        self._processed_urls = set()
        
        # Statistics
        self.stats = {
            'feeds_processed': 0,
            'items_collected': 0,
            'errors': 0,
            'duplicates_skipped': 0
        }
    
    def _setup_session(self):
        """Setup HTTP session with proper headers and timeouts"""
        self.session = requests.Session()
        
        # Rotate user agents to avoid blocking
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'application/rss+xml, application/xml, text/xml, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Set timeouts
        self.timeout = self.config.get('timeout', 30)
        
        # SSL verification
        self.session.verify = True
    
    def _setup_feeds(self):
        """Setup comprehensive list of cybersecurity feeds"""
        self.feeds = self.config.get('feeds', {}).get('rss_feeds', [])
        
        # Add default feeds if none provided
        if not self.feeds:
            self.feeds = [
                # Major cybersecurity news
                "https://thehackernews.com/feeds/posts/default?alt=rss",
                "https://www.bleepingcomputer.com/feed/",
                "https://krebsonsecurity.com/feed/",
                "https://www.darkreading.com/rss.xml",
                "https://cybersecuritynews.com/feed/",
                "https://thecyberexpress.com/feed/",
                "https://www.securityweek.com/feed",
                "https://www.infosecurity-magazine.com/rss/news/",
                
                # Threat intelligence specific
                "https://www.recordedfuture.com/feed",
                "https://intel471.com/feed",
                "https://www.crowdstrike.com/blog/feed/",
                "https://www.fireeye.com/blog/threat-research.xml",
                
                # CERT feeds
                "https://www.us-cert.gov/ncas/current-activity.xml",
                "https://www.cert.org/vulnerability-notes/",
                
                # Vendor security feeds
                "https://msrc.microsoft.com/blog/feed",
                "https://chromereleases.googleblog.com/feeds/posts/default",
                "https://blog.mozilla.org/security/feed/",
                
                # Research and analysis
                "https://www.schneier.com/blog/atom.xml",
                "https://securelist.com/feed/",
                "https://unit42.paloaltonetworks.com/feed/",
                
                # Government and industry
                "https://www.cisa.gov/uscert/ncas/current-activity.xml",
                "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
            ]
    
    def _setup_rate_limiting(self):
        """Setup rate limiting to be respectful to servers"""
        self.rate_limits = {
            'requests_per_minute': self.config.get('rate_limit', {}).get('requests_per_minute', 60),
            'delay_between_requests': self.config.get('rate_limit', {}).get('delay_between_requests', 1),
            'max_concurrent_feeds': self.config.get('rate_limit', {}).get('max_concurrent_feeds', 5)
        }
        
        self.last_request_times = {}
    
    def collect_all_feeds(self, since: datetime, max_items: int = 1000) -> List[FeedItem]:
        """
        Collect articles from all feeds with parallel processing
        
        Args:
            since: Collect articles published after this datetime
            max_items: Maximum number of items to collect
            
        Returns:
            List of FeedItem objects
        """
        logger.info(f"Starting collection from {len(self.feeds)} feeds since {since}")
        
        all_items = []
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.rate_limits['max_concurrent_feeds']) as executor:
            # Submit all feed collection tasks
            future_to_feed = {
                executor.submit(self._collect_feed_safe, feed_url, since): feed_url 
                for feed_url in self.feeds
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_feed):
                feed_url = future_to_feed[future]
                try:
                    items = future.result(timeout=120)  # 2-minute timeout per feed
                    if items:
                        all_items.extend(items)
                        logger.info(f"Collected {len(items)} items from {self._get_domain(feed_url)}")
                    
                    # Stop if we've reached max items
                    if len(all_items) >= max_items:
                        break
                        
                except Exception as e:
                    logger.error(f"Error collecting from {feed_url}: {e}")
                    self.stats['errors'] += 1
        
        # Sort by publication date (newest first)
        all_items.sort(key=lambda x: x.published_utc or datetime.min, reverse=True)
        
        # Limit results
        all_items = all_items[:max_items]
        
        self.stats['items_collected'] = len(all_items)
        logger.info(f"Collection complete: {len(all_items)} total items")
        
        return all_items
    
    def _collect_feed_safe(self, feed_url: str, since: datetime) -> List[FeedItem]:
        """Safely collect from a single feed with error handling"""
        try:
            self.stats['feeds_processed'] += 1
            return self._collect_feed(feed_url, since)
        except Exception as e:
            logger.error(f"Failed to collect from {feed_url}: {e}")
            self.stats['errors'] += 1
            return []
    
    def _collect_feed(self, feed_url: str, since: datetime) -> List[FeedItem]:
        """Collect articles from a single RSS feed"""
        domain = self._get_domain(feed_url)
        
        # Rate limiting
        self._apply_rate_limit(domain)
        
        # Fetch feed
        try:
            response = self.session.get(feed_url, timeout=self.timeout)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP error for {feed_url}: {e}")
            return []
        
        # Parse feed
        try:
            parsed_feed = feedparser.parse(response.content)
        except Exception as e:
            logger.warning(f"Parse error for {feed_url}: {e}")
            return []
        
        if not parsed_feed.entries:
            logger.warning(f"No entries found in {feed_url}")
            return []
        
        items = []
        for entry in parsed_feed.entries:
            try:
                item = self._process_entry(entry, domain, since)
                if item:
                    items.append(item)
            except Exception as e:
                logger.warning(f"Error processing entry from {feed_url}: {e}")
                continue
        
        return items
    
    def _process_entry(self, entry, domain: str, since: datetime) -> Optional[FeedItem]:
        """Process a single feed entry"""
        # Extract URL
        url = entry.get('link', '')
        if not url:
            return None
        
        # Check for duplicates
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        with self._lock:
            if url_hash in self._processed_urls:
                self.stats['duplicates_skipped'] += 1
                return None
            self._processed_urls.add(url_hash)
        
        # Parse publication date
        pub_date = self._parse_date(
            entry.get('published') or 
            entry.get('updated') or 
            entry.get('pubDate')
        )
        
        # Skip if too old
        if pub_date and pub_date < since:
            return None
        
        # Extract basic information
        title = self._clean_text(entry.get('title', ''))
        summary = self._clean_text(entry.get('summary', ''))
        author = self._clean_text(entry.get('author', ''))
        
        # Extract tags
        tags = self._extract_tags(entry)
        
        # Fetch full content
        content = self._fetch_article_content(url, domain)
        
        # Determine severity and threat actor
        severity = self._analyze_severity(title, summary, content)
        threat_actor = self._extract_threat_actor(title, summary, content)
        
        return FeedItem(
            url=url,
            title=title,
            published_utc=pub_date,
            source=domain,
            content=content,
            summary=summary,
            tags=tags,
            author=author,
            threat_actor=threat_actor,
            severity=severity
        )
    
    def _fetch_article_content(self, url: str, domain: str) -> str:
        """Fetch and extract clean article content"""
        try:
            # Rate limiting
            self._apply_rate_limit(domain)
            
            # Fetch article
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove unwanted elements
            for tag in soup(['script', 'style', 'nav', 'header', 'footer', 
                           'sidebar', 'advertisement', 'ads', 'social-share']):
                tag.decompose()
            
            # Try to find main content
            content_selectors = [
                'article',
                '.post-content',
                '.entry-content',
                '.article-content',
                '.content',
                'main',
                '#content',
                '.post-body'
            ]
            
            content_text = ""
            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    content_text = content_elem.get_text(' ', strip=True)
                    break
            
            # Fallback to body text
            if not content_text:
                content_text = soup.get_text(' ', strip=True)
            
            # Clean and limit content
            content_text = self._clean_content(content_text)
            
            return content_text[:15000]  # Limit to 15k characters
            
        except Exception as e:
            logger.debug(f"Could not fetch content from {url}: {e}")
            return ""
    
    def _clean_content(self, text: str) -> str:
        """Clean and normalize content text"""
        if not text:
            return ""
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Remove common boilerplate
        boilerplate_patterns = [
            r'Subscribe to our newsletter.*',
            r'Follow us on.*',
            r'Share this article.*',
            r'Related articles.*',
            r'Copyright.*',
            r'All rights reserved.*'
        ]
        
        for pattern in boilerplate_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text.strip()
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats to datetime"""
        if not date_str:
            return None
        
        try:
            # Try feedparser's built-in parsing first
            parsed = feedparser._parse_date(date_str)
            if parsed:
                return datetime(*parsed[:6])
        except:
            pass
        
        # Try manual parsing with common formats
        date_formats = [
            '%a, %d %b %Y %H:%M:%S %z',  # RFC 2822
            '%Y-%m-%dT%H:%M:%S%z',       # ISO 8601
            '%Y-%m-%d %H:%M:%S',         # Simple format
            '%Y-%m-%d',                  # Date only
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except:
                continue
        
        logger.debug(f"Could not parse date: {date_str}")
        return datetime.now()
    
    def _extract_tags(self, entry) -> List[str]:
        """Extract tags from feed entry"""
        tags = []
        
        # Check different tag fields
        tag_fields = ['tags', 'categories', 'keywords']
        for field in tag_fields:
            if hasattr(entry, field):
                field_data = getattr(entry, field)
                if isinstance(field_data, list):
                    tags.extend([tag.get('term', '') for tag in field_data if isinstance(tag, dict)])
                elif isinstance(field_data, str):
                    tags.append(field_data)
        
        # Clean tags
        tags = [self._clean_text(tag) for tag in tags if tag]
        tags = [tag for tag in tags if len(tag) > 1 and len(tag) < 50]
        
        return list(set(tags))  # Remove duplicates
    
    def _analyze_severity(self, title: str, summary: str, content: str) -> str:
        """Analyze severity based on content keywords"""
        text = f"{title} {summary} {content}".lower()
        
        critical_keywords = [
            'critical', 'zero-day', '0-day', 'ransomware', 'breach', 
            'compromised', 'exploited', 'nation-state', 'apt'
        ]
        
        high_keywords = [
            'vulnerability', 'malware', 'phishing', 'attack', 'threat',
            'exploit', 'backdoor', 'trojan'
        ]
        
        medium_keywords = [
            'security', 'warning', 'alert', 'suspicious', 'incident'
        ]
        
        if any(keyword in text for keyword in critical_keywords):
            return 'critical'
        elif any(keyword in text for keyword in high_keywords):
            return 'high'
        elif any(keyword in text for keyword in medium_keywords):
            return 'medium'
        else:
            return 'low'
    
    def _extract_threat_actor(self, title: str, summary: str, content: str) -> str:
        """Extract threat actor names from content"""
        text = f"{title} {summary} {content}"
        
        # Common threat actor patterns
        apt_pattern = r'\b(APT\s*\d+|APT[\s-][A-Za-z]+)\b'
        group_pattern = r'\b([A-Za-z]+\s+(?:Group|Team|Gang|Bear|Panda|Dragon|Spider))\b'
        
        actors = []
        
        # Find APT groups
        apt_matches = re.finditer(apt_pattern, text, re.IGNORECASE)
        actors.extend([match.group(1) for match in apt_matches])
        
        # Find named groups
        group_matches = re.finditer(group_pattern, text, re.IGNORECASE)
        actors.extend([match.group(1) for match in group_matches])
        
        # Known threat actors
        known_actors = [
            'Lazarus', 'Cozy Bear', 'Fancy Bear', 'Carbanak', 'FIN7', 'FIN8',
            'Sandworm', 'Turla', 'Equation Group', 'Dark Halo', 'SolarWinds',
            'DarkSide', 'REvil', 'Conti', 'LockBit', 'BlackCat', 'AlphV'
        ]
        
        for actor in known_actors:
            if actor.lower() in text.lower():
                actors.append(actor)
        
        # Return most specific match
        if actors:
            return actors[0]
        
        return ""
    
    def _apply_rate_limit(self, domain: str):
        """Apply rate limiting for domain"""
        current_time = time.time()
        last_request = self.last_request_times.get(domain, 0)
        
        time_since_last = current_time - last_request
        min_interval = self.rate_limits['delay_between_requests']
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_times[domain] = time.time()
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc
        except:
            return "unknown"
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        if not text:
            return ""
        
        # Remove HTML entities
        import html
        text = html.unescape(text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text.strip())
        
        return text
    
    def get_statistics(self) -> Dict[str, int]:
        """Get collection statistics"""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset collection statistics"""
        self.stats = {
            'feeds_processed': 0,
            'items_collected': 0,
            'errors': 0,
            'duplicates_skipped': 0
        }
    
    def validate_feeds(self) -> Dict[str, bool]:
        """Validate all configured feeds"""
        results = {}
        
        for feed_url in self.feeds:
            try:
                response = self.session.get(feed_url, timeout=10)
                results[feed_url] = response.status_code == 200
            except:
                results[feed_url] = False
        
        return results
    
    def __del__(self):
        """Cleanup session on deletion"""
        if hasattr(self, 'session'):
            self.session.close()
