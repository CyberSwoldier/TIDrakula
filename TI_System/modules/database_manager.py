#!/usr/bin/env python3
"""
Enhanced Database Manager Module for Threat Intelligence System
File: modules/database_manager.py
"""
import sqlite3
import json
import pandas as pd
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
import threading
from pathlib import Path
import os

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Enhanced database manager with connection pooling and error handling"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.connection_lock = threading.Lock()
        self._ensure_directory_exists()
        self.initialize_database()
    
    def _ensure_directory_exists(self):
        """Ensure database directory exists"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get a database connection with proper error handling"""
        try:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row  # Enable dict-like row access
            return conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def initialize_database(self):
        """Create database tables if they don't exist"""
        with self.connection_lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                # Create articles table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS articles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        title TEXT,
                        published_date DATETIME,
                        source TEXT,
                        threat_actor TEXT,
                        is_human_targeted BOOLEAN DEFAULT 0,
                        content TEXT,
                        severity TEXT DEFAULT 'unknown',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create TTPs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ttps (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        article_id INTEGER,
                        ttp TEXT NOT NULL,
                        confidence REAL DEFAULT 1.0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (article_id) REFERENCES articles (id) ON DELETE CASCADE
                    )
                ''')
                
                # Create countries table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS countries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        article_id INTEGER,
                        country TEXT NOT NULL,
                        confidence REAL DEFAULT 1.0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (article_id) REFERENCES articles (id) ON DELETE CASCADE
                    )
                ''')
                
                # Create indexes for better performance
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_articles_date ON articles(published_date)',
                    'CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source)',
                    'CREATE INDEX IF NOT EXISTS idx_articles_human_targeted ON articles(is_human_targeted)',
                    'CREATE INDEX IF NOT EXISTS idx_ttps_article ON ttps(article_id)',
                    'CREATE INDEX IF NOT EXISTS idx_ttps_ttp ON ttps(ttp)',
                    'CREATE INDEX IF NOT EXISTS idx_countries_article ON countries(article_id)',
                    'CREATE INDEX IF NOT EXISTS idx_countries_country ON countries(country)',
                    'CREATE INDEX IF NOT EXISTS idx_articles_url ON articles(url)'
                ]
                
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                conn.commit()
                logger.info("Database initialized successfully")
                
            except Exception as e:
                logger.error(f"Database initialization error: {e}")
                raise
            finally:
                if 'conn' in locals():
                    conn.close()
    
    def insert_article(self, url: str, title: str, published_date: datetime,
                      source: str, ttps: List[str], countries: List[str],
                      threat_actor: str = "", is_human_targeted: bool = False,
                      content: str = "", severity: str = "unknown") -> Optional[int]:
        """
        Insert article with related TTPs and countries
        
        Returns:
            Article ID if successful, None otherwise
        """
        with self.connection_lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                # Insert or update article
                cursor.execute('''
                    INSERT OR REPLACE INTO articles 
                    (url, title, published_date, source, threat_actor, is_human_targeted, 
                     content, severity, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (url, title, published_date, source, threat_actor, 
                     is_human_targeted, content, severity))
                
                article_id = cursor.lastrowid
                
                # If this was an update, get the existing article ID
                if article_id == 0:
                    cursor.execute('SELECT id FROM articles WHERE url = ?', (url,))
                    result = cursor.fetchone()
                    if result:
                        article_id = result[0]
                
                if not article_id:
                    logger.error("Failed to get article ID")
                    return None
                
                # Clear existing TTPs and countries for this article
                cursor.execute('DELETE FROM ttps WHERE article_id = ?', (article_id,))
                cursor.execute('DELETE FROM countries WHERE article_id = ?', (article_id,))
                
                # Insert TTPs
                for ttp in ttps:
                    if ttp and ttp.strip():
                        cursor.execute('''
                            INSERT INTO ttps (article_id, ttp)
                            VALUES (?, ?)
                        ''', (article_id, ttp.strip()))
                
                # Insert countries
                for country in countries:
                    if country and country.strip():
                        cursor.execute('''
                            INSERT INTO countries (article_id, country)
                            VALUES (?, ?)
                        ''', (article_id, country.strip()))
                
                conn.commit()
                return article_id
                
            except Exception as e:
                logger.error(f"Error inserting article: {e}")
                if 'conn' in locals():
                    conn.rollback()
                return None
            finally:
                if 'conn' in locals():
                    conn.close()
    
    def get_human_targeted_articles(self, limit: int = 1000) -> pd.DataFrame:
        """Get all human-targeted articles with TTPs and countries"""
        try:
            query = '''
                SELECT a.*, 
                       GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                       GROUP_CONCAT(DISTINCT c.country) as countries,
                       COUNT(DISTINCT t.id) as ttp_count,
                       COUNT(DISTINCT c.id) as country_count
                FROM articles a
                LEFT JOIN ttps t ON a.id = t.article_id
                LEFT JOIN countries c ON a.id = c.article_id
                WHERE a.is_human_targeted = 1
                GROUP BY a.id
                ORDER BY a.published_date DESC
                LIMIT ?
            '''
            
            conn = self.get_connection()
            df = pd.read_sql_query(query, conn, params=(limit,))
            conn.close()
            
            # Convert published_date to datetime
            if 'published_date' in df.columns:
                df['published_date'] = pd.to_datetime(df['published_date'])
            
            return df
            
        except Exception as e:
            logger.error(f"Error getting human-targeted articles: {e}")
            return pd.DataFrame()
    
    def get_general_articles(self, limit: int = 1000) -> pd.DataFrame:
        """Get all general (non-human-targeted) articles with TTPs and countries"""
        try:
            query = '''
                SELECT a.*, 
                       GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                       GROUP_CONCAT(DISTINCT c.country) as countries,
                       COUNT(DISTINCT t.id) as ttp_count,
                       COUNT(DISTINCT c.id) as country_count
                FROM articles a
                LEFT JOIN ttps t ON a.id = t.article_id
                LEFT JOIN countries c ON a.id = c.article_id
                WHERE a.is_human_targeted = 0 OR a.is_human_targeted IS NULL
                GROUP BY a.id
                ORDER BY a.published_date DESC
                LIMIT ?
            '''
            
            conn = self.get_connection()
            df = pd.read_sql_query(query, conn, params=(limit,))
            conn.close()
            
            # Convert published_date to datetime
            if 'published_date' in df.columns:
                df['published_date'] = pd.to_datetime(df['published_date'])
            
            return df
            
        except Exception as e:
            logger.error(f"Error getting general articles: {e}")
            return pd.DataFrame()
    
    def query_articles(self, start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       country: Optional[str] = None,
                       ttp: Optional[str] = None,
                       is_human_targeted: Optional[bool] = None,
                       source: Optional[str] = None,
                       threat_actor: Optional[str] = None,
                       severity: Optional[str] = None,
                       limit: int = 1000) -> pd.DataFrame:
        """Query articles with comprehensive filters"""
        try:
            query_parts = ['''
                SELECT DISTINCT a.*, 
                       GROUP_CONCAT(DISTINCT t.ttp) as ttps,
                       GROUP_CONCAT(DISTINCT c.country) as countries
                FROM articles a
                LEFT JOIN ttps t ON a.id = t.article_id
                LEFT JOIN countries c ON a.id = c.article_id
                WHERE 1=1
            ''']
            
            params = []
            
            if start_date:
                query_parts.append('AND a.published_date >= ?')
                params.append(start_date)
            
            if end_date:
                query_parts.append('AND a.published_date <= ?')
                params.append(end_date)
            
            if country:
                query_parts.append('AND c.country = ?')
                params.append(country)
            
            if ttp:
                query_parts.append('AND t.ttp LIKE ?')
                params.append(f'%{ttp}%')
            
            if is_human_targeted is not None:
                query_parts.append('AND a.is_human_targeted = ?')
                params.append(is_human_targeted)
            
            if source:
                query_parts.append('AND a.source LIKE ?')
                params.append(f'%{source}%')
            
            if threat_actor:
                query_parts.append('AND a.threat_actor LIKE ?')
                params.append(f'%{threat_actor}%')
            
            if severity:
                query_parts.append('AND a.severity = ?')
                params.append(severity)
            
            query_parts.append('GROUP BY a.id ORDER BY a.published_date DESC LIMIT ?')
            params.append(limit)
            
            query = ' '.join(query_parts)
            
            conn = self.get_connection()
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            
            # Convert published_date to datetime
            if 'published_date' in df.columns:
                df['published_date'] = pd.to_datetime(df['published_date'])
            
            return df
            
        except Exception as e:
            logger.error(f"Error querying articles: {e}")
            return pd.DataFrame()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            # Article counts
            cursor.execute('SELECT COUNT(*) FROM articles')
            stats['total_articles'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM articles WHERE is_human_targeted = 1')
            stats['human_targeted_articles'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM articles WHERE is_human_targeted = 0')
            stats['general_articles'] = cursor.fetchone()[0]
            
            # Date range
            cursor.execute('SELECT MIN(published_date), MAX(published_date) FROM articles')
            date_range = cursor.fetchone()
            stats['date_range'] = {
                'start': date_range[0],
                'end': date_range[1]
            }
            
            # Unique counts
            cursor.execute('SELECT COUNT(DISTINCT source) FROM articles')
            stats['unique_sources'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT threat_actor) FROM articles WHERE threat_actor IS NOT NULL AND threat_actor != ""')
            stats['unique_threat_actors'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT ttp) FROM ttps')
            stats['unique_ttps'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT country) FROM countries')
            stats['unique_countries'] = cursor.fetchone()[0]
            
            # Top sources
            cursor.execute('''
                SELECT source, COUNT(*) as count 
                FROM articles 
                WHERE source IS NOT NULL 
                GROUP BY source 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            stats['top_sources'] = dict(cursor.fetch
