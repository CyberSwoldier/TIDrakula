#!/usr/bin/env python3
"""
Threat Intelligence System Modules Package
File: modules/__init__.py
"""

# Import all modules for easy access
from .config import Config
from .data_fetcher import DataFetcher
from .data_processor import DataProcessor
from .ui_components import UIComponents
from .dashboard_page import DashboardPage
from .trends_page import TrendsPage
from .about_page import AboutPage
from .country_detector import CountryDetector
from .ttp_classifier import TTPClassifier
from .feed_manager import FeedManager
from .otx_client import OTXClient
from .database_manager import DatabaseManager
from .report_generator import ReportGenerator

__all__ = [
    'Config',
    'DataFetcher',
    'DataProcessor',
    'UIComponents',
    'DashboardPage',
    'TrendsPage',
    'AboutPage',
    'CountryDetector',
    'TTPClassifier',
    'FeedManager',
    'OTXClient',
    'DatabaseManager',
    'ReportGenerator'
]

__version__ = '2.0.0'