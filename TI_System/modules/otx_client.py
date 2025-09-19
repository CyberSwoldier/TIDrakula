#!/usr/bin/env python3
"""
Enhanced OTX Client Module for AlienVault OTX Integration
File: modules/otx_client.py
"""
import requests
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
import hashlib
from urllib.parse import urljoin
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

@dataclass
class OTXPulse:
    """Data class for OTX pulse"""
    pulse_id: str
    name: str
    description: str
    created: datetime
    modified: datetime
    author_name: str
    revision: int
    tlp: str
    adversary: str
    malware_families: List[str]
    attack_ids: List[str]
    indicators: List[Dict]
    industries: List[str]
    targeted_countries: List[str]
    tags: List[str]
    references: List[str]

class OTXClient:
    """Enhanced client for AlienVault OTX API with comprehensive threat intelligence collection"""
    
    def __init__(self, api_key: str, config: dict = None):
        """
        Initialize OTX client
        
        Args:
            api_key: OTX API key
            config: Configuration dictionary
        """
        if not api_key or api_key == "YOUR_OTX_API_KEY_HERE":
            raise ValueError("Valid OTX API key is required")
        
        self.api_key = api_key
        self.config = config or {}
        self.base_url = "https://otx.alienvault.com/api/v1"
        
        self._setup_session()
        self._setup_rate_limiting()
        
        # Statistics
