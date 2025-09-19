#!/usr/bin/env python3
"""
Country Detection Module for Threat Intelligence System
File: modules/country_detector.py
"""
import re
import pycountry
import tldextract
from typing import List, Optional, Set
import unicodedata
import ipaddress
import logging

logger = logging.getLogger(__name__)

class CountryDetector:
    """Detects countries mentioned in text and URLs using multiple methods"""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        """
        Initialize the country detector
        
        Args:
            geoip_db_path: Optional path to MaxMind GeoIP database
        """
        self._setup_country_mappings()
        self._setup_geoip(geoip_db_path)
        self._setup_spacy()
    
    def _setup_country_mappings(self):
        """Setup comprehensive country name mappings and aliases"""
        # Common aliases and abbreviations
        self.aliases = {
            # United States variations
            "usa": "United States",
            "us": "United States",
            "u.s.": "United States",
            "u.s.a.": "United States",
            "america": "United States",
            "united states of america": "United States",
            "the states": "United States",
            
            # United Kingdom variations
            "uk": "United Kingdom",
            "u.k.": "United Kingdom",
            "great britain": "United Kingdom",
            "england": "United Kingdom",
            "scotland": "United Kingdom",
            "wales": "United Kingdom",
            "northern ireland": "United Kingdom",
            "britain": "United Kingdom",
            
            # Korea variations
            "south korea": "South Korea",
            "republic of korea": "South Korea",
            "rok": "South Korea",
            "north korea": "North Korea",
            "democratic people's republic of korea": "North Korea",
            "dprk": "North Korea",
            
            # China variations
            "china": "China",
            "prc": "China",
            "people's republic of china": "China",
            "mainland china": "China",
            
            # Russia variations
            "russia": "Russia",
            "russian federation": "Russia",
            "soviet union": "Russia",
            "ussr": "Russia",
            
            # Other common abbreviations
            "uae": "United Arab Emirates",
            "u.a.e.": "United Arab Emirates",
            "emirates": "United Arab Emirates",
            "drc": "Democratic Republic of the Congo",
            "dr congo": "Democratic Republic of the Congo",
            "czechia": "Czech Republic",
            "holland": "Netherlands",
            "burma": "Myanmar",
        }
        
        # Native language names
        self.native_names = {
            # European languages
            "sverige": "Sweden",
            "suomi": "Finland",
            "danmark": "Denmark",
            "norge": "Norway",
            "island": "Iceland",
            "deutschland": "Germany",
            "österreich": "Austria",
            "schweiz": "Switzerland",
            "france": "France",
            "españa": "Spain",
            "italia": "Italy",
            "polska": "Poland",
            "česká republika": "Czech Republic",
            "magyarország": "Hungary",
            "românia": "Romania",
            "ελλάδα": "Greece",
            "türkiye": "Turkey",
            
            # Asian languages
            "中国": "China",
            "中華人民共和国": "China",
            "日本": "Japan",
            "nippon": "Japan",
            "한국": "South Korea",
            "대한민국": "South Korea",
            "조선민주주의인민공화국": "North Korea",
            "भारत": "India",
            "ประเทศไทย": "Thailand",
            "việt nam": "Vietnam",
            
            # Middle Eastern
            "مصر": "Egypt",
            "العراق": "Iraq",
            "ایران": "Iran",
            "السعودية": "Saudi Arabia",
            "الإمارات": "United Arab Emirates",
            
            # Others
            "brasil": "Brazil",
            "méxico": "Mexico",
            "россия": "Russia",
        }
        
        # Build pycountry lookup tables
        self._build_pycountry_lookups()
    
    def _build_pycountry_lookups(self):
        """Build lookup tables from pycountry"""
        self.name_to_alpha = {}
        self.alpha_to_name = {}
        
        try:
            for country in pycountry.countries:
                # Add name variations
                names = {getattr(country, "name", "")}
                if hasattr(country, "official_name"):
                    names.add(country.official_name)
                if hasattr(country, "common_name"):
                    names.add(country.common_name)
                
                # Store alpha codes
                if hasattr(country, "alpha_2"):
                    self.alpha_to_name[country.alpha_2.upper()] = country.name
                if hasattr(country, "alpha_3"):
                    self.alpha_to_name[country.alpha_3.upper()] = country.name
                
                # Store name mappings
                for name in names:
                    if name:
                        self.name_to_alpha[name.lower()] = country.alpha_2
        except Exception as e:
            logger.warning(f"Error building pycountry lookups: {e}")
    
    def _setup_geoip(self, geoip_db_path: Optional[str]):
        """Setup GeoIP resolver if database is available"""
        self.geoip = None
        
        if geoip_db_path:
            try:
                import geoip2.database
                self.geoip = geoip2.database.Reader(geoip_db_path)
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.warning(f"Could not load GeoIP database: {e}")
    
    def _setup_spacy(self):
        """Setup spaCy for NER if available"""
        self.nlp = None
        
        try:
            import spacy
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except:
                try:
                    self.nlp = spacy.load("xx_ent_wiki_sm")
                except:
                    pass
            
            if self.nlp:
                logger.info("spaCy NLP model loaded")
        except ImportError:
            logger.debug("spaCy not available for country detection")
    
    def detect(self, text: str, url: Optional[str] = None) -> List[str]:
        """
        Detect countries in text and URL using multiple methods
        
        Args:
            text: Text to analyze
            url: Optional URL to check TLD
        
        Returns:
            List of unique detected country names
        """
        countries = set()
        
        # Method 1: Named Entity Recognition
        if self.nlp:
            countries.update(self._detect_with_ner(text))
        
        # Method 2: Pattern matching
        countries.update(self._detect_in_text(text))
        
        # Method 3: URL TLD analysis
        if url:
            tld_country = self._detect_from_tld(url)
            if tld_country:
                countries.add(tld_country)
        
        # Method 4: IP address resolution
        if self.geoip:
            countries.update(self._detect_from_ips(text))
        
        # Remove duplicates and return sorted
        return sorted(list(countries))
    
    def _detect_with_ner(self, text: str) -> Set[str]:
        """Use spaCy NER to detect countries"""
        countries = set()
        
        try:
            doc = self.nlp(text[:1000000])  # Limit text length for performance
            
            for ent in doc.ents:
                if ent.label_ in ("GPE", "LOC"):
                    mapped = self._map_to_country(ent.text.strip())
                    if mapped:
                        countries.add(mapped)
        except Exception as e:
            logger.debug(f"NER detection error: {e}")
        
        return countries
    
    def _detect_in_text(self, text: str) -> Set[str]:
        """Detect countries using pattern matching"""
        countries = set()
        text_lower = text.lower()
        
        # Check aliases
        for alias, country in self.aliases.items():
            if re.search(r'\b' + re.escape(alias) + r'\b', text_lower, re.I):
                countries.add(country)
        
        # Check native names
        for native, country in self.native_names.items():
            if native in text:
                countries.add(country)
        
        # Check pycountry names
        for name_lower, alpha in self.name_to_alpha.items():
            if re.search(r'\b' + re.escape(name_lower) + r'\b', text_lower, re.I):
                try:
                    canonical = self.alpha_to_name.get(alpha.upper())
                    if canonical:
                        countries.add(canonical)
                except:
                    pass
        
        return countries
    
    def _detect_from_tld(self, url: str) -> Optional[str]:
        """Detect country from URL top-level domain"""
        try:
            ext = tldextract.extract(url)
            suffix = (ext.suffix or "").split('.')[-1]
            
            # Check if it's a country code TLD
            if suffix and len(suffix) == 2:
                country = pycountry.countries.get(alpha_2=suffix.upper())
                if country:
                    return country.name
        except Exception as e:
            logger.debug(f"TLD detection error: {e}")
        
        return None
    
    def _detect_from_ips(self, text: str) -> Set[str]:
        """Detect countries from IP addresses in text"""
        countries = set()
        
        # IPv4 pattern
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        
        # Find all IPs
        ips = re.findall(ipv4_pattern, text) + re.findall(ipv6_pattern, text)
        
        for ip in ips:
            try:
                # Validate IP
                ip_obj = ipaddress.ip_address(ip)
                
                # Skip private IPs
                if ip_obj.is_private:
                    continue
                
                # Resolve country
                if self.geoip:
                    response = self.geoip.country(str(ip_obj))
                    if response.country.name:
                        countries.add(response.country.name)
            except Exception as e:
                logger.debug(f"IP resolution error for {ip}: {e}")
        
        return countries
    
    def _map_to_country(self, candidate: str) -> Optional[str]:
        """
        Map a candidate string to a standardized country name
        
        Args:
            candidate: String that might be a country
        
        Returns:
            Standardized country name or None
        """
        if not candidate or not isinstance(candidate, str):
            return None
        
        # Normalize the candidate
        cand_norm = self._normalize_text(candidate)
        
        # Check aliases
        if cand_norm in self.aliases:
            return self.aliases[cand_norm]
        
        # Check native names
        if cand_norm in self.native_names:
            return self.native_names[cand_norm]
        
        # Check if it's a 2-letter code
        if len(cand_norm) == 2:
            try:
                country = pycountry.countries.get(alpha_2=cand_norm.upper())
                if country:
                    return country.name
            except:
                pass
        
        # Check if it's a 3-letter code
        if len(cand_norm) == 3:
            try:
                country = pycountry.countries.get(alpha_3=cand_norm.upper())
                if country:
                    return country.name
            except:
                pass
        
        # Try fuzzy search
        try:
            results = pycountry.countries.search_fuzzy(candidate)
            if results:
                return results[0].name
        except:
            pass
        
        return None
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for matching"""
        if not isinstance(text, str):
            return ""
        
        # Normalize unicode
        text = unicodedata.normalize("NFKD", text)
        # Remove combining characters
        text = "".join(ch for ch in text if not unicodedata.combining(ch))
        # Lowercase and strip
        return text.lower().strip()
    
    def get_country_stats(self, countries: List[str]) -> dict:
        """
        Get statistics about detected countries
        
        Args:
            countries: List of country names
        
        Returns:
            Dictionary with country statistics
        """
        from collections import Counter
        
        counter = Counter(countries)
        
        return {
            "total": len(countries),
            "unique": len(set(countries)),
            "most_common": counter.most_common(10),
            "by_continent": self._group_by_continent(list(set(countries)))
        }
    
    def _group_by_continent(self, countries: List[str]) -> dict:
        """Group countries by continent"""
        continents = {
            "Africa": [],
            "Asia": [],
            "Europe": [],
            "North America": [],
            "South America": [],
            "Oceania": [],
            "Unknown": []
        }
        
        # Simple continent mapping (can be enhanced)
        continent_map = {
            "United States": "North America",
            "Canada": "North America",
            "Mexico": "North America",
            "Brazil": "South America",
            "Argentina": "South America",
            "United Kingdom": "Europe",
            "Germany": "Europe",
            "France": "Europe",
            "China": "Asia",
            "Japan": "Asia",
            "India": "Asia",
            "Australia": "Oceania",
            "New Zealand": "Oceania",
            # Add more mappings
        }
        
        for country in countries:
            continent = continent_map.get(country, "Unknown")
            if continent in continents:
                continents[continent].append(country)
            else:
                continents["Unknown"].append(country)
        
        return continents