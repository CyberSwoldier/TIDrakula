#!/usr/bin/env python3
"""
Enhanced data processing module with better error handling
File: modules/data_processor.py
"""
import os
import glob
import pandas as pd
import pycountry
import streamlit as st
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class DataProcessor:
    """Enhanced data processor with robust error handling and sample data fallback"""
    
    def __init__(self):
        """Initialize the data processor"""
        self.sample_data_created = False
    
    def load_reports(self, folder="reports") -> pd.DataFrame:
        """Load and combine all report files with fallback to sample data"""
        try:
            # Try to load real data first
            files = glob.glob(f"{folder}/ttp_reports_*.xlsx")
            
            if not files:
                st.warning(f"No report files found in {folder}/ directory. Using sample data for demonstration.")
                return self._create_sample_data()
            
            all_data = []
            
            for f in files:
                try:
                    xls = pd.ExcelFile(f)
                    sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
                    
                    if "Human_Attacks" not in xls.sheet_names:
                        logger.warning(f"'Human_Attacks' sheet not found in {f}, using '{sheet_name}' instead.")
                    
                    df = pd.read_excel(xls, sheet_name=sheet_name)
                    date_str = os.path.basename(f).replace("ttp_reports_", "").replace(".xlsx", "")
                    df["report_date"] = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
                    all_data.append(df)
                    
                except Exception as e:
                    logger.warning(f"Could not read {f}: {e}")
                    continue
            
            if all_data:
                combined = pd.concat(all_data, ignore_index=True)
                combined = combined.dropna(subset=["report_date"])
                
                if combined.empty:
                    st.warning("No valid data after combining reports. Using sample data.")
                    return self._create_sample_data()
                
                return combined
            else:
                st.warning("Could not load any report files. Using sample data.")
                return self._create_sample_data()
                
        except Exception as e:
            st.error(f"Error loading reports: {e}. Using sample data.")
            return self._create_sample_data()
    
    def _create_sample_data(self) -> pd.DataFrame:
        """Create comprehensive sample data for demonstration"""
        if self.sample_data_created:
            # Return cached sample data
            return self._get_cached_sample_data()
        
        import random
        from datetime import timedelta
        
        # Sample countries
        countries = [
            "United States", "China", "Russia", "Germany", "United Kingdom",
            "Japan", "France", "South Korea", "India", "Brazil",
            "Canada", "Australia", "Netherlands", "Israel", "Sweden"
        ]
        
        # Sample TTPs (simplified for demo)
        ttps = [
            "Phishing (T1566.002)",
            "Spearphishing (T1566.001)", 
            "Ransomware (T1486)",
            "Credential Dumping (T1003)",
            "PowerShell (T1059.001)",
            "Command Line Interface (T1059.003)",
            "Social Engineering (T1566)",
            "Supply Chain Compromise (T1195)",
            "Brute Force (T1110)",
            "Malware (T1204)",
            "Backdoor (T1505.003)",
            "Data Exfiltration (T1041)",
            "Lateral Movement (TA0008)",
            "Privilege Escalation (TA0004)",
            "Defense Evasion (TA0005)"
        ]
        
        # Sample threat actors
        threat_actors = [
            "APT28", "APT29", "APT1", "APT41", "Lazarus Group",
            "Cozy Bear", "Fancy Bear", "Carbanak", "FIN7", "DarkSide",
            "REvil", "LockBit", "Conti", "BlackCat", "Unknown"
        ]
        
        # Sample sources
        sources = [
            "CyberNews", "ThreatPost", "BleepingComputer", "KrebsOnSecurity",
            "SecurityWeek", "InfoSecurity", "DarkReading", "TheHackerNews"
        ]
        
        # Sample titles templates
        title_templates = [
            "{actor} Launches {attack} Campaign Against {target}",
            "New {attack} Variant Targets {target} in {country}",
            "{country} Reports Increase in {attack} Incidents",
            "Security Alert: {attack} Campaign Affects {target}",
            "{actor} Uses {attack} to Target {target} Sector",
            "Critical Vulnerability Leads to {attack} in {country}",
            "Researchers Discover {attack} Malware Targeting {country}",
            "{target} Organizations Hit by {attack} Campaign"
        ]
        
        targets = [
            "Financial Institutions", "Government Agencies", "Healthcare Organizations",
            "Educational Institutions", "Energy Companies", "Manufacturing Firms",
            "Technology Companies", "Retail Businesses", "Critical Infrastructure"
        ]
        
        attack_types = [
            "Phishing", "Ransomware", "Supply Chain", "Zero-Day", "Credential Theft",
            "Social Engineering", "Advanced Persistent Threat", "Malware"
        ]
        
        # Generate sample data
        num_records = 150
        sample_data = []
        
        for i in range(num_records):
            # Random date within last 90 days
            days_ago = random.randint(0, 90)
            report_date = datetime.now() - timedelta(days=days_ago)
            
            # Generate title
            title = random.choice(title_templates).format(
                actor=random.choice(threat_actors),
                attack=random.choice(attack_types),
                target=random.choice(targets),
                country=random.choice(countries)
            )
            
            # Select random number of countries (1-3)
            num_countries = random.randint(1, 3)
            selected_countries = random.sample(countries, num_countries)
            
            # Select random number of TTPs (1-4)
            num_ttps = random.randint(1, 4)
            selected_ttps = random.sample(ttps, num_ttps)
            
            record = {
                'id': i + 1,
                'report_date': report_date,
                'title': title,
                'source': random.choice(sources),
                'threat_actor': random.choice(threat_actors),
                'url': f"https://example.com/threat-{i+1}",
                'content': f"Sample threat intelligence content for incident {i+1}. " * 5
            }
            
            # Add country columns
            for j, country in enumerate(selected_countries):
                record[f'country_{j+1}'] = country
            
            # Fill remaining country columns with None
            for j in range(len(selected_countries), 5):
                record[f'country_{j+1}'] = None
            
            # Add TTP columns
            for j, ttp in enumerate(selected_ttps):
                record[f'ttp_desc_{j+1}'] = ttp
            
            # Fill remaining TTP columns with None
            for j in range(len(selected_ttps), 6):
                record[f'ttp_desc_{j+1}'] = None
            
            sample_data.append(record)
        
        df = pd.DataFrame(sample_data)
        
        # Cache the sample data
        self._cache_sample_data(df)
        self.sample_data_created = True
        
        return df
    
    def _cache_sample_data(self, df: pd.DataFrame):
        """Cache sample data to avoid regeneration"""
        self.cached_sample_data = df
    
    def _get_cached_sample_data(self) -> pd.DataFrame:
        """Get cached sample data"""
        return getattr(self, 'cached_sample_data', self._create_sample_data())
    
    @staticmethod
    def get_ttp_columns(df: pd.DataFrame) -> List[str]:
        """Get all TTP description columns"""
        return [c for c in df.columns if c.lower().startswith("ttp_desc")]
    
    @staticmethod
    def get_country_columns(df: pd.DataFrame) -> List[str]:
        """Get all country columns"""
        return [c for c in df.columns if c.lower().startswith("country_")]
    
    @staticmethod
    def country_to_iso3(name: str) -> Optional[str]:
        """Convert country name to ISO3 code with error handling"""
        if not name or pd.isna(name):
            return None
        
        try:
            return pycountry.countries.lookup(name).alpha_3
        except LookupError:
            # Try some common mappings
            mappings = {
                'US': 'USA',
                'UK': 'GBR',
                'UAE': 'ARE',
                'Russia': 'RUS',
                'South Korea': 'KOR',
                'North Korea': 'PRK'
            }
            
            mapped_name = mappings.get(name, name)
            try:
                return pycountry.countries.lookup(mapped_name).alpha_3
            except LookupError:
                logger.debug(f"Could not find ISO3 code for country: {name}")
                return None
    
    def prepare_melted_data(self, df: pd.DataFrame, country_columns: List[str], 
                          ttp_columns: List[str], selected_countries: Optional[List[str]] = None) -> pd.DataFrame:
        """Prepare melted data for visualization with enhanced error handling"""
        if not country_columns or not ttp_columns or df.empty:
            return pd.DataFrame()
        
        try:
            # Create a copy to avoid modifying original
            df_copy = df.copy()
            
            # Handle missing columns
            for col in country_columns + ttp_columns:
                if col not in df_copy.columns:
                    df_copy[col] = None
            
            # Melt TTPs first
            ttp_melted = df_copy.melt(
                id_vars=country_columns + ['id'] if 'id' in df_copy.columns else country_columns,
                value_vars=ttp_columns,
                var_name="ttp_col",
                value_name="TTP"
            )
            
            # Clean TTP data
            ttp_melted = ttp_melted.dropna(subset=["TTP"])
            ttp_melted = ttp_melted[ttp_melted["TTP"].notna()]
            ttp_melted = ttp_melted[ttp_melted["TTP"] != ""]
            ttp_melted = ttp_melted[ttp_melted["TTP"] != "None"]
            
            if ttp_melted.empty:
                return pd.DataFrame()
            
            # Melt countries
            country_melted = ttp_melted.melt(
                id_vars=["TTP"] + (['id'] if 'id' in ttp_melted.columns else []),
                value_vars=country_columns,
                var_name="country_col",
                value_name="country"
            )
            
            # Clean country data
            country_melted = country_melted.dropna(subset=["country"])
            country_melted = country_melted[country_melted["country"].notna()]
            country_melted = country_melted[country_melted["country"] != ""]
            country_melted = country_melted[country_melted["country"] != "None"]
            
            # Apply country filter if specified
            if selected_countries:
                country_melted = country_melted[country_melted["country"].isin(selected_countries)]
            
            return country_melted
            
        except Exception as e:
            logger.error(f"Error preparing melted data: {e}")
            return pd.DataFrame()
    
    def get_unique_countries(self, df: pd.DataFrame, country_columns: List[str]) -> List[str]:
        """Get list of unique countries from dataframe with error handling"""
        if not country_columns or df.empty:
            return []
        
        try:
            all_countries = []
            for col in country_columns:
                if col in df.columns:
                    countries = df[col].dropna().unique()
                    all_countries.extend([c for c in countries if c and str(c) != 'None' and str(c) != 'nan'])
            
            unique_countries = list(set(all_countries))
            return sorted([c for c in unique_countries if c])
            
        except Exception as e:
            logger.error(f"Error getting unique countries: {e}")
            return []
    
    def filter_data_by_search(self, df: pd.DataFrame, search_term: str) -> pd.DataFrame:
        """Filter dataframe by search term with error handling"""
        if not search_term or df.empty:
            return df
        
        try:
            # Convert search term to lowercase for case-insensitive search
            search_lower = search_term.lower()
            
            # Create mask for all columns
            mask = df.apply(
                lambda row: row.astype(str).str.lower().str.contains(
                    search_lower, case=False, na=False, regex=False
                ).any(),
                axis=1
            )
            
            return df[mask]
            
        except Exception as e:
            logger.error(f"Error filtering data by search: {e}")
            return df
    
    def get_data_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Get comprehensive data summary"""
        if df.empty:
            return {}
        
        try:
            summary = {
                'total_records': len(df),
                'date_range': {
                    'start': df['report_date'].min() if 'report_date' in df.columns else None,
                    'end': df['report_date'].max() if 'report_date' in df.columns else None
                },
                'unique_sources': df['source'].nunique() if 'source' in df.columns else 0,
                'columns': list(df.columns),
                'memory_usage': df.memory_usage(deep=True).sum(),
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting data summary: {e}")
            return {}
    
    def validate_data_structure(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Validate data structure and return validation results"""
        validation_results = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'column_info': {}
        }
        
        try:
            # Check required columns
            required_columns = ['report_date', 'title', 'source']
            missing_required = [col for col in required_columns if col not in df.columns]
            
            if missing_required:
                validation_results['errors'].append(f"Missing required columns: {missing_required}")
                validation_results['is_valid'] = False
            
            # Check TTP columns
            ttp_columns = self.get_ttp_columns(df)
            if not ttp_columns:
                validation_results['warnings'].append("No TTP description columns found")
            
            # Check country columns
            country_columns = self.get_country_columns(df)
            if not country_columns:
                validation_results['warnings'].append("No country columns found")
            
            # Check data types
            for col in df.columns:
                validation_results['column_info'][col] = {
                    'dtype': str(df[col].dtype),
                    'null_count': df[col].isnull().sum(),
                    'unique_count': df[col].nunique()
                }
            
            return validation_results
            
        except Exception as e:
            validation_results['errors'].append(f"Validation error: {e}")
            validation_results['is_valid'] = False
            return validation_results
