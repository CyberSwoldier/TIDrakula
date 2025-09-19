#!/usr/bin/env python3
"""
Data fetching module for retrieving threat intelligence reports
"""
import os
import requests
import streamlit as st
from importlib import util

class DataFetcher:
    """Handles fetching data from GitHub and other sources"""
    
    def __init__(self, config):
        self.config = config
        self.threat_intel = self._load_threat_intel_module()
    
    def _load_threat_intel_module(self):
        """Fetch and load the threat_intel.py module"""
        try:
            r = requests.get(self.config.GITHUB_RAW_URL)
            r.raise_for_status()
            with open("threat_intel.py", "w", encoding="utf-8") as f:
                f.write(r.text)
                
            spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
            threat_intel = util.module_from_spec(spec)
            spec.loader.exec_module(threat_intel)
            return threat_intel
        except Exception:
            return None
    
    def fetch_reports(self):
        """Fetch reports from GitHub repository"""
        local_folder = self.config.REPORTS_FOLDER
        os.makedirs(local_folder, exist_ok=True)
        
        try:
            r = requests.get(self.config.API_URL)
            r.raise_for_status()
            files = r.json()
        except Exception as e:
            st.error(f"Failed to list files from GitHub: {e}")
            return []
        
        downloaded = []
        for file in files:
            name = file.get("name", "")
            download_url = file.get("download_url", "")
            
            if name.startswith("ttp_reports_") and name.endswith(".xlsx"):
                local_path = os.path.join(local_folder, name)
                
                if not os.path.exists(local_path):
                    try:
                        fr = requests.get(download_url)
                        fr.raise_for_status()
                        with open(local_path, "wb") as f:
                            f.write(fr.content)
                        st.sidebar.success(f"Fetched {name}")
                    except Exception as e:
                        st.sidebar.warning(f"Failed {name}: {e}")
                        continue
                        
                downloaded.append(local_path)
        
        return downloaded