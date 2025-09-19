#!/usr/bin/env python3
"""
Configuration module for the Threat Intelligence Dashboard
"""

class Config:
    """Central configuration for the application"""
    
    def __init__(self):
        # Page configuration
        self.PAGE_TITLE = "Weekly Threat Intelligence"
        self.LAYOUT = "wide"
        
        # GitHub configuration
        self.GITHUB_USER = "CyberSwoldier"
        self.GITHUB_REPO = "Threat-Intelligence-NIMBLR"
        self.GITHUB_BRANCH = "main"
        self.REPORTS_FOLDER = "reports"
        
        # API URLs
        self.API_URL = f"https://api.github.com/repos/{self.GITHUB_USER}/{self.GITHUB_REPO}/contents/{self.REPORTS_FOLDER}?ref={self.GITHUB_BRANCH}"
        self.GITHUB_RAW_URL = "https://raw.githubusercontent.com/CyberSwoldier/Threat-Intelligence-Report/main/threat_intel.py"
        
        # Display configuration
        self.COLORS = {
            "background": "#0E1117",
            "plot_background": "#0E1117",
            "text": "white",
            "highlight": "yellow",
            "coastline": "lightblue",
            "colorscale": "YlOrBr"
        }
        
        # Chart configuration
        self.CHART_HEIGHTS = {
            "globe": 400,
            "bar": 400,
            "heatmap": 500,
            "trends": 500
        }
        
        # Data configuration
        self.DATE_FORMAT = "%d%m%y"
        self.EXCEL_ENGINE = "openpyxl"