#!/usr/bin/env python3
"""
ML-Enhanced Threat Intelligence Platform with OTX & Shodan Integration
Real-time threat data with machine learning analytics
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import time
import hashlib
import requests
from typing import Dict, List, Tuple
import json
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
import joblib

# Page configuration
st.set_page_config(
    page_title="ML Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# API CONFIGURATION
# ============================================================================

class APIConfig:
    """Secure API configuration management"""
    
    @staticmethod
    def get_api_keys():
        """Retrieve API keys from session state or prompt user"""
        if 'api_keys_configured' not in st.session_state:
            st.session_state.api_keys_configured = False
            st.session_state.otx_api_key = ""
            st.session_state.shodan_api_key = ""
        
        return {
            'otx': st.session_state.get('otx_api_key', ''),
            'shodan': st.session_state.get('shodan_api_key', '')
        }
    
    @staticmethod
    def configure_apis():
        """API configuration interface"""
        with st.sidebar.expander("⚙️ API CONFIGURATION", expanded=not st.session_state.api_keys_configured):
            st.markdown("### 🔑 API Keys Setup")
            
            otx_key = st.text_input(
                "OTX API Key",
                value=st.session_state.get('otx_api_key', ''),
                type="password",
                help="Get your free API key from: https://otx.alienvault.com"
            )
            
            shodan_key = st.text_input(
                "Shodan API Key",
                value=st.session_state.get('shodan_api_key', ''),
                type="password",
                help="Get your API key from: https://account.shodan.io"
            )
            
            if st.button("💾 Save API Keys"):
                st.session_state.otx_api_key = otx_key
                st.session_state.shodan_api_key = shodan_key
                st.session_state.api_keys_configured = True
                st.success("✅ API keys saved!")
                st.rerun()
            
            if not st.session_state.api_keys_configured:
                st.warning("⚠️ Please configure API keys to fetch real threat data")
            else:
                st.success("✅ API keys configured")

# ============================================================================
# OTX API INTEGRATION
# ============================================================================

class OTXIntegration:
    """AlienVault OTX API integration for threat intelligence"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {'X-OTX-API-KEY': api_key}
    
    def get_pulses(self, modified_since=None, limit=50):
        """Fetch threat pulses from OTX"""
        try:
            if not modified_since:
                modified_since = (datetime.now() - timedelta(days=7)).isoformat()
            
            url = f"{self.base_url}/pulses/subscribed"
            params = {'modified_since': modified_since, 'limit': limit}
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json().get('results', [])
        except Exception as e:
            st.error(f"OTX API Error: {str(e)}")
            return []
    
    def get_pulse_details(self, pulse_id):
        """Get detailed information about a specific pulse"""
        try:
            url = f"{self.base_url}/pulses/{pulse_id}"
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return None
    
    def search_pulses(self, query, page=1):
        """Search for specific threat pulses"""
        try:
            url = f"{self.base_url}/search/pulses"
            params = {'q': query, 'page': page}
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json().get('results', [])
        except Exception as e:
            return []
    
    def parse_pulses_to_dataframe(self, pulses):
        """Convert OTX pulses to structured dataframe"""
        threat_data = []
        
        for pulse in pulses:
            try:
                # Extract threat indicators
                indicators = pulse.get('indicators', [])
                tags = pulse.get('tags', [])
                
                # Determine severity based on tags and TLP
                severity = self._determine_severity(pulse)
                
                # Extract targeted industries/countries
                targeted_countries = pulse.get('targeted_countries', [])
                industries = pulse.get('industries', [])
                
                # Create threat record
                threat_record = {
                    'timestamp': pd.to_datetime(pulse.get('modified', datetime.now())),
                    'threat_id': pulse.get('id', ''),
                    'name': pulse.get('name', 'Unknown'),
                    'description': pulse.get('description', '')[:500],
                    'author': pulse.get('author_name', 'Unknown'),
                    'severity': severity,
                    'tlp': pulse.get('TLP', 'white'),
                    'tags': ','.join(tags[:5]),
                    'indicator_count': len(indicators),
                    'attack_ids': ','.join([ind.get('title', '') for ind in pulse.get('attack_ids', [])])[:200],
                    'malware_families': ','.join(pulse.get('malware_families', []))[:200],
                    'adversary': pulse.get('adversary', 'Unknown'),
                    'targeted_countries': ','.join(targeted_countries[:5]) if targeted_countries else 'Unknown',
                    'industries': ','.join(industries[:5]) if industries else 'Unknown',
                    'references': len(pulse.get('references', [])),
                    'pulse_source': 'OTX',
                    'confidence': self._calculate_confidence(pulse)
                }
                
                threat_data.append(threat_record)
                
            except Exception as e:
                continue
        
        return pd.DataFrame(threat_data) if threat_data else pd.DataFrame()
    
    def _determine_severity(self, pulse):
        """Determine threat severity based on pulse attributes"""
        tlp = pulse.get('TLP', 'white').lower()
        tags = [tag.lower() for tag in pulse.get('tags', [])]
        
        critical_keywords = ['critical', 'apt', 'ransomware', 'zero-day', 'exploit']
        high_keywords = ['malware', 'trojan', 'backdoor', 'botnet']
        
        if tlp in ['red', 'amber'] or any(kw in ' '.join(tags) for kw in critical_keywords):
            return 'Critical'
        elif any(kw in ' '.join(tags) for kw in high_keywords):
            return 'High'
        elif len(pulse.get('indicators', [])) > 50:
            return 'High'
        elif len(pulse.get('indicators', [])) > 10:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_confidence(self, pulse):
        """Calculate confidence score for threat"""
        score = 50  # Base score
        
        # Increase confidence based on indicators
        score += min(len(pulse.get('indicators', [])), 20)
        
        # Increase based on references
        score += min(len(pulse.get('references', [])) * 5, 15)
        
        # Increase based on validation/votes
        score += min(pulse.get('votes', {}).get('up', 0) * 2, 15)
        
        return min(score, 100)

# ============================================================================
# SHODAN API INTEGRATION
# ============================================================================

class ShodanIntegration:
    """Shodan API integration for network exposure data"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
    
    def search_exploits(self, query, limit=50):
        """Search for exploits in Shodan"""
        try:
            url = f"{self.base_url}/exploits/search"
            params = {'query': query, 'key': self.api_key, 'limit': limit}
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json().get('matches', [])
        except Exception as e:
            st.error(f"Shodan Exploits API Error: {str(e)}")
            return []
    
    def get_vulnerabilities(self, cve_list=None):
        """Get vulnerability information"""
        vulnerabilities = []
        
        if not cve_list:
            # Default recent CVEs to search
            cve_list = [f"CVE-2024-{i:04d}" for i in range(1, 21)]
        
        for cve in cve_list[:20]:  # Limit to avoid rate limiting
            try:
                url = f"{self.base_url}/exploits/search"
                params = {'query': cve, 'key': self.api_key}
                response = requests.get(url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities.extend(data.get('matches', []))
                
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def parse_exploits_to_dataframe(self, exploits):
        """Convert Shodan exploits to structured dataframe"""
        exploit_data = []
        
        for exploit in exploits:
            try:
                exploit_record = {
                    'timestamp': datetime.now(),
                    'threat_id': exploit.get('_id', ''),
                    'name': exploit.get('description', 'Unknown')[:200],
                    'description': exploit.get('description', '')[:500],
                    'cve': ','.join(exploit.get('cve', []))[:100],
                    'severity': self._map_cvss_to_severity(exploit.get('cvss')),
                    'cvss_score': exploit.get('cvss', 0),
                    'platform': exploit.get('platform', 'Unknown'),
                    'type': exploit.get('type', 'Unknown'),
                    'author': exploit.get('author', 'Unknown'),
                    'publish_date': exploit.get('publish_date', ''),
                    'source': exploit.get('source', 'Unknown'),
                    'pulse_source': 'Shodan',
                    'confidence': min(80 + (exploit.get('cvss', 0) * 2), 100)
                }
                
                exploit_data.append(exploit_record)
                
            except Exception as e:
                continue
        
        return pd.DataFrame(exploit_data) if exploit_data else pd.DataFrame()
    
    def _map_cvss_to_severity(self, cvss):
        """Map CVSS score to severity level"""
        if cvss is None:
            return 'Low'
        
        try:
            score = float(cvss)
            if score >= 9.0:
                return 'Critical'
            elif score >= 7.0:
                return 'High'
            elif score >= 4.0:
                return 'Medium'
            else:
                return 'Low'
        except:
            return 'Low'

# ============================================================================
# MACHINE LEARNING MODELS
# ============================================================================

class ThreatMLModels:
    """Machine learning models for threat intelligence"""
    
    def __init__(self):
        self.anomaly_detector = None
        self.risk_classifier = None
        self.threat_clusterer = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
    
    def prepare_features(self, df):
        """Prepare features for ML models"""
        if df.empty:
            return np.array([])
        
        features = pd.DataFrame()
        
        # Numerical features
        if 'confidence' in df.columns:
            features['confidence'] = df['confidence']
        if 'indicator_count' in df.columns:
            features['indicator_count'] = df['indicator_count'].fillna(0)
        if 'references' in df.columns:
            features['references'] = df['references'].fillna(0)
        
        # Time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            features['hour'] = df['timestamp'].dt.hour
            features['day_of_week'] = df['timestamp'].dt.dayofweek
            features['is_weekend'] = (df['timestamp'].dt.dayofweek >= 5).astype(int)
        
        # Categorical encoding
        for col in ['severity', 'pulse_source', 'tlp']:
            if col in df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    try:
                        features[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col].fillna('Unknown'))
                    except:
                        features[f'{col}_encoded'] = 0
                else:
                    try:
                        features[f'{col}_encoded'] = self.label_encoders[col].transform(df[col].fillna('Unknown'))
                    except:
                        features[f'{col}_encoded'] = 0
        
        # Text-based features
        if 'tags' in df.columns:
            features['tag_count'] = df['tags'].fillna('').str.split(',').str.len()
        
        # Fill any remaining NaN values
        features = features.fillna(0)
        
        return features.values if not features.empty else np.array([])
    
    def train_anomaly_detector(self, df):
        """Train anomaly detection model"""
        if df.empty or len(df) < 10:
            return None
        
        try:
            X = self.prepare_features(df)
            if X.size == 0 or len(X.shape) != 2 or X.shape[0] < 10:
                return None
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.anomaly_detector.fit(X_scaled)
            
            return self.anomaly_detector
        except Exception as e:
            st.warning(f"Anomaly detector training failed: {str(e)}")
            return None
    
    def detect_anomalies(self, df):
        """Detect anomalous threats"""
        if self.anomaly_detector is None or df.empty:
            return np.array([])
        
        try:
            X = self.prepare_features(df)
            if X.size == 0:
                return np.array([])
            
            X_scaled = self.scaler.transform(X)
            predictions = self.anomaly_detector.predict(X_scaled)
            scores = self.anomaly_detector.score_samples(X_scaled)
            
            return predictions, scores
        except Exception as e:
            return np.array([]), np.array([])
    
    def cluster_threats(self, df, n_clusters=5):
        """Cluster similar threats using K-Means"""
        if df.empty or len(df) < n_clusters:
            return None, None
        
        try:
            X = self.prepare_features(df)
            if X.size == 0 or len(X.shape) != 2:
                return None, None
            
            X_scaled = self.scaler.fit_transform(X)
            
            # Apply K-Means clustering
            kmeans = KMeans(n_clusters=min(n_clusters, len(df)), random_state=42)
            clusters = kmeans.fit_predict(X_scaled)
            
            # PCA for visualization
            if X_scaled.shape[1] > 2:
                pca = PCA(n_components=2)
                X_pca = pca.fit_transform(X_scaled)
            else:
                X_pca = X_scaled
            
            return clusters, X_pca
        except Exception as e:
            st.warning(f"Clustering failed: {str(e)}")
            return None, None
    
    def calculate_risk_score(self, df):
        """Calculate ML-based risk scores"""
        if df.empty:
            return np.array([])
        
        try:
            # Base risk score
            risk_scores = np.zeros(len(df))
            
            # Severity weight
            severity_map = {'Critical': 100, 'High': 75, 'Medium': 50, 'Low': 25}
            if 'severity' in df.columns:
                risk_scores += df['severity'].map(severity_map).fillna(25).values * 0.4
            
            # Confidence weight
            if 'confidence' in df.columns:
                risk_scores += df['confidence'].fillna(50).values * 0.3
            
            # Indicator count weight
            if 'indicator_count' in df.columns:
                normalized_indicators = np.clip(df['indicator_count'].fillna(0).values / 100, 0, 1)
                risk_scores += normalized_indicators * 100 * 0.2
            
            # Recency weight
            if 'timestamp' in df.columns:
                hours_ago = (datetime.now() - pd.to_datetime(df['timestamp'])).dt.total_seconds() / 3600
                recency_score = np.clip(1 - (hours_ago / 168), 0, 1)  # 7 days decay
                risk_scores += recency_score * 100 * 0.1
            
            return np.clip(risk_scores, 0, 100)
        except Exception as e:
            return np.zeros(len(df))
    
    def predict_threat_trend(self, df, days_ahead=7):
        """Predict threat trends using time series analysis"""
        if df.empty or 'timestamp' not in df.columns:
            return None
        
        try:
            # Aggregate threats by day
            df['date'] = pd.to_datetime(df['timestamp']).dt.date
            daily_threats = df.groupby('date').size().reset_index(name='count')
            daily_threats['date'] = pd.to_datetime(daily_threats['date'])
            daily_threats = daily_threats.sort_values('date')
            
            if len(daily_threats) < 7:
                return None
            
            # Simple moving average prediction
            window = min(7, len(daily_threats))
            daily_threats['ma'] = daily_threats['count'].rolling(window=window).mean()
            
            # Generate future predictions
            last_date = daily_threats['date'].max()
            future_dates = pd.date_range(start=last_date + timedelta(days=1), periods=days_ahead)
            
            last_ma = daily_threats['ma'].iloc[-1]
            trend = daily_threats['count'].diff().mean()
            
            predictions = []
            for i in range(days_ahead):
                pred = last_ma + (trend * (i + 1))
                predictions.append(max(0, pred))
            
            return pd.DataFrame({
                'date': future_dates,
                'predicted_count': predictions
            })
        except Exception as e:
            return None

# ============================================================================
# DATA MANAGEMENT
# ============================================================================

class ThreatDataManager:
    """Manage threat intelligence data from multiple sources"""
    
    @staticmethod
    @st.cache_data(ttl=300)  # Cache for 5 minutes
    def fetch_all_threat_data(otx_key, shodan_key):
        """Fetch and combine threat data from all sources"""
        all_threats = []
        
        # Fetch from OTX
        if otx_key:
            with st.spinner("Fetching threats from OTX..."):
                otx = OTXIntegration(otx_key)
                pulses = otx.get_pulses(limit=100)
                if pulses:
                    otx_df = otx.parse_pulses_to_dataframe(pulses)
                    if not otx_df.empty:
                        all_threats.append(otx_df)
        
        # Fetch from Shodan
        if shodan_key:
            with st.spinner("Fetching exploits from Shodan..."):
                shodan = ShodanIntegration(shodan_key)
                
                # Search for recent exploits
                queries = ['remote code execution', 'privilege escalation', 'sql injection', 'xss']
                for query in queries:
                    exploits = shodan.search_exploits(query, limit=25)
                    if exploits:
                        shodan_df = shodan.parse_exploits_to_dataframe(exploits)
                        if not shodan_df.empty:
                            all_threats.append(shodan_df)
                    time.sleep(1)  # Rate limiting
        
        # Combine all threats
        if all_threats:
            combined_df = pd.concat(all_threats, ignore_index=True)
            combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
            return combined_df.sort_values('timestamp', ascending=False)
        else:
            return pd.DataFrame()
    
    @staticmethod
    def enrich_with_ml(df, ml_models):
        """Enrich threat data with ML insights"""
        if df.empty:
            return df
        
        # Calculate risk scores
        df['ml_risk_score'] = ml_models.calculate_risk_score(df)
        
        # Detect anomalies
        predictions, scores = ml_models.detect_anomalies(df)
        if len(predictions) > 0:
            df['is_anomaly'] = (predictions == -1)
            df['anomaly_score'] = -scores  # Invert for intuitive scoring
        else:
            df['is_anomaly'] = False
            df['anomaly_score'] = 0
        
        # Cluster threats
        clusters, _ = ml_models.cluster_threats(df)
        if clusters is not None:
            df['threat_cluster'] = clusters
        else:
            df['threat_cluster'] = 0
        
        return df

# ============================================================================
# FUTURISTIC THEME STYLING
# ============================================================================

def apply_futuristic_theme():
    """Apply enhanced futuristic CSS styling"""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #151934 50%, #1a0033 100%);
        background-attachment: fixed;
    }
    
    h1 {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(90deg, #00ffff, #bf00ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-transform: uppercase;
        letter-spacing: 3px;
        font-weight: 900 !important;
        text-align: center;
        padding: 20px 0;
        font-size: 2.5em !important;
    }
    
    h2, h3 {
        font-family: 'Orbitron', monospace !important;
        color: #00ffff !important;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    
    [data-testid="stSidebar"] {
        background: rgba(20, 25, 47, 0.95);
        backdrop-filter: blur(20px);
        border-right: 2px solid rgba(0, 255, 255, 0.3);
    }
    
    .stButton > button {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(45deg, #00ffff, #bf00ff);
        color: #ffffff !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 30px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        box-shadow: 0 4px 15px rgba(0, 255, 255, 0.3);
    }
    
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0a0e27;
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00ffff, #bf00ff);
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================================
# VISUALIZATION COMPONENTS
# ============================================================================

def create_ml_anomaly_chart(df):
    """Create anomaly detection visualization"""
    if df.empty or 'is_anomaly' not in df.columns:
        return None
    
    fig = go.Figure()
    
    # Normal threats
    normal = df[~df['is_anomaly']]
    fig.add_trace(go.Scatter(
        x=normal['timestamp'],
        y=normal['ml_risk_score'],
        mode='markers',
        name='Normal Threats',
        marker=dict(size=8, color='#00ffff', opacity=0.6)
    ))
    
    # Anomalous threats
    anomalies = df[df['is_anomaly']]
    fig.add_trace(go.Scatter(
        x=anomalies['timestamp'],
        y=anomalies['ml_risk_score'],
        mode='markers',
        name='Anomalies',
        marker=dict(size=12, color='#ff0000', symbol='x', line=dict(width=2, color='#ffff00'))
    ))
    
    fig.update_layout(
        title='ML Anomaly Detection - Unusual Threat Patterns',
        xaxis_title='Timestamp',
        yaxis_title='Risk Score',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400,
        hovermode='closest'
    )
    
    return fig

def create_threat_cluster_viz(df, clusters, X_pca):
    """Create threat clustering visualization"""
    if df.empty or clusters is None or X_pca is None:
        return None
    
    fig = go.Figure()
    
    unique_clusters = np.unique(clusters)
    colors = px.colors.qualitative.Plotly
    
    for i, cluster in enumerate(unique_clusters):
        mask = clusters == cluster
        fig.add_trace(go.Scatter(
            x=X_pca[mask, 0],
            y=X_pca[mask, 1],
            mode='markers',
            name=f'Cluster {cluster}',
            marker=dict(size=10, color=colors[i % len(colors)], opacity=0.7)
        ))
    
    fig.update_layout(
        title='ML Threat Clustering - Similar Threat Groups',
        xaxis_title='Component 1',
        yaxis_title='Component 2',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400
    )
    
    return fig

def create_risk_distribution(df):
    """Create risk score distribution"""
    if df.empty or 'ml_risk_score' not in df.columns:
        return None
    
    fig = go.Figure()
    
    fig.add_trace(go.Histogram(
        x=df['ml_risk_score'],
        nbinsx=50,
        marker=dict(
            color=df['ml_risk_score'],
            colorscale=[[0, '#00ff00'], [0.5, '#ffff00'], [1, '#ff0000']],
            line=dict(color='#0a0e27', width=1)
        ),
        name='Risk Distribution'
    ))
    
    fig.update_layout(
        title='ML Risk Score Distribution',
        xaxis_title='Risk Score',
        yaxis_title='Frequency',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=350
    )
    
    return fig

def create_prediction_chart(historical_df, prediction_df):
    """Create threat prediction visualization"""
    if historical_df.empty or prediction_df is None:
        return None
    
    # Aggregate historical data
    historical_df['date'] = pd.to_datetime(historical_df['timestamp']).dt.date
    daily_counts = historical_df.groupby('date').size().reset_index(name='count')
    daily_counts['date'] = pd.to_datetime(daily_counts['date'])
    
    fig = go.Figure()
    
    # Historical data
    fig.add_trace(go.Scatter(
        x=daily_counts['date'],
        y=daily_counts['count'],
        mode='lines+markers',
        name='Historical',
        line=dict(color='#00ffff', width=2),
        marker=dict(size=6)
    ))
    
    # Predictions
    fig.add_trace(go.Scatter(
        x=prediction_df['date'],
        y=prediction_df['predicted_count'],
        mode='lines+markers',
        name='Predicted',
        line=dict(color='#bf00ff', width=2, dash='dash'),
        marker=dict(size=8, symbol='diamond')
    ))
    
    fig.update_layout(
        title='ML Threat Trend Prediction - Next 7 Days',
        xaxis_title='Date',
        yaxis_title='Threat Count',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400,
        hovermode='x unified'
    )
    
    return fig

def create_source_comparison(df):
    """Compare threat sources"""
    if df.empty or 'pulse_source' not in df.columns:
        return None
    
    source_counts = df['pulse_source'].value_counts()
    
    fig = go.Figure(data=[go.Pie(
        labels=source_counts.index,
        values=source_counts.values,
        hole=0.6,
        marker=dict(
            colors=['#00ffff', '#bf00ff', '#ff00bf'],
            line=dict(color='#0a0e27', width=2)
        ),
        textinfo='label+percent+value'
    )])
    
    fig.update_layout(
        title='Threat Intelligence Sources',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400
    )
    
    return fig

def create_severity_timeline(df):
    """Create severity timeline"""
    if df.empty:
        return None
    
    df_sorted = df.sort_values('timestamp')
    
    severity_colors = {
        'Critical': '#ff0000',
        'High': '#ff7f00',
        'Medium': '#ffff00',
        'Low': '#00ff00'
    }
    
    fig = go.Figure()
    
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        severity_df = df_sorted[df_sorted['severity'] == severity]
        if not severity_df.empty:
            severity_df['date'] = severity_df['timestamp'].dt.date
            daily = severity_df.groupby('date').size().reset_index(name='count')
            
            fig.add_trace(go.Scatter(
                x=pd.to_datetime(daily['date']),
                y=daily['count'],
                mode='lines',
                name=severity,
                line=dict(color=severity_colors[severity], width=2),
                stackgroup='one'
            ))
    
    fig.update_layout(
        title='Threat Severity Timeline',
        xaxis_title='Date',
        yaxis_title='Threat Count',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400,
        hovermode='x unified'
    )
    
    return fig

def create_top_threats_table(df, n=10):
    """Create top threats table"""
    if df.empty:
        return None
    
    top_threats = df.nlargest(n, 'ml_risk_score')
    
    display_df = top_threats[['name', 'severity', 'ml_risk_score', 'pulse_source', 'timestamp']].copy()
    display_df['ml_risk_score'] = display_df['ml_risk_score'].round(1)
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
    display_df.columns = ['Threat Name', 'Severity', 'Risk Score', 'Source', 'Detected']
    
    return display_df

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    apply_futuristic_theme()
    
    # Initialize session state
    if 'ml_models' not in st.session_state:
        st.session_state.ml_models = ThreatMLModels()
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    if 'threat_data' not in st.session_state:
        st.session_state.threat_data = pd.DataFrame()
    
    # Header
    st.markdown(f"""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                backdrop-filter: blur(20px); border-radius: 20px; 
                border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;
                box-shadow: 0 0 40px rgba(0, 255, 255, 0.2);">
        <h1 style="margin: 0;">ML THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8; font-size: 1.1em; margin-top: 10px; letter-spacing: 2px;">
            REAL-TIME OTX & SHODAN DATA • ML ANOMALY DETECTION • PREDICTIVE ANALYTICS
        </p>
        <p style="color: #00ff00; font-size: 0.9em; margin-top: 5px;">
            🟢 Last Refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # API Configuration
    APIConfig.configure_apis()
    api_keys = APIConfig.get_api_keys()
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚡ ACTIONS")
        
        if st.button("🔄 FETCH LATEST THREATS", use_container_width=True, type="primary"):
            if api_keys['otx'] or api_keys['shodan']:
                st.session_state.threat_data = ThreatDataManager.fetch_all_threat_data(
                    api_keys['otx'], api_keys['shodan']
                )
                st.session_state.last_refresh = datetime.now()
                
                if not st.session_state.threat_data.empty:
                    # Train ML models
                    st.session_state.ml_models.train_anomaly_detector(st.session_state.threat_data)
                    # Enrich with ML
                    st.session_state.threat_data = ThreatDataManager.enrich_with_ml(
                        st.session_state.threat_data, st.session_state.ml_models
                    )
                    st.success(f"✅ Fetched {len(st.session_state.threat_data)} threats!")
                else:
                    st.warning("⚠️ No threats fetched. Check API keys.")
            else:
                st.error("❌ Please configure API keys first!")
        
        st.markdown("---")
        
        # Filters
        st.markdown("### 🎯 FILTERS")
        
        df = st.session_state.threat_data
        
        if not df.empty:
            # Severity filter
            severities = df['severity'].unique().tolist()
            selected_severity = st.multiselect(
                "Severity",
                options=severities,
                default=severities
            )
            
            # Source filter
            if 'pulse_source' in df.columns:
                sources = df['pulse_source'].unique().tolist()
                selected_sources = st.multiselect(
                    "Source",
                    options=sources,
                    default=sources
                )
            else:
                selected_sources = []
            
            # ML Anomaly filter
            show_anomalies_only = st.checkbox("🔍 Show Anomalies Only", value=False)
            
            # Risk score threshold
            risk_threshold = st.slider(
                "Min Risk Score",
                min_value=0,
                max_value=100,
                value=0,
                step=10
            )
            
            # Apply filters
            filtered_df = df.copy()
            filtered_df = filtered_df[filtered_df['severity'].isin(selected_severity)]
            if selected_sources and 'pulse_source' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['pulse_source'].isin(selected_sources)]
            if show_anomalies_only and 'is_anomaly' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['is_anomaly']]
            if 'ml_risk_score' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['ml_risk_score'] >= risk_threshold]
        else:
            filtered_df = pd.DataFrame()
            st.info("👆 Click 'Fetch Latest Threats' to load data")
    
    # Main content
    if not filtered_df.empty:
        # Metrics
        st.markdown("### 📊 KEY METRICS")
        
        cols = st.columns(6)
        with cols[0]:
            st.metric("Total Threats", f"{len(filtered_df):,}")
        with cols[1]:
            critical = len(filtered_df[filtered_df['severity'] == 'Critical'])
            st.metric("Critical", f"{critical}")
        with cols[2]:
            if 'is_anomaly' in filtered_df.columns:
                anomalies = filtered_df['is_anomaly'].sum()
                st.metric("Anomalies", f"{anomalies}")
        with cols[3]:
            if 'ml_risk_score' in filtered_df.columns:
                avg_risk = filtered_df['ml_risk_score'].mean()
                st.metric("Avg Risk Score", f"{avg_risk:.1f}")
        with cols[4]:
            if 'pulse_source' in filtered_df.columns:
                sources = filtered_df['pulse_source'].nunique()
                st.metric("Sources", f"{sources}")
        with cols[5]:
            if 'threat_cluster' in filtered_df.columns:
                clusters = filtered_df['threat_cluster'].nunique()
                st.metric("Threat Groups", f"{clusters}")
        
        # Tabs
        tabs = st.tabs([
            "🎯 Overview",
            "🤖 ML Insights",
            "📈 Predictions",
            "📊 Analytics",
            "🔍 Threat Explorer"
        ])
        
        # Overview Tab
        with tabs[0]:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### 🚨 TOP THREATS BY ML RISK SCORE")
                top_threats = create_top_threats_table(filtered_df, n=10)
                if top_threats is not None:
                    st.dataframe(top_threats, use_container_width=True, height=400)
            
            with col2:
                fig_source = create_source_comparison(filtered_df)
                if fig_source:
                    st.plotly_chart(fig_source, use_container_width=True)
            
            st.markdown("#### 📈 THREAT SEVERITY TIMELINE")
            fig_timeline = create_severity_timeline(filtered_df)
            if fig_timeline:
                st.plotly_chart(fig_timeline, use_container_width=True)
        
        # ML Insights Tab
        with tabs[1]:
            st.markdown("### 🤖 MACHINE LEARNING INSIGHTS")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### 🔍 ANOMALY DETECTION")
                fig_anomaly = create_ml_anomaly_chart(filtered_df)
                if fig_anomaly:
                    st.plotly_chart(fig_anomaly, use_container_width=True)
                
                if 'is_anomaly' in filtered_df.columns:
                    anomaly_count = filtered_df['is_anomaly'].sum()
                    st.markdown(f"""
                    <div style="padding: 15px; background: rgba(20, 25, 47, 0.7); 
                                border: 2px solid #ff0000; border-radius: 10px; margin-top: 10px;">
                        <p style="color: #ff0000; font-weight: bold; margin: 0;">
                            ⚠️ {anomaly_count} ANOMALOUS THREATS DETECTED
                        </p>
                        <p style="color: #b8bcc8; font-size: 0.9em; margin-top: 5px;">
                            These threats exhibit unusual patterns and require immediate investigation.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
            
            with col2:
                st.markdown("#### 🎯 THREAT CLUSTERING")
                clusters, X_pca = st.session_state.ml_models.cluster_threats(filtered_df)
                fig_cluster = create_threat_cluster_viz(filtered_df, clusters, X_pca)
                if fig_cluster:
                    st.plotly_chart(fig_cluster, use_container_width=True)
                
                st.markdown("""
                <div style="padding: 15px; background: rgba(20, 25, 47, 0.7); 
                            border: 2px solid #00ffff; border-radius: 10px; margin-top: 10px;">
                    <p style="color: #00ffff; font-weight: bold; margin: 0;">
                        💡 ML CLUSTERING ANALYSIS
                    </p>
                    <p style="color: #b8bcc8; font-size: 0.9em; margin-top: 5px;">
                        Similar threats are grouped together based on their characteristics, 
                        enabling pattern recognition and coordinated response.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("#### 📊 ML RISK SCORE DISTRIBUTION")
            fig_risk = create_risk_distribution(filtered_df)
            if fig_risk:
                st.plotly_chart(fig_risk, use_container_width=True)
        
        # Predictions Tab
        with tabs[2]:
            st.markdown("### 📈 PREDICTIVE ANALYTICS")
            
            prediction_df = st.session_state.ml_models.predict_threat_trend(filtered_df, days_ahead=7)
            fig_pred = create_prediction_chart(filtered_df, prediction_df)
            
            if fig_pred:
                st.plotly_chart(fig_pred, use_container_width=True)
                
                if prediction_df is not None:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        next_day = int(prediction_df['predicted_count'].iloc[0])
                        st.metric("Tomorrow's Prediction", f"{next_day} threats")
                    with col2:
                        weekly_avg = int(prediction_df['predicted_count'].mean())
                        st.metric("7-Day Average", f"{weekly_avg} threats/day")
                    with col3:
                        trend = "📈 Increasing" if prediction_df['predicted_count'].is_monotonic_increasing else "📉 Decreasing"
                        st.metric("Trend", trend)
            else:
                st.info("Insufficient data for prediction. Need at least 7 days of history.")
        
        # Analytics Tab
        with tabs[3]:
            st.markdown("### 📊 DETAILED ANALYTICS")
            
            # Add more visualizations here similar to original dashboard
            st.info("Additional analytics charts can be added here")
        
        # Threat Explorer Tab
        with tabs[4]:
            st.markdown("### 🔍 THREAT EXPLORER")
            
            # Search and filter
            search_term = st.text_input("🔎 Search threats", placeholder="Enter keywords...")
            
            if search_term:
                search_df = filtered_df[
                    filtered_df['name'].str.contains(search_term, case=False, na=False) |
                    filtered_df['description'].str.contains(search_term, case=False, na=False)
                ]
            else:
                search_df = filtered_df
            
            # Display results
            st.markdown(f"#### Found {len(search_df)} threats")
            
            for idx, row in search_df.head(20).iterrows():
                with st.expander(f"🎯 {row['name'][:100]}"):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown(f"**Severity:** {row['severity']}")
                        st.markdown(f"**Source:** {row.get('pulse_source', 'Unknown')}")
                    with col2:
                        if 'ml_risk_score' in row:
                            st.markdown(f"**ML Risk Score:** {row['ml_risk_score']:.1f}/100")
                        if 'is_anomaly' in row:
                            anomaly_status = "🚨 YES" if row['is_anomaly'] else "✅ NO"
                            st.markdown(f"**Anomaly:** {anomaly_status}")
                    with col3:
                        st.markdown(f"**Detected:** {row['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        if 'confidence' in row:
                            st.markdown(f"**Confidence:** {row['confidence']}%")
                    
                    st.markdown(f"**Description:** {row.get('description', 'No description available')[:500]}...")
    else:
        st.info("👆 Configure your API keys and click 'Fetch Latest Threats' to begin monitoring")

if __name__ == "__main__":
    main()
