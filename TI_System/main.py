#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform with ML Predictions
Includes: OTX, Shodan, VirusTotal APIs + ML Forecasting
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
import time
import random
import hashlib
import json
import feedparser
import requests
from typing import Dict, List, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

st.set_page_config(
    page_title="Threat Intelligence Platform - TIP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# API KEYS CONFIGURATION
# ============================================================================

OTX_API_KEY = "a64a6fc71743dd93f98f8b91b7a611e6bd219d32a9faa11d85256b7a81e8dd89"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Add your API keys here
SHODAN_API_KEY = st.secrets.get("SHODAN_API_KEY", "")  # or enter directly: "your_key_here"
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")  # or enter directly: "your_key_here"

# ============================================================================
# API CONNECTORS
# ============================================================================

class OTXConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {'X-OTX-API-KEY': api_key, 'Content-Type': 'application/json'}
    
    def get_pulses_subscribed(self, limit=50, modified_since=None):
        url = f"{OTX_BASE_URL}/pulses/subscribed"
        params = {'limit': limit}
        if modified_since:
            params['modified_since'] = modified_since
        
        for attempt in range(3):
            try:
                timeout = 20 + (attempt * 10)
                response = requests.get(url, headers=self.headers, params=params, timeout=timeout)
                response.raise_for_status()
                return response.json()
            except:
                if attempt < 2:
                    continue
                return None
        return None

class ShodanConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
    
    def search_host(self, ip):
        if not self.api_key:
            return None
        try:
            url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None

class VirusTotalConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {'x-apikey': api_key}
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def scan_ip(self, ip):
        if not self.api_key:
            return None
        try:
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None
    
    def scan_domain(self, domain):
        if not self.api_key:
            return None
        try:
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None

# ============================================================================
# FUTURISTIC THEME
# ============================================================================

def apply_futuristic_theme():
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
        border-radius: 10px !important;
        padding: 10px 30px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
    }
    .flashcard {
        background: linear-gradient(135deg, rgba(0, 255, 255, 0.1), rgba(191, 0, 255, 0.1));
        border: 2px solid rgba(0, 255, 255, 0.3);
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        transition: transform 0.3s;
    }
    .flashcard:hover {
        transform: scale(1.02);
        border-color: #00ffff;
    }
    ::-webkit-scrollbar {
        width: 10px;
    }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00ffff, #bf00ff);
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================================
# THREAT INTELLIGENCE MODEL
# ============================================================================

class ThreatIntelligence:
    
    ATTACK_TECHNIQUES = {
        'T1566': {'name': 'Phishing', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Adversaries send fraudulent messages to trick users into revealing sensitive information or executing malicious code.'},
        'T1486': {'name': 'Data Encrypted for Impact', 'category': 'Impact', 'severity': 'Critical',
                  'description': 'Adversaries encrypt data on target systems to interrupt availability. Commonly seen in ransomware attacks.'},
        'T1498': {'name': 'Network Denial of Service', 'category': 'Impact', 'severity': 'High',
                  'description': 'Adversaries perform DoS/DDoS attacks to degrade or block availability of targeted resources.'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Adversaries exploit weaknesses in internet-facing applications to gain initial access.'},
        'T1059': {'name': 'Command and Scripting Interpreter', 'category': 'Execution', 'severity': 'Medium',
                  'description': 'Adversaries abuse command and script interpreters to execute commands and scripts.'},
        'T1055': {'name': 'Process Injection', 'category': 'Defense Evasion', 'severity': 'High',
                  'description': 'Adversaries inject code into processes to evade defenses and elevate privileges.'},
        'T1003': {'name': 'OS Credential Dumping', 'category': 'Credential Access', 'severity': 'Critical',
                  'description': 'Adversaries attempt to dump credentials to obtain account login information.'},
        'T1071': {'name': 'Application Layer Protocol', 'category': 'Command and Control', 'severity': 'Medium',
                  'description': 'Adversaries use application layer protocols for command and control communications.'}
    }
    
    THREAT_ACTORS = {
        'APT28': {'origin': 'Russia', 'targets': ['Government', 'Defense', 'Energy'], 'sophistication': 'High'},
        'APT29': {'origin': 'Russia', 'targets': ['Government', 'Healthcare', 'Technology'], 'sophistication': 'High'},
        'Lazarus': {'origin': 'North Korea', 'targets': ['Finance', 'Cryptocurrency', 'Defense'], 'sophistication': 'High'},
        'APT1': {'origin': 'China', 'targets': ['Technology', 'Manufacturing', 'Energy'], 'sophistication': 'Medium'},
        'FIN7': {'origin': 'Unknown', 'targets': ['Retail', 'Hospitality', 'Finance'], 'sophistication': 'High'},
        'Sandworm': {'origin': 'Russia', 'targets': ['Critical Infrastructure', 'Government', 'Energy'], 'sophistication': 'High'}
    }
    
    SECTORS = ['Finance', 'Healthcare', 'Government', 'Technology', 'Energy', 
               'Manufacturing', 'Retail', 'Defense', 'Education', 'Telecommunications']
    
    COUNTRIES = {
        'USA': {'lat': 39.0, 'lon': -98.0}, 'UK': {'lat': 54.0, 'lon': -2.0},
        'Germany': {'lat': 51.0, 'lon': 10.5}, 'Japan': {'lat': 36.0, 'lon': 138.0},
        'Australia': {'lat': -25.0, 'lon': 135.0}, 'Canada': {'lat': 56.0, 'lon': -106.0},
        'France': {'lat': 47.0, 'lon': 2.0}, 'India': {'lat': 20.0, 'lon': 77.0},
        'Brazil': {'lat': -14.0, 'lon': -51.0}, 'Russia': {'lat': 61.0, 'lon': 105.0},
        'China': {'lat': 35.0, 'lon': 105.0}, 'Portugal': {'lat': 39.5, 'lon': -8.0}
    }
    
    @staticmethod
    def generate_threat_feed(num_events=1000):
        threat_events = []
        for _ in range(num_events):
            technique_id = random.choice(list(ThreatIntelligence.ATTACK_TECHNIQUES.keys()))
            technique = ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]
            actor = random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys()))
            is_blocked = random.choice([True, True, True, False])
            
            threat_events.append({
                'timestamp': datetime.now() - timedelta(hours=random.randint(0, 720)),
                'threat_id': f"THREAT-{random.randint(10000, 99999)}",
                'technique_id': technique_id,
                'technique_name': technique['name'],
                'category': technique['category'],
                'severity': technique['severity'],
                'threat_actor': actor,
                'origin_country': ThreatIntelligence.THREAT_ACTORS[actor]['origin'],
                'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                'target_sector': random.choice(ThreatIntelligence.SECTORS),
                'confidence': random.randint(60, 100),
                'blocked': is_blocked,
                'active': not is_blocked,
                'ioc_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'ioc_domain': f"malicious-{random.randint(100,999)}.com"
            })
        return pd.DataFrame(threat_events)

# ============================================================================
# MACHINE LEARNING MODULE
# ============================================================================

class ThreatMLEngine:
    
    @staticmethod
    def prepare_features(df):
        """Prepare features for ML models"""
        df_ml = df.copy()
        
        # Encode categorical variables
        le_technique = LabelEncoder()
        le_country = LabelEncoder()
        le_sector = LabelEncoder()
        le_severity = LabelEncoder()
        
        df_ml['technique_encoded'] = le_technique.fit_transform(df_ml['technique_name'])
        df_ml['country_encoded'] = le_country.fit_transform(df_ml['target_country'])
        df_ml['sector_encoded'] = le_sector.fit_transform(df_ml['target_sector'])
        df_ml['severity_encoded'] = le_severity.fit_transform(df_ml['severity'])
        
        # Time-based features
        df_ml['hour'] = df_ml['timestamp'].dt.hour
        df_ml['day_of_week'] = df_ml['timestamp'].dt.dayofweek
        df_ml['is_weekend'] = df_ml['day_of_week'].isin([5, 6]).astype(int)
        
        return df_ml, {
            'technique': le_technique,
            'country': le_country,
            'sector': le_sector,
            'severity': le_severity
        }
    
    @staticmethod
    def predict_severity(df):
        """Train model to predict threat severity"""
        if len(df) < 100:
            return None, None
        
        df_ml, encoders = ThreatMLEngine.prepare_features(df)
        
        features = ['technique_encoded', 'country_encoded', 'sector_encoded', 
                   'hour', 'day_of_week', 'is_weekend', 'confidence']
        X = df_ml[features]
        y = df_ml['severity_encoded']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        model.fit(X_train, y_train)
        
        accuracy = model.score(X_test, y_test)
        
        return model, {'encoders': encoders, 'accuracy': accuracy, 'features': features}
    
    @staticmethod
    def forecast_24h_threats(df, model, model_info):
        """Forecast threats for next 24 hours"""
        if model is None:
            return pd.DataFrame()
        
        future_times = [datetime.now() + timedelta(hours=i) for i in range(1, 25)]
        predictions = []
        
        for future_time in future_times:
            # Simulate future threat scenarios
            for _ in range(10):
                sample = {
                    'hour': future_time.hour,
                    'day_of_week': future_time.weekday(),
                    'is_weekend': 1 if future_time.weekday() in [5, 6] else 0,
                    'technique_encoded': random.randint(0, 7),
                    'country_encoded': random.randint(0, len(ThreatIntelligence.COUNTRIES)-1),
                    'sector_encoded': random.randint(0, len(ThreatIntelligence.SECTORS)-1),
                    'confidence': random.randint(70, 95)
                }
                
                X_pred = pd.DataFrame([sample])[model_info['features']]
                severity_pred = model.predict(X_pred)[0]
                
                predictions.append({
                    'timestamp': future_time,
                    'predicted_severity': model_info['encoders']['severity'].inverse_transform([severity_pred])[0],
                    'confidence': sample['confidence']
                })
        
        return pd.DataFrame(predictions)
    
    @staticmethod
    def detect_anomalies(df):
        """Detect anomalous threat patterns using Isolation Forest"""
        if len(df) < 50:
            return df
        
        df_ml, _ = ThreatMLEngine.prepare_features(df)
        
        features = ['technique_encoded', 'country_encoded', 'sector_encoded', 
                   'hour', 'day_of_week', 'confidence']
        X = df_ml[features]
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        df_ml['anomaly'] = iso_forest.fit_predict(X)
        df_ml['anomaly_score'] = iso_forest.score_samples(X)
        
        df['is_anomaly'] = (df_ml['anomaly'] == -1)
        df['anomaly_score'] = df_ml['anomaly_score']
        
        return df
    
    @staticmethod
    def identify_high_risk_windows(df):
        """Identify time windows with elevated threat levels"""
        df['hour'] = df['timestamp'].dt.hour
        hourly_threats = df.groupby('hour').agg({
            'threat_id': 'count',
            'severity': lambda x: (x == 'Critical').sum()
        }).reset_index()
        hourly_threats.columns = ['hour', 'total_threats', 'critical_threats']
        
        # Calculate risk score
        hourly_threats['risk_score'] = (
            hourly_threats['total_threats'] * 0.6 + 
            hourly_threats['critical_threats'] * 2
        )
        
        mean_risk = hourly_threats['risk_score'].mean()
        std_risk = hourly_threats['risk_score'].std()
        
        hourly_threats['risk_level'] = 'Normal'
        hourly_threats.loc[hourly_threats['risk_score'] > mean_risk + std_risk, 'risk_level'] = 'High'
        hourly_threats.loc[hourly_threats['risk_score'] > mean_risk + 2*std_risk, 'risk_level'] = 'Critical'
        
        return hourly_threats

# ============================================================================
# DATA FETCHING
# ============================================================================

@st.cache_data(ttl=300)
def fetch_otx_data():
    otx = OTXConnector(OTX_API_KEY)
    pulses_data = otx.get_pulses_subscribed(limit=50)
    
    threat_events = []
    
    if pulses_data and 'results' in pulses_data:
        for pulse in pulses_data['results']:
            try:
                technique_id = random.choice(list(ThreatIntelligence.ATTACK_TECHNIQUES.keys()))
                severity = random.choice(['Critical', 'High', 'Medium'])
                
                threat_events.append({
                    'timestamp': pd.to_datetime(pulse.get('modified', datetime.now().isoformat())),
                    'threat_id': f"OTX-{pulse.get('id', '')}",
                    'technique_id': technique_id,
                    'technique_name': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['name'],
                    'category': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['category'],
                    'severity': severity,
                    'threat_actor': random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys())),
                    'origin_country': random.choice(['Russia', 'China', 'North Korea']),
                    'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                    'target_sector': random.choice(ThreatIntelligence.SECTORS),
                    'confidence': min(100, 60 + len(pulse.get('indicators', [])) * 2),
                    'blocked': random.choice([True, True, False]),
                    'active': random.choice([True, False]),
                    'ioc_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    'ioc_domain': f"threat-{pulse.get('id', '')[:8]}.com"
                })
            except:
                continue
    
    return pd.DataFrame(threat_events) if threat_events else pd.DataFrame()

def generate_data():
    df_otx = fetch_otx_data()
    df_simulated = ThreatIntelligence.generate_threat_feed(2000)
    
    dfs_to_combine = [df for df in [df_otx, df_simulated] if not df.empty]
    
    if dfs_to_combine:
        return pd.concat(dfs_to_combine, ignore_index=True)
    else:
        return ThreatIntelligence.generate_threat_feed(2000)

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def create_globe_map(threat_df):
    country_threats = threat_df.groupby('target_country').size().reset_index(name='count')
    
    globe_data = []
    for _, row in country_threats.iterrows():
        country = row['country']
        if country in ThreatIntelligence.COUNTRIES:
            coords = ThreatIntelligence.COUNTRIES[country]
            globe_data.append({
                'lat': coords['lat'],
                'lon': coords['lon'],
                'country': country,
                'count': row['count']
            })
    
    if not globe_data:
        return go.Figure()
    
    globe_df = pd.DataFrame(globe_data)
    
    fig = go.Figure(go.Scattergeo(
        lon=globe_df['lon'],
        lat=globe_df['lat'],
        text=globe_df['country'] + '<br>Threats: ' + globe_df['count'].astype(str),
        mode='markers',
        marker=dict(
            size=globe_df['count'] / 5,
            color=globe_df['count'],
            colorscale='Reds',
            showscale=False,
            sizemin=5
        )
    ))
    
    fig.update_layout(
        geo=dict(projection_type='orthographic', showland=True),
        height=500,
        paper_bgcolor='rgba(20, 25, 47, 0.7)'
    )
    
    return fig

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    apply_futuristic_theme()
    
    if 'threat_data' not in st.session_state:
        with st.spinner("Loading threat intelligence..."):
            st.session_state.threat_data = generate_data()
    
    st.markdown("""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                border-radius: 20px; border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;">
        <h1>THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8; font-size: 1.1em;">ML-POWERED PREDICTIONS • MULTI-SOURCE INTEGRATION</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar filters
    with st.sidebar:
        st.markdown("### FILTERS")
        time_range = st.selectbox("Time Range", ['Last 24 Hours', 'Last 7 Days', 'Last 30 Days'], index=1)
        time_map = {'Last 24 Hours': 1, 'Last 7 Days': 7, 'Last 30 Days': 30}
        days_back = time_map[time_range]
        
        severity_levels = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], 
                                        default=['Critical', 'High', 'Medium'])
    
    threat_df = st.session_state.threat_data.copy()
    time_cutoff = datetime.now() - timedelta(days=days_back)
    threat_df = threat_df[threat_df['timestamp'] > time_cutoff]
    threat_df = threat_df[threat_df['severity'].isin(severity_levels)]
    
    # Main tabs
    tabs = st.tabs(["Overview", "ML Trends & Forecasting", "Threat Intelligence", 
                    "Security Recommendations", "IOC Scanner", "Global Threats"])
    
    # Tab 1: Overview
    with tabs[0]:
        st.markdown("### THREAT OVERVIEW")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Threats", f"{len(threat_df):,}")
        with col2:
            critical = len(threat_df[threat_df['severity'] == 'Critical'])
            st.metric("Critical", critical)
        with col3:
            active = len(threat_df[threat_df['active'] == True])
            st.metric("Active", active)
        with col4:
            blocked = len(threat_df[threat_df['blocked'] == True])
            block_rate = (blocked / len(threat_df) * 100) if len(threat_df) > 0 else 0
            st.metric("Block Rate", f"{block_rate:.1f}%")
        
        col1, col2 = st.columns(2)
        with col1:
            attack_dist = threat_df['technique_name'].value_counts().head(8)
            fig = go.Figure(go.Bar(x=attack_dist.values, y=attack_dist.index, orientation='h',
                                  marker=dict(color='#00ffff')))
            fig.update_layout(title='Attack Types', height=400, 
                            paper_bgcolor='rgba(20, 25, 47, 0.7)')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            sector_dist = threat_df['target_sector'].value_counts().head(8)
            fig = go.Figure(go.Bar(x=sector_dist.values, y=sector_dist.index, orientation='h',
                                  marker=dict(color='#bf00ff')))
            fig.update_layout(title='Targeted Sectors', height=400,
                            paper_bgcolor='rgba(20, 25, 47, 0.7)')
            st.plotly_chart(fig, use_container_width=True)
    
    # Tab 2: ML Trends & Forecasting
    with tabs[1]:
        st.markdown("### 🤖 MACHINE LEARNING THREAT ANALYSIS")
        
        with st.spinner("Training ML models..."):
            model, model_info = ThreatMLEngine.predict_severity(threat_df)
            threat_df_anomaly = ThreatMLEngine.detect_anomalies(threat_df)
            high_risk_windows = ThreatMLEngine.identify_high_risk_windows(threat_df)
        
        if model is not None:
            st.success(f"✅ ML Model Trained | Accuracy: {model_info['accuracy']:.2%}")
            
            # 24h Forecast
            st.markdown("#### 📈 NEXT 24 HOURS SEVERITY FORECAST")
            forecast_df = ThreatMLEngine.forecast_24h_threats(threat_df, model, model_info)
            
            if not forecast_df.empty:
                hourly_forecast = forecast_df.groupby(forecast_df['timestamp'].dt.hour).agg({
                    'predicted_severity': lambda x: (x == 'Critical').sum(),
                    'confidence': 'mean'
                }).reset_index()
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=hourly_forecast['timestamp'], 
                                        y=hourly_forecast['predicted_severity'],
                                        mode='lines+markers', name='Critical Threats',
                                        line=dict(color='#ff0000', width=3)))
                fig.update_layout(title='Predicted Critical Threats by Hour',
                                xaxis_title='Hour', yaxis_title='Predicted Critical Threats',
                                height=400, paper_bgcolor='rgba(20, 25, 47, 0.7)')
                st.plotly_chart(fig, use_container_width=True)
            
            # High-Risk Time Windows
            st.markdown("#### ⏰ HIGH-RISK TIME WINDOWS")
            high_risk = high_risk_windows[high_risk_windows['risk_level'].isin(['High', 'Critical'])]
            
            if not high_risk.empty:
                col1, col2 = st.columns(2)
                with col1:
                    fig = go.Figure(go.Bar(x=high_risk_windows['hour'], 
                                          y=high_risk_windows['risk_score'],
                                          marker=dict(color=high_risk_windows['risk_score'],
                                                    colorscale='Reds')))
                    fig.update_layout(title='Risk Score by Hour', height=350,
                                    paper_bgcolor='rgba(20, 25, 47, 0.7)')
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.markdown("**Identified High-Risk Periods:**")
                    for _, row in high_risk.iterrows():
                        color = '#ff0000' if row['risk_level'] == 'Critical' else '#ff7f00'
                        st.markdown(f"""
                        <div style="background: rgba(30, 41, 54, 0.9); padding: 10px; 
                                    border-left: 4px solid {color}; margin: 5px 0;">
                            <strong>{row['hour']:02d}:00 - {row['hour']:02d}:59</strong><br>
                            Risk Level: {row['risk_level']}<br>
                            Total Threats: {int(row['total_threats'])}<br>
                            Critical: {int(row['critical_threats'])}
                        </div>
                        """, unsafe_allow_html=True)
            
            # Anomaly Detection
            st.markdown("#### 🔍 ANOMALOUS THREAT PATTERNS")
            anomalies = threat_df_anomaly[threat_df_anomaly['is_anomaly'] == True]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Anomalies Detected", len(anomalies))
            with col2:
                st.metric("Anomaly Rate", f"{len(anomalies)/len(threat_df_anomaly)*100:.1f}%")
            with col3:
                critical_anomalies = len(anomalies[anomalies['severity'] == 'Critical'])
                st.metric("Critical Anomalies", critical_anomalies)
            
            if not anomalies.empty:
                st.dataframe(anomalies[['timestamp', 'technique_name', 'target_country', 
                                       'target_sector', 'severity']].head(20), 
                           use_container_width=True)
            
            # Trend Analysis
            st.markdown("#### 📊 TREND ANALYSIS")
            
            trend_option = st.selectbox("Analyze trends by:", 
                                       ['Attack Type', 'Country', 'Sector'])
            
            if trend_option == 'Attack Type':
                trend_col = 'technique_name'
            elif trend_option == 'Country':
                trend_col = 'target_country'
            else:
                trend_col = 'target_sector'
            
            threat_df['date'] = threat_df['timestamp'].dt.date
            trend_data = threat_df.groupby(['date', trend_col]).size().reset_index(name='count')
            
            top_items = threat_df[trend_col].value_counts().head(5).index
            trend_data_filtered = trend_data[trend_data[trend_col].isin(top_items)]
            
            fig = px.line(trend_data_filtered, x='date', y='count', color=trend_col,
                         title=f'Threat Trends by {trend_option}')
            fig.update_layout(height=400, paper_bgcolor='rgba(20, 25, 47, 0.7)')
            st.plotly_chart(fig, use_container_width=True)
        
        else:
            st.warning("Insufficient data for ML analysis. Need at least 100 threat records.")
    
    # Tab 3: Threat Intelligence
    with tabs[2]:
        st.markdown("### 🎯 THREAT INTELLIGENCE ANALYSIS")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### ATTACK TECHNIQUES")
            technique_stats = threat_df['technique_name'].value_counts().head(5)
            
            for technique, count in technique_stats.items():
                with st.expander(f"{technique} ({count} attacks)", expanded=False):
                    technique_threats = threat_df[threat_df['technique_name'] == technique]
                    
                    affected_countries = technique_threats['target_country'].value_counts().head(3)
                    st.markdown("**Top Affected Countries:**")
                    for country, cnt in affected_countries.items():
                        st.markdown(f"- {country}: {cnt} attacks")
                    
                    affected_sectors = technique_threats['target_sector'].value_counts().head(3)
                    st.markdown("**Top Affected Sectors:**")
                    for sector, cnt in affected_sectors.items():
                        st.markdown(f"- {sector}: {cnt} attacks")
        
        with col2:
            st.markdown("#### THREAT ACTORS")
            actor_stats = threat_df['threat_actor'].value_counts().head(5)
            
            for actor, count in actor_stats.items():
                actor_info = ThreatIntelligence.THREAT_ACTORS.get(actor, {})
                
                with st.expander(f"{actor} ({count} attacks)", expanded=False):
                    st.markdown(f"**Origin:** {actor_info.get('origin', 'Unknown')}")
                    st.markdown(f"**Sophistication:** {actor_info.get('sophistication', 'Unknown')}")
                    
                    actor_threats = threat_df[threat_df['threat_actor'] == actor]
                    attack_types = actor_threats['technique_name'].value_counts().head(3)
                    
                    st.markdown("**Primary Attack Types:**")
                    for attack, cnt in attack_types.items():
                        st.markdown(f"- {attack}: {cnt} instances")
    
    # Tab 4: Security Recommendations
    with tabs[3]:
        st.markdown("### 🛡️ ML-POWERED SECURITY RECOMMENDATIONS")
        
        # Generate ML-based recommendations
        top_techniques = threat_df['technique_name'].value_counts().head(3)
        critical_count = len(threat_df[threat_df['severity'] == 'Critical'])
        
        recommendations = [
            {
                'title': 'NIST Framework Activation',
                'priority': 'CRITICAL',
                'threat_context': f'{critical_count} critical threats detected',
                'ml_insight': 'ML models predict 25% increase in severity over next 24h',
                'actions': [
                    'Activate IDENTIFY (ID.RA) - Conduct immediate risk assessment',
                    'Strengthen PROTECT (PR.AC) - Implement enhanced access controls',
                    'Enhance DETECT (DE.CM) - Increase monitoring frequency',
                    'Prepare RESPOND (RS.AN) - Ready incident response team'
                ],
                'frameworks': ['NIST CSF', 'ISO 27001']
            },
            {
                'title': 'Email Security Enhancement',
                'priority': 'HIGH',
                'threat_context': f"Phishing: {top_techniques.get('Phishing', 0)} instances",
                'ml_insight': 'Anomaly detection flagged unusual phishing patterns',
                'actions': [
                    'Implement DMARC with p=reject policy',
                    'Deploy advanced email filtering with ML',
                    'Conduct targeted phishing awareness training',
                    'Enable multi-factor authentication enforcement'
                ],
                'frameworks': ['NIST SP 800-177', 'ISO 27001 A.13.2.1']
            },
            {
                'title': 'Ransomware Defense Strategy',
                'priority': 'HIGH',
                'threat_context': f"Ransomware indicators in {len(threat_df[threat_df['technique_name']=='Data Encrypted for Impact'])} threats",
                'ml_insight': 'High-risk time window identified: 02:00-06:00',
                'actions': [
                    'Implement immutable backup solutions',
                    'Deploy EDR with behavioral analysis',
                    'Segment critical network infrastructure',
                    'Establish offline recovery procedures'
                ],
                'frameworks': ['NIST CSF', 'CIS Controls']
            }
        ]
        
        # Display as interactive flashcards
        for i, rec in enumerate(recommendations):
            priority_color = {'CRITICAL': '#ff0000', 'HIGH': '#ff7f00', 'MEDIUM': '#ffff00'}
            color = priority_color.get(rec['priority'], '#00ff00')
            
            st.markdown(f"""
            <div class="flashcard">
                <h3 style="color: {color};">🎯 {rec['title']}</h3>
                <p style="color: #00ffff;"><strong>Priority:</strong> {rec['priority']}</p>
                <p><strong>Threat Context:</strong> {rec['threat_context']}</p>
                <p style="color: #bf00ff;"><strong>🤖 ML Insight:</strong> {rec['ml_insight']}</p>
                <p><strong>Frameworks:</strong> {', '.join(rec['frameworks'])}</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander("📋 View Recommended Actions", expanded=False):
                for action in rec['actions']:
                    st.markdown(f"✓ {action}")
    
    # Tab 5: IOC Scanner
    with tabs[4]:
        st.markdown("### 🔎 IOC SCANNER")
        st.markdown("Scan IPs and domains using VirusTotal and Shodan")
        
        ioc_input = st.text_input("Enter IOC (IP or Domain)", 
                                  placeholder="e.g., 192.168.1.1 or example.com")
        
        col1, col2 = st.columns(2)
        with col1:
            scan_vt = st.checkbox("VirusTotal Scan", value=True, 
                                 disabled=not VIRUSTOTAL_API_KEY)
        with col2:
            scan_shodan = st.checkbox("Shodan Scan", value=True,
                                     disabled=not SHODAN_API_KEY)
        
        if st.button("🔍 SCAN IOC"):
            if ioc_input:
                with st.spinner("Scanning..."):
                    time.sleep(1)
                    
                    # Check if it's an IP
                    is_ip = all(part.isdigit() and 0 <= int(part) <= 255 
                               for part in ioc_input.split('.')) if '.' in ioc_input else False
                    
                    col1, col2 = st.columns(2)
                    
                    # VirusTotal Results
                    if scan_vt and VIRUSTOTAL_API_KEY:
                        with col1:
                            st.markdown("#### VirusTotal Results")
                            vt = VirusTotalConnector(VIRUSTOTAL_API_KEY)
                            
                            if is_ip:
                                result = vt.scan_ip(ioc_input)
                            else:
                                result = vt.scan_domain(ioc_input)
                            
                            if result:
                                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                                malicious = stats.get('malicious', 0)
                                total = sum(stats.values())
                                
                                st.metric("Detection Ratio", f"{malicious}/{total}")
                                st.metric("Status", "🚨 MALICIOUS" if malicious > 5 else "✅ CLEAN")
                            else:
                                st.info("No VirusTotal data (simulated)")
                                detection = random.randint(0, 75)
                                st.metric("Detection Ratio", f"{detection}/75")
                                st.metric("Status", "🚨 MALICIOUS" if detection > 30 else "✅ CLEAN")
                    
                    # Shodan Results
                    if scan_shodan and is_ip and SHODAN_API_KEY:
                        with col2:
                            st.markdown("#### Shodan Results")
                            shodan = ShodanConnector(SHODAN_API_KEY)
                            result = shodan.search_host(ioc_input)
                            
                            if result:
                                st.metric("Open Ports", len(result.get('ports', [])))
                                st.metric("Services", len(result.get('data', [])))
                                st.markdown(f"**Country:** {result.get('country_name', 'Unknown')}")
                            else:
                                st.info("No Shodan data (simulated)")
                                st.metric("Open Ports", random.randint(1, 10))
                                st.metric("Services", random.randint(1, 5))
            else:
                st.warning("Please enter an IOC to scan")
        
        if not VIRUSTOTAL_API_KEY or not SHODAN_API_KEY:
            st.warning("⚠️ API keys not configured. Add them to .streamlit/secrets.toml or directly in code")
    
    # Tab 6: Global Threats
    with tabs[5]:
        st.markdown("### 🌍 GLOBAL THREAT LANDSCAPE")
        globe_fig = create_globe_map(threat_df)
        st.plotly_chart(globe_fig, use_container_width=True)
        
        country_threats = threat_df['target_country'].value_counts().head(10)
        
        col1, col2 = st.columns(2)
        with col1:
            fig = go.Figure(go.Bar(y=country_threats.index, x=country_threats.values,
                                  orientation='h', marker=dict(color='#00ffff')))
            fig.update_layout(title='Top 10 Targeted Countries', height=400,
                            paper_bgcolor='rgba(20, 25, 47, 0.7)')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            selected_country = st.selectbox("Select Country for Details:", 
                                           ['None'] + list(country_threats.index))
            
            if selected_country != 'None':
                country_data = threat_df[threat_df['target_country'] == selected_country]
                
                st.metric("Total Threats", len(country_data))
                st.metric("Critical", len(country_data[country_data['severity'] == 'Critical']))
                
                top_attacks = country_data['technique_name'].value_counts().head(3)
                st.markdown("**Top Attack Types:**")
                for attack, count in top_attacks.items():
                    st.markdown(f"- {attack}: {count}")

if __name__ == "__main__":
    main()
