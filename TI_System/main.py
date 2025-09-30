#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform with OTX API Integration
Real-time threat feeds from AlienVault OTX with auto-updating every 5 minutes

Installation Requirements:
pip install streamlit pandas numpy plotly feedparser requests

Usage:
streamlit run main.py
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

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence Platform - TIP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# OTX API INTEGRATION
# ============================================================================

OTX_API_KEY = "a64a6fc71743dd93f98f8b91b7a611e6bd219d32a9faa11d85256b7a81e8dd89"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

class OTXConnector:
    """Connector for AlienVault OTX API"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            'X-OTX-API-KEY': api_key,
            'Content-Type': 'application/json'
        }
    
    def get_pulses_subscribed(self, limit=50, modified_since=None):
        """Get pulses from subscribed users with retry logic"""
        url = f"{OTX_BASE_URL}/pulses/subscribed"
        params = {'limit': limit}
        if modified_since:
            params['modified_since'] = modified_since
        
        # Retry up to 3 times with increasing timeout
        for attempt in range(3):
            try:
                timeout = 20 + (attempt * 10)  # 20s, 30s, 40s
                response = requests.get(url, headers=self.headers, params=params, timeout=timeout)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.Timeout:
                if attempt < 2:  # Don't show error on last attempt yet
                    continue
                st.warning(f"OTX API timeout after {attempt + 1} attempts. Using cached/alternative data.")
                return None
            except requests.exceptions.RequestException as e:
                st.error(f"OTX API error: {str(e)[:100]}")
                return None
            except Exception as e:
                st.error(f"Unexpected error: {str(e)[:100]}")
                return None
        
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
    </style>
    """, unsafe_allow_html=True)

# ============================================================================
# AUTO-UPDATE
# ============================================================================

def initialize_auto_update():
    if 'last_update' not in st.session_state:
        st.session_state.last_update = datetime.now()
    if 'auto_update_counter' not in st.session_state:
        st.session_state.auto_update_counter = 0

def check_auto_update():
    current_time = datetime.now()
    if (current_time - st.session_state.last_update).total_seconds() >= 300:
        st.session_state.last_update = current_time
        st.session_state.auto_update_counter += 1
        return True
    return False

# ============================================================================
# THREAT INTELLIGENCE MODEL
# ============================================================================

class ThreatIntelligence:
    
    ATTACK_TECHNIQUES = {
        'T1566': {'name': 'Phishing', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Fraudulent messages to trick users into revealing sensitive information'},
        'T1486': {'name': 'Ransomware', 'category': 'Impact', 'severity': 'Critical',
                  'description': 'Data encryption to interrupt availability'},
        'T1498': {'name': 'DDoS', 'category': 'Impact', 'severity': 'High',
                  'description': 'Denial of service attacks'},
        'T1190': {'name': 'Exploit', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Exploiting public-facing applications'},
        'T1059': {'name': 'Command Execution', 'category': 'Execution', 'severity': 'Medium',
                  'description': 'Abusing command interpreters'},
        'T1055': {'name': 'Process Injection', 'category': 'Defense Evasion', 'severity': 'High',
                  'description': 'Injecting code into processes'},
        'T1003': {'name': 'Credential Dumping', 'category': 'Credential Access', 'severity': 'Critical',
                  'description': 'Dumping credentials'},
        'T1071': {'name': 'C2 Protocol', 'category': 'Command and Control', 'severity': 'Medium',
                  'description': 'Application layer protocols for C2'}
    }
    
    KILL_CHAIN_PHASES = {
        'Reconnaissance': 'Gathering information',
        'Weaponization': 'Creating malicious payloads',
        'Delivery': 'Transmitting the weapon',
        'Exploitation': 'Triggering the weapon',
        'Installation': 'Installing backdoors',
        'Command & Control': 'Establishing communication',
        'Actions on Objectives': 'Achieving attack goals'
    }
    
    THREAT_ACTORS = {
        'APT28': {'origin': 'Russia', 'sophistication': 'High',
                  'description': 'Russian state-sponsored group'},
        'APT29': {'origin': 'Russia', 'sophistication': 'High',
                  'description': 'Russian SVR-linked group'},
        'Lazarus': {'origin': 'North Korea', 'sophistication': 'High',
                    'description': 'North Korean financial theft group'},
        'APT1': {'origin': 'China', 'sophistication': 'Medium',
                 'description': 'Chinese IP theft unit'},
        'FIN7': {'origin': 'Unknown', 'sophistication': 'High',
                 'description': 'Financial crime group'},
        'Sandworm': {'origin': 'Russia', 'sophistication': 'High',
                     'description': 'Critical infrastructure attacks'}
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
                'timestamp': datetime.now() - timedelta(hours=random.randint(0, 168)),
                'threat_id': f"THREAT-{random.randint(10000, 99999)}",
                'technique_id': technique_id,
                'technique_name': technique['name'],
                'technique_description': technique['description'],
                'category': technique['category'],
                'severity': technique['severity'],
                'threat_actor': actor,
                'actor_description': ThreatIntelligence.THREAT_ACTORS[actor]['description'],
                'origin_country': ThreatIntelligence.THREAT_ACTORS[actor]['origin'],
                'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                'target_sector': random.choice(ThreatIntelligence.SECTORS),
                'confidence': random.randint(60, 100),
                'kill_chain_phase': random.choice(list(ThreatIntelligence.KILL_CHAIN_PHASES.keys())),
                'malware_family': random.choice(['Emotet', 'TrickBot', 'REvil', 'Conti']),
                'detection_source': 'Internal SOC',
                'blocked': is_blocked,
                'active': not is_blocked,
                'ioc_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'ioc_domain': f"malicious-{random.randint(100,999)}.com",
                'mitigation': 'Blocked' if is_blocked else 'ACTION REQUIRED'
            })
        return pd.DataFrame(threat_events)

# ============================================================================
# OTX DATA FETCHING
# ============================================================================

@st.cache_data(ttl=300)
def fetch_otx_data():
    """Fetch real threat data from OTX with better error handling"""
    
    # Show loading indicator
    progress_text = st.empty()
    progress_text.info("🔄 Connecting to OTX API...")
    
    otx = OTXConnector(OTX_API_KEY)
    
    # Try to fetch pulses
    pulses_data = otx.get_pulses_subscribed(limit=50)  # Reduced from 100 for faster response
    
    threat_events = []
    
    if pulses_data and 'results' in pulses_data:
        progress_text.success(f"✅ Retrieved {len(pulses_data['results'])} pulses from OTX")
        
        for pulse in pulses_data['results']:
            try:
                pulse_id = pulse.get('id', '')
                name = pulse.get('name', 'Unknown')
                description = pulse.get('description', '')
                modified = pulse.get('modified', datetime.now().isoformat())
                tags = pulse.get('tags', [])
                tlp = pulse.get('TLP', 'white')
                
                severity = 'Critical' if tlp == 'red' else 'High' if tlp == 'amber' else 'Medium'
                
                technique_mapping = {
                    'phishing': 'T1566', 'ransomware': 'T1486', 'ddos': 'T1498',
                    'exploit': 'T1190', 'malware': 'T1059', 'trojan': 'T1055',
                    'credential': 'T1003', 'c2': 'T1071'
                }
                
                technique_id = 'T1566'
                for keyword, tid in technique_mapping.items():
                    if keyword in name.lower() or keyword in description.lower():
                        technique_id = tid
                        break
                
                target_country = 'USA'
                for country in ThreatIntelligence.COUNTRIES.keys():
                    if country.lower() in ' '.join(tags).lower():
                        target_country = country
                        break
                
                target_sector = random.choice(ThreatIntelligence.SECTORS)
                threat_actor = random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys()))
                
                indicators = pulse.get('indicators', [])
                num_indicators = len(indicators)
                
                ioc_ip = ''
                ioc_domain = ''
                for ind in indicators[:5]:
                    if ind.get('type') == 'IPv4' and not ioc_ip:
                        ioc_ip = ind.get('indicator', '')
                    elif ind.get('type') in ['domain', 'hostname'] and not ioc_domain:
                        ioc_domain = ind.get('indicator', '')
                
                if not ioc_ip:
                    ioc_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                if not ioc_domain:
                    ioc_domain = f"threat-{pulse_id[:8]}.com"
                
                is_blocked = num_indicators > 5 or severity == 'Medium'
                
                threat_events.append({
                    'timestamp': pd.to_datetime(modified),
                    'threat_id': f"OTX-{pulse_id}",
                    'technique_id': technique_id,
                    'technique_name': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['name'],
                    'technique_description': description[:200] if description else ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['description'],
                    'category': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['category'],
                    'severity': severity,
                    'threat_actor': threat_actor,
                    'actor_description': ThreatIntelligence.THREAT_ACTORS[threat_actor]['description'],
                    'origin_country': ThreatIntelligence.THREAT_ACTORS[threat_actor]['origin'],
                    'target_country': target_country,
                    'target_sector': target_sector,
                    'confidence': min(100, 60 + num_indicators * 2),
                    'kill_chain_phase': random.choice(list(ThreatIntelligence.KILL_CHAIN_PHASES.keys())),
                    'malware_family': tags[0] if tags else 'Unknown',
                    'detection_source': 'OTX AlienVault',
                    'blocked': is_blocked,
                    'active': not is_blocked,
                    'ioc_ip': ioc_ip,
                    'ioc_domain': ioc_domain,
                    'mitigation': 'Blocked' if is_blocked else 'ACTION REQUIRED'
                })
            except Exception as e:
                continue
        
        progress_text.empty()
    else:
        progress_text.warning("⚠️ OTX API unavailable - using alternative feeds")
        time.sleep(2)
        progress_text.empty()
    
    return pd.DataFrame(threat_events) if threat_events else pd.DataFrame()

@st.cache_data(ttl=600)
def fetch_rss_feeds():
    """Fetch RSS feeds"""
    feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Hacker News": "https://hnrss.org/frontpage"
    }
    
    all_articles = []
    for source, url in feeds.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:10]:
                pub_date = entry.get('published_parsed')
                timestamp = datetime(*pub_date[:6]) if pub_date else datetime.now()
                
                all_articles.append({
                    'timestamp': timestamp,
                    'threat_id': hashlib.md5(entry.get('link', '').encode()).hexdigest()[:16],
                    'technique_id': 'T1566',
                    'technique_name': "News",
                    'technique_description': entry.get('title', 'Security News')[:200],
                    'category': "Information",
                    'severity': "Info",
                    'threat_actor': 'N/A',
                    'actor_description': 'News source',
                    'origin_country': 'Unknown',
                    'target_country': 'USA',
                    'target_sector': 'Technology',
                    'confidence': 70,
                    'kill_chain_phase': 'Reconnaissance',
                    'malware_family': 'News',
                    'detection_source': source,
                    'blocked': True,
                    'active': False,
                    'ioc_ip': '0.0.0.0',
                    'ioc_domain': source,
                    'mitigation': 'Information only'
                })
        except:
            continue
            
    return pd.DataFrame(all_articles)

def generate_data():
    """Fetch threat intelligence with fallback options"""
    df_otx = fetch_otx_data()
    df_rss = fetch_rss_feeds()
    
    if not df_otx.empty:
        df_combined = pd.concat([df_otx, df_rss], ignore_index=True)
        return df_combined
    elif not df_rss.empty:
        # OTX failed but RSS succeeded
        return df_rss
    else:
        # Both external sources failed, generate sample data
        st.info("📊 Generating sample threat data for demonstration")
        return ThreatIntelligence.generate_threat_feed(100)

# ============================================================================
# VISUALIZATIONS
# ============================================================================

def create_globe_map(threat_df):
    """Create 3D globe"""
    country_threats = threat_df.groupby('target_country').agg({
        'threat_id': 'count',
        'severity': lambda x: (x == 'Critical').sum()
    }).reset_index()
    country_threats.columns = ['country', 'total', 'critical']
    
    globe_data = []
    for country, coords in ThreatIntelligence.COUNTRIES.items():
        country_data = country_threats[country_threats['country'] == country]
        if not country_data.empty:
            globe_data.append({
                'lat': coords['lat'],
                'lon': coords['lon'],
                'country': country,
                'total': country_data['total'].values[0],
                'critical': country_data['critical'].values[0],
                'text': f"{country}<br>Threats: {country_data['total'].values[0]}"
            })
    
    if not globe_data:
        return go.Figure()
    
    globe_df = pd.DataFrame(globe_data)
    
    fig = go.Figure(go.Scattergeo(
        lon=globe_df['lon'],
        lat=globe_df['lat'],
        text=globe_df['text'],
        mode='markers',
        marker=dict(
            size=globe_df['total'] / 5,
            color=globe_df['critical'],
            colorscale=[[0, '#00ff00'], [1, '#ff0000']],
            showscale=False,
            line=dict(width=1, color='#00ffff')
        ),
        hoverinfo='text'
    ))
    
    fig.update_layout(
        geo=dict(
            projection_type='orthographic',
            showland=True,
            landcolor='rgba(30, 35, 57, 0.9)',
            coastlinecolor='#00ffff',
            oceancolor='rgba(10, 14, 39, 0.95)',
            bgcolor='rgba(20, 25, 47, 0.1)'
        ),
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=500,
        title='Global Threat Map',
        margin=dict(l=0, r=0, t=50, b=0)
    )
    
    return fig

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    apply_futuristic_theme()
    initialize_auto_update()
    
    # Initialize data
    if 'threat_data' not in st.session_state:
        with st.spinner("Connecting to threat intelligence sources..."):
            st.session_state.threat_data = generate_data()
    
    # Auto-update check
    if check_auto_update():
        new_data = generate_data()
        if not new_data.empty:
            st.session_state.threat_data = pd.concat([new_data, st.session_state.threat_data]).reset_index(drop=True)
            st.session_state.threat_data = st.session_state.threat_data.head(1000)
    
    # Calculate time until next update
    seconds_since = (datetime.now() - st.session_state.last_update).total_seconds()
    seconds_until = 300 - seconds_since
    minutes_until = int(seconds_until // 60)
    seconds_remainder = int(seconds_until % 60)
    
    # Header
    st.markdown(f"""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                border-radius: 20px; border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;">
        <h1>THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8; font-size: 1.1em;">
            REAL-TIME OTX INTEGRATION • AUTO-UPDATING EVERY 5 MINUTES
        </p>
        <p style="color: #00ff00; font-size: 0.9em;">
            🟢 Next Update: {minutes_until}m {seconds_remainder}s
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar Filters
    with st.sidebar:
        st.markdown("### ⚙️ FILTERS")
        
        time_range = st.selectbox(
            "Time Range",
            ['Last 24 Hours', 'Last 7 Days', 'Last 30 Days'],
            index=1
        )
        
        time_map = {
            'Last 24 Hours': timedelta(days=1),
            'Last 7 Days': timedelta(days=7),
            'Last 30 Days': timedelta(days=30)
        }
        
        time_cutoff = datetime.now() - time_map[time_range]
        
        severity_filter = st.multiselect(
            "Severity",
            ['Critical', 'High', 'Medium', 'Low', 'Info'],
            default=['Critical', 'High', 'Medium', 'Low', 'Info']
        )
        
        if st.button("🔄 APPLY FILTERS", use_container_width=True):
            st.rerun()
    
    # Apply filters
    threat_df = st.session_state.threat_data.copy()
    threat_df = threat_df[threat_df['timestamp'] > time_cutoff]
    threat_df = threat_df[threat_df['severity'].isin(severity_filter)]
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_threats = len(threat_df)
    critical_threats = len(threat_df[threat_df['severity'] == 'Critical'])
    active_threats = len(threat_df[threat_df['active'] == True])
    blocked_threats = len(threat_df[threat_df['blocked'] == True])
    
    with col1:
        st.metric("Total Threats", f"{total_threats:,}")
    with col2:
        st.metric("Critical", critical_threats)
    with col3:
        st.metric("Active", active_threats)
    with col4:
        block_rate = (blocked_threats / total_threats * 100) if total_threats > 0 else 0
        st.metric("Block Rate", f"{block_rate:.1f}%")
    
    # Tabs
    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🌍 Global Map", "📋 Threat Details"])
    
    with tab1:
        st.markdown("### 📈 THREAT TRENDS")
        
        # Attack types distribution
        if not threat_df.empty:
            attack_dist = threat_df['technique_name'].value_counts()
            
            fig = go.Figure(go.Bar(
                x=attack_dist.values,
                y=attack_dist.index,
                orientation='h',
                marker=dict(color='#00ffff')
            ))
            
            fig.update_layout(
                title='Top Attack Types',
                plot_bgcolor='rgba(20, 25, 47, 0.1)',
                paper_bgcolor='rgba(20, 25, 47, 0.7)',
                font=dict(color='#b8bcc8'),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("### 🌍 GLOBAL THREAT DISTRIBUTION")
        if not threat_df.empty:
            globe_fig = create_globe_map(threat_df)
            st.plotly_chart(globe_fig, use_container_width=True)
        else:
            st.info("No threat data available")
    
    with tab3:
        st.markdown("### 📋 RECENT THREATS")
        if not threat_df.empty:
            display_df = threat_df[['timestamp', 'threat_id', 'technique_name', 
                                   'severity', 'target_country', 'detection_source']].head(50)
            st.dataframe(display_df, use_container_width=True, height=400)
        else:
            st.info("No threat data available")

if __name__ == "__main__":
    main()
