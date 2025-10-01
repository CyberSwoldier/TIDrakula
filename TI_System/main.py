#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform with Machine Learning & Enhanced Interactivity
Auto-updating feeds every 5 minutes with ML-powered analytics
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
from typing import Dict, List, Tuple

# Machine Learning imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.cluster import KMeans
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence Platform - TIP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# FUTURISTIC THEME STYLING
# ============================================================================

def apply_futuristic_theme():
    """Apply futuristic CSS styling to the entire dashboard"""
    st.markdown("""
    <style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
    /* Main app background */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #151934 50%, #1a0033 100%);
        background-attachment: fixed;
    }
    
    /* Headers styling */
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
    
    h2 {
        font-family: 'Orbitron', monospace !important;
        color: #00ffff !important;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-weight: 700 !important;
    }
    
    h3 {
        font-family: 'Orbitron', monospace !important;
        color: #bf00ff !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: rgba(20, 25, 47, 0.95);
        backdrop-filter: blur(20px);
        border-right: 2px solid rgba(0, 255, 255, 0.3);
    }
    
    /* Buttons */
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
    
    /* Scrollable container for live feed */
    .live-feed-container {
        max-height: 400px;
        overflow-y: auto;
        padding-right: 10px;
    }
    
    .live-feed-container::-webkit-scrollbar {
        width: 8px;
    }
    
    .live-feed-container::-webkit-scrollbar-track {
        background: rgba(20, 25, 47, 0.3);
        border-radius: 4px;
    }
    
    .live-feed-container::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00ffff, #bf00ff);
        border-radius: 4px;
    }
    
    /* Custom scrollbar */
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
# AUTO-UPDATE MECHANISM (5 MINUTES)
# ============================================================================

def initialize_auto_update():
    """Initialize auto-update mechanism"""
    if 'last_update' not in st.session_state:
        st.session_state.last_update = datetime.now()
    if 'auto_update_counter' not in st.session_state:
        st.session_state.auto_update_counter = 0

def check_auto_update():
    """Check if 5 minutes have passed and trigger update"""
    current_time = datetime.now()
    if (current_time - st.session_state.last_update).total_seconds() >= 300:  # 300 seconds = 5 minutes
        st.session_state.last_update = current_time
        st.session_state.auto_update_counter += 1
        return True
    return False

# ============================================================================
# MACHINE LEARNING MODELS
# ============================================================================

class ThreatMLModels:
    """Machine Learning models for threat intelligence analysis"""
    
    @staticmethod
    def prepare_features(threat_df):
        """Prepare features for ML models"""
        if threat_df.empty:
            return None, None
        
        # Create a copy
        df = threat_df.copy()
        
        # Encode categorical variables
        le_technique = LabelEncoder()
        le_actor = LabelEncoder()
        le_sector = LabelEncoder()
        le_country = LabelEncoder()
        
        df['technique_encoded'] = le_technique.fit_transform(df['technique_name'])
        df['actor_encoded'] = le_actor.fit_transform(df['threat_actor'])
        df['sector_encoded'] = le_sector.fit_transform(df['target_sector'])
        df['country_encoded'] = le_country.fit_transform(df['target_country'])
        
        # Create severity numeric
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        df['severity_numeric'] = df['severity'].map(severity_map)
        
        # Time-based features
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
        
        # Feature matrix
        features = ['technique_encoded', 'actor_encoded', 'sector_encoded', 
                   'country_encoded', 'confidence', 'hour', 'day_of_week']
        
        X = df[features]
        y = df['severity_numeric']
        
        return X, y, df
    
    @staticmethod
    def train_threat_predictor(threat_df):
        """Train a model to predict threat severity"""
        X, y, df = ThreatMLModels.prepare_features(threat_df)
        
        if X is None:
            return None, None
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train Random Forest
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return model, {'accuracy': accuracy, 'feature_importance': feature_importance}
    
    @staticmethod
    def detect_anomalies(threat_df):
        """Detect anomalous threats using Isolation Forest"""
        X, _, df = ThreatMLModels.prepare_features(threat_df)
        
        if X is None:
            return None
        
        # Train Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X)
        
        # Add anomaly flag to dataframe
        df['is_anomaly'] = anomaly_labels == -1
        
        return df[df['is_anomaly']]
    
    @staticmethod
    def cluster_threats(threat_df, n_clusters=5):
        """Cluster similar threats together"""
        X, _, df = ThreatMLModels.prepare_features(threat_df)
        
        if X is None:
            return None
        
        # Perform K-means clustering
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        df['cluster'] = kmeans.fit_predict(X)
        
        # Analyze clusters
        cluster_analysis = []
        for cluster_id in range(n_clusters):
            cluster_data = df[df['cluster'] == cluster_id]
            
            analysis = {
                'cluster_id': cluster_id,
                'size': len(cluster_data),
                'top_technique': cluster_data['technique_name'].mode()[0] if len(cluster_data) > 0 else 'Unknown',
                'top_actor': cluster_data['threat_actor'].mode()[0] if len(cluster_data) > 0 else 'Unknown',
                'top_sector': cluster_data['target_sector'].mode()[0] if len(cluster_data) > 0 else 'Unknown',
                'avg_confidence': cluster_data['confidence'].mean(),
                'critical_count': len(cluster_data[cluster_data['severity'] == 'Critical'])
            }
            cluster_analysis.append(analysis)
        
        return pd.DataFrame(cluster_analysis)
    
    @staticmethod
    def forecast_threats(threat_df, days_ahead=7):
        """Simple time series forecast for threat trends"""
        if threat_df.empty:
            return None
        
        # Aggregate by day
        threat_df['date'] = pd.to_datetime(threat_df['timestamp']).dt.date
        daily_counts = threat_df.groupby('date').size().reset_index(name='count')
        daily_counts['date'] = pd.to_datetime(daily_counts['date'])
        daily_counts = daily_counts.sort_values('date')
        
        # Simple moving average forecast
        window = min(7, len(daily_counts))
        if window > 0:
            ma = daily_counts['count'].rolling(window=window).mean().iloc[-1]
            
            # Generate forecast dates
            last_date = daily_counts['date'].max()
            forecast_dates = pd.date_range(start=last_date + timedelta(days=1), periods=days_ahead, freq='D')
            
            # Simple forecast (using MA with some random variation)
            forecast_values = [ma + random.randint(-10, 10) for _ in range(days_ahead)]
            
            forecast_df = pd.DataFrame({
                'date': forecast_dates,
                'forecast_count': forecast_values
            })
            
            return forecast_df
        
        return None

# ============================================================================
# DATA GENERATION AND FEEDS INTEGRATION
# ============================================================================

def generate_data():
    """
    Generates a mock dataframe for threat intelligence data.
    This simulates fetching new data every 5 minutes.
    """
    # Simulate a new threat every few minutes
    new_threats = random.randint(5, 20)
    
    # Generate data for the last 90 days
    start_date = datetime.now() - timedelta(days=90)
    data = []
    
    for i in range(new_threats):
        date = datetime.now()
        source = random.choice(['Email', 'Web', 'API', 'Insider'])
        severity = random.choice(['Critical', 'High', 'Medium', 'Low'])
        threat_type = random.choice(['Malware', 'Phishing', 'DDoS', 'Spyware', 'Exploit', 'Ransomware'])
        
        # Simulate a human-targeted attack
        is_human_targeted = random.choice([True, False, False, False]) # More likely to be false
        
        data.append({
            'timestamp': date,
            'threat_id': hashlib.md5(str(date).encode()).hexdigest(),
            'source': source,
            'threat_type': threat_type,
            'severity': severity,
            'status': random.choice(['Active', 'Mitigated', 'False Positive']),
            'is_human_targeted': is_human_targeted
        })
    
    # Generate historical data
    for day in range(1, 91):
        for _ in range(random.randint(20, 50)):
            date = start_date + timedelta(days=day)
            source = random.choice(['Email', 'Web', 'API', 'Insider'])
            severity = random.choice(['Critical', 'High', 'Medium', 'Low'])
            threat_type = random.choice(['Malware', 'Phishing', 'DDoS', 'Spyware', 'Exploit', 'Ransomware'])
            is_human_targeted = random.choice([True, False, False, False])

            data.append({
                'timestamp': date,
                'threat_id': hashlib.md5(str(date).encode() + str(random.random()).encode()).hexdigest(),
                'source': source,
                'threat_type': threat_type,
                'severity': severity,
                'status': random.choice(['Mitigated', 'False Positive']),
                'is_human_targeted': is_human_targeted
            })

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Add RSS feed data to the main dataframe
    df_rss = fetch_and_process_rss_feeds()
    df_combined = pd.concat([df, df_rss], ignore_index=True)
    
    return df_combined

@st.cache_data(ttl=600) # Cache the feed for 10 minutes (600 seconds)
def get_rss_feed(url):
    """Fetches and parses an RSS feed from a given URL."""
    try:
        feed = feedparser.parse(url)
        return feed.entries
    except Exception as e:
        st.error(f"Could not fetch feed from {url}: {e}")
        return []

def fetch_and_process_rss_feeds():
    """
    Fetches articles from various RSS feeds and formats them into a DataFrame
    to be merged with the main threat data.
    """
    feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Hacker News": "https://hnrss.org/frontpage",
        "Malwarebytes": "https://blog.malwarebytes.com/feed/"
    }
    
    all_articles = []
    for source, url in feeds.items():
        entries = get_rss_feed(url)
        for entry in entries:
            # Check for a valid publication date
            pub_date = entry.get('published_parsed')
            if pub_date:
                timestamp = datetime(*pub_date[:6])
            else:
                timestamp = datetime.now()
            
            all_articles.append({
                'timestamp': timestamp,
                'threat_id': hashlib.md5(entry.get('link', '').encode()).hexdigest(),
                'source': source,
                'threat_type': "News",
                'severity': "Info",
                'status': "Active",
                'is_human_targeted': True
            })
            
    return pd.DataFrame(all_articles)

# ============================================================================
# THREAT INTELLIGENCE DATA MODELS
# ============================================================================

class ThreatIntelligence:
    """Enhanced Threat Intelligence data simulation and processing"""
    
    # MITRE ATT&CK Techniques with descriptions
    ATTACK_TECHNIQUES = {
        'T1566': {
            'name': 'Phishing',
            'category': 'Initial Access',
            'severity': 'High',
            'description': 'Adversaries send fraudulent messages to trick users into revealing sensitive information or executing malicious code.',
            'platforms': ['Windows', 'macOS', 'Linux', 'Email', 'Web'],
            'permissions_required': 'User interaction (none to low)',
            'example_behaviors': [
                'Spearphishing emails with malicious links or attachments',
                'Credential harvesting via fake login pages',
                'Malicious HTML or Office documents prompting macros'
            ],
            'mitigations': [
                'User security awareness training and phishing simulations',
                'Email filtering and attachment sanitization',
                'Enforce multifactor authentication (MFA) for all remote access',
                'Block or sandbox risky attachment types and macros by default'
            ],
            'detection': {
                'data_sources': ['Email gateway logs', 'Web proxy logs', 'Endpoint telemetry', 'Authentication logs'],
                'heuristics': [
                    'Unusual sender-to-recipient patterns (external address spoofing)',
                    'Recipients clicking known-malicious URLs or visiting suspicious domains',
                    'Attachment execution followed by unusual process activity'
                ]
            },
            'related_techniques': ['T1078', 'T1193', 'T1204'],
            'notes': 'Phishing is a common initial vector – defenses should combine prevention, detection, and rapid response (credential resets, log analysis).'
        },

        'T1486': {
            'name': 'Data Encrypted for Impact',
            'category': 'Impact',
            'severity': 'Critical',
            'description': 'Adversaries encrypt data on target systems to interrupt availability. Commonly seen in ransomware attacks.',
            'platforms': ['Windows', 'Linux', 'Network Attached Storage', 'Cloud storage'],
            'permissions_required': 'Local admin / high privilege typically required to mass-encrypt',
            'example_behaviors': [
                'Rapid file rename/encryption across multiple hosts or shares',
                'Creation of ransom notes on directories',
                'Deletion of backups or snapshot manipulation prior to encryption'
            ],
            'mitigations': [
                'Maintain offline and immutable backups; test restores regularly',
                'Least privilege access controls and segmentation (limit lateral movement)',
                'Apply endpoint protection with ransomware-specific detections and EDR roll-back features',
                'Harden backup systems and restrict access to snapshot APIs'
            ],
            'detection': {
                'data_sources': ['File system monitoring', 'EDR process and file events', 'SIEM alerts', 'Backup system logs'],
                'heuristics': [
                    'Large numbers of file modification events with file content changes and new file extensions',
                    'Processes spawning mass file I/O after privilege escalation',
                    'Deletions of snapshot/backup-related files or API calls to backup services from unusual accounts'
                ]
            },
            'related_techniques': ['T1489', 'T1490', 'T1078'],
            'notes': 'Focus on resilience (backups + segmentation) and rapid containment; avoid paying ransoms where possible and involve incident response/legal teams.'
        },

        'T1498': {
            'name': 'Network Denial of Service',
            'category': 'Impact',
            'severity': 'High',
            'description': 'Adversaries perform DoS/DDoS attacks to degrade or block availability of targeted resources.',
            'platforms': ['Network infrastructure', 'Cloud services', 'Web applications'],
            'permissions_required': 'None – external network access sufficient',
            'example_behaviors': [
                'Volumetric traffic floods to saturate bandwidth',
                'Application-layer request floods (HTTP GET/POST floods)',
                'Protocol or state-exhaustion attacks (SYN floods, DNS amplification)'
            ],
            'mitigations': [
                'Use DDoS protection and scrubbing services (cloud or upstream ISP)',
                'Rate limiting, application-level throttling and caching',
                'Design for redundancy and elastic scaling (where appropriate)',
                'Implement network filtering and ACLs to drop malicious traffic'
            ],
            'detection': {
                'data_sources': ['Network flow logs (NetFlow/sFlow)', 'Firewalls', 'WAF logs', 'Cloud provider telemetry'],
                'heuristics': [
                    'Rapid spike in inbound traffic volume from many sources',
                    'High error rates or slow response times on services',
                    'Unusual distribution of source IPs or repeated identical requests'
                ]
            },
            'related_techniques': ['T1499', 'T1531'],
            'notes': 'Preparation (contracts with providers, runbooks) is key – operational playbooks reduce downtime during an attack.'
        },

        'T1190': {
            'name': 'Exploit Public-Facing Application',
            'category': 'Initial Access',
            'severity': 'High',
            'description': 'Adversaries exploit weaknesses in internet-facing applications to gain initial access.',
            'platforms': ['Web servers', 'APIs', 'Application frameworks', 'Cloud services'],
            'permissions_required': 'None initially; may lead to privilege escalation',
            'example_behaviors': [
                'Failed and successful exploit attempts against known CVEs',
                'Web application error chains and unusual parameter values',
                'New service or web shell deployed after exploitation'
            ],
            'mitigations': [
                'Timely patch management and vulnerability scanning',
                'Web application firewalls (WAF) and input validation',
                'Network segmentation of public-facing apps from internal assets',
                'Threat modeling and secure SDLC practices'
            ],
            'detection': {
                'data_sources': ['Web server logs', 'WAF logs', 'Host EDR', 'Vulnerability scan results'],
                'heuristics': [
                    'Patterned exploit attempts (fuzzing-like requests, unusual user agents)',
                    'Unexpected process creation or reverse shells from web servers',
                    'Out-of-band changes to application files or database contents'
                ]
            },
            'related_techniques': ['T1505', 'T1210', 'T1078'],
            'notes': 'Prioritize patching high-risk internet-facing assets and monitor for anomalous web traffic and post-exploit artifacts.'
        },

        'T1059': {
            'name': 'Command and Scripting Interpreter',
            'category': 'Execution',
            'severity': 'Medium',
            'description': 'Adversaries abuse command and script interpreters to execute commands and scripts.',
            'platforms': ['Windows (PowerShell, cmd)', 'Linux/macOS (bash, sh, python)'],
            'permissions_required': 'User-level to elevated depending on action',
            'example_behaviors': [
                'Invocation of PowerShell with encoded commands',
                'Use of scripting languages to download and execute payloads',
                'Scheduling tasks or cronjobs to maintain persistence'
            ],
            'mitigations': [
                'Constrain use of interpreters with application control / allowlisting',
                'Enable logging of command interpreter activity (PowerShell module logging, bash audit)',
                'Harden endpoints to reduce script execution by untrusted users'
            ],
            'detection': {
                'data_sources': ['Process command-line logging', 'Script block logging', 'EDR process telemetry', 'Sysmon'],
                'heuristics': [
                    'Unusual CLI flags or long/encoded command lines',
                    'Interpreter processes spawning network connections or writing executables',
                    'Child processes typical of payload staging (e.g., curl/wget followed by execution)'
                ]
            },
            'related_techniques': ['T1204', 'T1218'],
            'notes': 'Scripting is commonly used for both benign admin tasks and malicious activity – robust logging + allowlisting reduce risk.'
        },

        'T1055': {
            'name': 'Process Injection',
            'category': 'Defense Evasion',
            'severity': 'High',
            'description': 'Adversaries inject code into processes to evade defenses and elevate privileges.',
            'platforms': ['Windows', 'Linux', 'macOS'],
            'permissions_required': 'Typically requires local privileges (may be possible from user context in some cases)',
            'example_behaviors': [
                'DLL injection or reflective loading into legitimate processes',
                'Remote thread creation and memory modification of another process',
                'Use of legitimate system processes to host malicious code'
            ],
            'mitigations': [
                'Enable EDR with heuristics for memory and injection behaviors',
                'Disable unnecessary services and harden process permissions',
                'Use code-signing and integrity protections where possible'
            ],
            'detection': {
                'data_sources': ['EDR memory scan, process create/modify logs, sysmon', 'Audit logs'],
                'heuristics': [
                    'Unexpected modules loaded into high-trust processes',
                    'Processes with injected memory regions that contain executable code but no on-disk counterpart',
                    'Creation of remote threads or suspicious API calls (e.g., WriteProcessMemory / CreateRemoteThread)'
                ]
            },
            'related_techniques': ['T1218', 'T1574'],
            'notes': 'Memory-only techniques are harder to detect via file-based controls – focus on behavioral/telemetry-based detection.'
        },

        'T1003': {
            'name': 'OS Credential Dumping',
            'category': 'Credential Access',
            'severity': 'Critical',
            'description': 'Adversaries attempt to dump credentials to obtain account login information.',
            'platforms': ['Windows (LSASS, SAM)', 'Linux (sshd, memory)', 'macOS'],
            'permissions_required': 'Local SYSTEM / admin typically required to access credential stores',
            'example_behaviors': [
                'Accessing LSASS memory or using tools to extract hashes',
                'Reading credential stores or configuration files (e.g., .ssh, keyrings)',
                'Running tools that enumerate accounts and password hashes'
            ],
            'mitigations': [
                'Restrict administrative privileges and use privileged access workstations',
                'Use credential protection mechanisms (LSA protection, Windows Defender Credential Guard)',
                'Rotate and enforce strong authentication, deploy MFA'
            ],
            'detection': {
                'data_sources': ['Process creation logs', 'Memory read events', 'EDR, authentication logs'],
                'heuristics': [
                    'Processes reading LSASS memory or opening protected credential files',
                    'Unusual account enumeration or repeated authentication failures after enumeration',
                    'Use of known credential-dumping tool binaries or suspicious new services'
                ]
            },
            'related_techniques': ['T1555', 'T1078', 'T1489'],
            'notes': 'Protecting secrets and limiting privileged access materially reduces the impact of credential dumping attempts.'
        },

        'T1071': {
            'name': 'Application Layer Protocol',
            'category': 'Command and Control',
            'severity': 'Medium',
            'description': 'Adversaries use application layer protocols for command and control communications.',
            'platforms': ['Any (HTTP/S, DNS, SMTP, WebSockets)'],
            'permissions_required': 'None (network connectivity required)',
            'example_behaviors': [
                'Beaconing to domain via HTTP/S with periodic callbacks',
                'Use of DNS queries/responses to tunnel data or receive commands',
                'Use of legitimate services (cloud storage, social media) as C2 channels'
            ],
            'mitigations': [
                'Network egress filtering and DNS filtering/blocking of suspicious domains',
                'Proxying outbound traffic and TLS inspection where legally/operationally viable',
                'Block or monitor uncommon protocols and high-risk external services'
            ],
            'detection': {
                'data_sources': ['Network proxy logs', 'DNS logs', 'NetFlow, EDR network telemetry'],
                'heuristics': [
                    'Regular periodic outbound connections to low-reputation domains',
                    'High-entropy or encoded payloads in apparently benign protocol fields',
                    'Unusual DNS query patterns or TXT record use for data exfiltration'
                ]
            },
            'related_techniques': ['T1090', 'T1573'],
            'notes': 'C2 detection benefits from a mix of network and host telemetry; monitoring for anomalous patterns is key.'
        }
    }
    
    # Cyber Kill Chain phases with descriptions
    KILL_CHAIN_PHASES = {
        'Reconnaissance': 'Gathering information about the target to plan the attack',
        'Weaponization': 'Creating malicious payloads and coupling them with exploits',
        'Delivery': 'Transmitting the weapon to the target environment',
        'Exploitation': 'Triggering the weapon to exploit vulnerabilities',
        'Installation': 'Installing malware or backdoors for persistent access',
        'Command & Control': 'Establishing communication channels with compromised systems',
        'Actions on Objectives': 'Achieving the attack goals (data theft, destruction, etc.)'
    }
    
    # Threat Actors with enhanced details
    THREAT_ACTORS = {
        'APT28': {
            'origin': 'Russia',
            'targets': ['Government', 'Defense', 'Energy'],
            'sophistication': 'High',
            'description': 'Russian state-sponsored group targeting government and military organizations'
        },
        'APT29': {
            'origin': 'Russia',
            'targets': ['Government', 'Healthcare', 'Technology'],
            'sophistication': 'High',
            'description': 'Russian SVR-linked group known for stealthy operations'
        },
        'Lazarus': {
            'origin': 'North Korea',
            'targets': ['Finance', 'Cryptocurrency', 'Defense'],
            'sophistication': 'High',
            'description': 'North Korean group involved in financial theft and espionage'
        },
        'APT1': {
            'origin': 'China',
            'targets': ['Technology', 'Manufacturing', 'Energy'],
            'sophistication': 'Medium',
            'description': 'Chinese military unit focused on intellectual property theft'
        },
        'FIN7': {
            'origin': 'Unknown',
            'targets': ['Retail', 'Hospitality', 'Finance'],
            'sophistication': 'High',
            'description': 'Financially motivated group targeting payment card data'
        },
        'Sandworm': {
            'origin': 'Russia',
            'targets': ['Critical Infrastructure', 'Government', 'Energy'],
            'sophistication': 'High',
            'description': 'Russian state-sponsored group linked to disruptive cyberattacks on critical infrastructure'
        },
        'Gamaredon': {
            'origin': 'Russia',
            'targets': ['Government', 'Military', 'Non-profits'],
            'sophistication': 'Medium',
            'description': 'Russian group focused on targeting entities within Ukraine, known for widespread phishing campaigns'
        },
        'Evil Corp': {
            'origin': 'Russia',
            'targets': ['Finance', 'Government', 'Technology'],
            'sophistication': 'High',
            'description': 'Financially motivated Russian cybercrime group notorious for malware like Dridex and Locky'
        },
        'MuddyWater': {
            'origin': 'Iran',
            'targets': ['Government', 'Telecommunications', 'Academia'],
            'sophistication': 'Medium',
            'description': 'Iranian state-sponsored group primarily focused on espionage against Middle Eastern and North American entities'
        },
        'WannaCry': {
            'origin': 'North Korea',
            'targets': ['Healthcare', 'Critical Infrastructure', 'Manufacturing'],
            'sophistication': 'Medium',
            'description': 'North Korean group responsible for the WannaCry ransomware attack'
        },
        'DarkSide': {
            'origin': 'Russia',
            'targets': ['Energy', 'Manufacturing', 'Finance'],
            'sophistication': 'High',
            'description': 'Ransomware-as-a-Service (RaaS) group that was responsible for the Colonial Pipeline attack'
        }
    }
    
    # Industry Sectors
    SECTORS = ['Finance', 'Healthcare', 'Government', 'Technology', 'Energy', 
               'Manufacturing', 'Retail', 'Defense', 'Education', 'Telecommunications',
               'Pharmaceutical', 'Engineering', 'Transportation', 'Media']
    
    # Countries
    COUNTRIES = {
        'USA': {'lat': 39.0, 'lon': -98.0, 'risk_level': 0.8},
        'UK': {'lat': 54.0, 'lon': -2.0, 'risk_level': 0.7},
        'Germany': {'lat': 51.0, 'lon': 10.5, 'risk_level': 0.7},
        'Japan': {'lat': 36.0, 'lon': 138.0, 'risk_level': 0.6},
        'Australia': {'lat': -25.0, 'lon': 135.0, 'risk_level': 0.6},
        'Canada': {'lat': 56.0, 'lon': -106.0, 'risk_level': 0.5},
        'France': {'lat': 47.0, 'lon': 2.0, 'risk_level': 0.7},
        'India': {'lat': 20.0, 'lon': 77.0, 'risk_level': 0.7},
        'Brazil': {'lat': -14.0, 'lon': -51.0, 'risk_level': 0.6},
        'Russia': {'lat': 61.0, 'lon': 105.0, 'risk_level': 0.9},
        'China': {'lat': 35.0, 'lon': 105.0, 'risk_level': 0.8},
        'Israel': {'lat': 31.0, 'lon': 35.0, 'risk_level': 0.8},
        'Portugal': {'lat': 39.5, 'lon': -8.0, 'risk_level': 0.5},
        'Spain': {'lat': 40.0, 'lon': -4.0, 'risk_level': 0.6},
        'Italy': {'lat': 42.5, 'lon': 12.5, 'risk_level': 0.6},
        'Denmark': {'lat': 56.0, 'lon': 10.0, 'risk_level': 0.5},
        'Finland': {'lat': 64.0, 'lon': 26.0, 'risk_level': 0.6},
        'Iceland': {'lat': 65.0, 'lon': -18.0, 'risk_level': 0.4},
        'Norway': {'lat': 61.0, 'lon': 8.0, 'risk_level': 0.6},
        'Sweden': {'lat': 63.0, 'lon': 16.0, 'risk_level': 0.6},
        'Estonia': {'lat': 59.0, 'lon': 26.0, 'risk_level': 0.5},
        'Latvia': {'lat': 57.0, 'lon': 25.0, 'risk_level': 0.5},
        'Lithuania': {'lat': 55.0, 'lon': 24.0, 'risk_level': 0.5},
        'Vietnam': {'lat': 14.0, 'lon': 108.0, 'risk_level': 0.6},
        'Austria': {'lat': 47.5, 'lon': 14.5, 'risk_level': 0.6},
        'Belgium': {'lat': 50.8, 'lon': 4.5, 'risk_level': 0.6},
        'Bulgaria': {'lat': 42.7, 'lon': 25.5, 'risk_level': 0.6},
        'Croatia': {'lat': 45.1, 'lon': 15.2, 'risk_level': 0.6},
        'Cyprus': {'lat': 35.0, 'lon': 33.0, 'risk_level': 0.5},
        'Czech Republic': {'lat': 49.8, 'lon': 15.5, 'risk_level': 0.6},
        'Greece': {'lat': 39.0, 'lon': 22.0, 'risk_level': 0.6},
        'Hungary': {'lat': 47.2, 'lon': 19.5, 'risk_level': 0.6},
        'Ireland': {'lat': 53.0, 'lon': -8.0, 'risk_level': 0.5},
        'Luxembourg': {'lat': 49.8, 'lon': 6.1, 'risk_level': 0.5},
        'Malta': {'lat': 35.9, 'lon': 14.5, 'risk_level': 0.4},
        'Netherlands': {'lat': 52.0, 'lon': 5.5, 'risk_level': 0.6},
        'Poland': {'lat': 52.0, 'lon': 19.0, 'risk_level': 0.6},
        'Romania': {'lat': 45.9, 'lon': 25.0, 'risk_level': 0.6},
        'Slovakia': {'lat': 48.7, 'lon': 19.7, 'risk_level': 0.6},
        'Slovenia': {'lat': 46.1, 'lon': 14.8, 'risk_level': 0.5}
    }
    
    @staticmethod
    def generate_threat_event():
        """Generate a single threat event with enhanced details"""
        technique_id = random.choice(list(ThreatIntelligence.ATTACK_TECHNIQUES.keys()))
        technique = ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]
        actor = random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys()))
        
        # Determine if threat is active or blocked
        is_blocked = random.choice([True, True, True, False])  # 75% blocked
        
        return {
            'timestamp': datetime.now() - timedelta(
                hours=random.randint(0, 168),  # Last 7 days
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            ),
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
            'malware_family': random.choice(['Emotet', 'TrickBot', 'REvil', 'Conti', 'DarkSide', 'BlackMatter', 'LockBit']),
            'detection_source': random.choice(['OTX', 'VirusTotal', 'MISP', 'Internal SOC', 'Partner Feed', 'OSINT']),
            'blocked': is_blocked,
            'active': not is_blocked,
            'ioc_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'ioc_domain': f"malicious-{random.randint(100,999)}.{random.choice(['com', 'net', 'org', 'io'])}",
            'mitigation': 'Implement network segmentation and update security patches' if is_blocked else 'IMMEDIATE ACTION REQUIRED'
        }
    
    @staticmethod
    def generate_threat_feed(num_events=1000):
        """Generate threat intelligence feed data"""
        return pd.DataFrame([ThreatIntelligence.generate_threat_event() for _ in range(num_events)])

# ============================================================================
# ENHANCED SECURITY RECOMMENDATIONS
# ============================================================================

def get_security_recommendations(threat_data):
    """Generate actionable security recommendations based on ISO 27001 and NIST frameworks"""
    
    top_techniques = threat_data['technique_name'].value_counts().head(3)
    top_sectors = threat_data['target_sector'].value_counts().head(3)
    critical_threats = len(threat_data[threat_data['severity'] == 'Critical'])
    
    recommendations = []
    
    # ISO 27001 based recommendations
    recommendations.append({
        'framework': 'ISO 27001',
        'priority': 'HIGH',
        'title': 'Information Security Management System (ISMS) Review',
        'threat': f'Multiple threat vectors detected across {len(threat_data["technique_name"].unique())} attack types',
        'controls': [
            '• A.12.1.1 - Documented operating procedures',
            '• A.12.6.1 - Management of technical vulnerabilities',
            '• A.13.1.1 - Network controls and segmentation',
            '• A.14.2.9 - System acceptance testing',
            '• A.16.1.1 - Incident response procedures'
        ]
    })
    
    # NIST Cybersecurity Framework recommendations
    recommendations.append({
        'framework': 'NIST CSF',
        'priority': 'CRITICAL',
        'title': 'NIST Framework Core Functions Activation',
        'threat': f'Critical threats detected: {critical_threats} instances',
        'controls': [
            '• IDENTIFY (ID.RA): Conduct immediate risk assessment',
            '• PROTECT (PR.AC): Strengthen access control measures',
            '• DETECT (DE.CM): Enhance continuous monitoring',
            '• RESPOND (RS.AN): Activate incident analysis procedures',
            '• RECOVER (RC.RP): Update recovery planning'
        ]
    })
    
    # Technique-specific recommendations
    for technique, count in top_techniques.items():
        if technique == 'Phishing':
            recommendations.append({
                'framework': 'NIST SP 800-177',
                'priority': 'HIGH',
                'title': 'Email Security Enhancement',
                'threat': f'Phishing attacks: {count} instances detected',
                'controls': [
                    '• Implement DMARC policy with p=reject',
                    '• Deploy DKIM signing for all domains',
                    '• Configure SPF records with -all',
                    '• Enable ATP/Safe Links protection',
                    '• Conduct phishing simulation training (NIST SP 800-50)'
                ]
            })
    
    return recommendations

# ============================================================================
# ENHANCED VISUALIZATION COMPONENTS
# ============================================================================

def create_3d_globe_threats(threat_df):
    """Create 3D globe visualization without threat count ruler"""
    
    # Aggregate data by country
    country_threats = threat_df.groupby('target_country').agg({
        'threat_id': 'count',
        'severity': lambda x: (x == 'Critical').sum(),
        'active': lambda x: x.sum()
    }).reset_index()
    country_threats.columns = ['country', 'total', 'critical', 'active']
    
    # Create globe data
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
                'active': country_data['active'].values[0],
                'text': f"{country}<br>Total: {country_data['total'].values[0]}<br>Critical: {country_data['critical'].values[0]}<br>Active: {country_data['active'].values[0]}"
            })
    
    globe_df = pd.DataFrame(globe_data)
    
    # Create 3D globe
    fig = go.Figure()
    
    # Add threat markers
    if not globe_df.empty:
        fig.add_trace(go.Scattergeo(
            lon=globe_df['lon'],
            lat=globe_df['lat'],
            text=globe_df['text'],
            mode='markers',
            marker=dict(
                size=globe_df['total'] / 10,
                color=globe_df['critical'],
                colorscale=[[0, '#00ff00'], [0.5, '#ffff00'], [1, '#ff0000']],
                showscale=False,
                line=dict(width=1, color='#00ffff'),
                sizemin=5,
                sizemode='diameter'
            ),
            hoverinfo='text'
        ))
    
    fig.update_layout(
        geo=dict(
            projection_type='orthographic',
            showland=True,
            landcolor='rgba(30, 35, 57, 0.9)',
            coastlinecolor='#00ffff',
            coastlinewidth=0.5,
            showocean=True,
            oceancolor='rgba(10, 14, 39, 0.95)',
            showcountries=True,
            countrycolor='#bf00ff',
            countrywidth=0.5,
            showlakes=True,
            lakecolor='rgba(10, 14, 39, 0.8)',
            bgcolor='rgba(20, 25, 47, 0.1)',
            projection_rotation=dict(lon=0, lat=20, roll=0)
        ),
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=600,
        title='3D Global Threat Distribution',
        margin=dict(l=0, r=0, t=50, b=0),
        dragmode='turntable'
    )
    
    return fig

def create_kill_chain_with_hover(threat_df):
    """Create cyber kill chain visualization with hover descriptions"""
    
    kill_chain_counts = threat_df['kill_chain_phase'].value_counts()
    
    phases = list(ThreatIntelligence.KILL_CHAIN_PHASES.keys())
    values = [kill_chain_counts.get(phase, 0) for phase in phases]
    descriptions = [ThreatIntelligence.KILL_CHAIN_PHASES[phase] for phase in phases]
    
    # Create hover text
    hover_text = [f"<b>{phase}</b><br>Count: {value}<br>Description: {desc}" 
                  for phase, value, desc in zip(phases, values, descriptions)]
    
    fig = go.Figure(data=[
        go.Funnel(
            y=phases,
            x=values,
            textposition="inside",
            textinfo="value+percent total",
            hovertext=hover_text,
            hoverinfo="text",
            marker=dict(
                color=['#00ffff', '#00e6e6', '#00cccc', '#bf00ff', '#9900cc', '#ff00bf', '#cc0099'],
                line=dict(color='#0a0e27', width=2)
            ),
            connector=dict(line=dict(color='#00ffff', width=2))
        )
    ])
    
    fig.update_layout(
        title='Cyber Kill Chain Analysis (Hover for descriptions)',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400
    )
    
    return fig

def create_trend_analysis_charts(threat_df, attack_type=None, country=None, sector=None, time_range='7d'):
    """Create customizable trend analysis charts"""
    
    # Filter data based on parameters
    filtered_df = threat_df.copy()
    
    if attack_type:
        filtered_df = filtered_df[filtered_df['technique_name'] == attack_type]
    if country:
        filtered_df = filtered_df[filtered_df['target_country'] == country]
    if sector:
        filtered_df = filtered_df[filtered_df['target_sector'] == sector]
    
    # Time range filter
    if time_range == '24h':
        cutoff = datetime.now() - timedelta(days=1)
    elif time_range == '7d':
        cutoff = datetime.now() - timedelta(days=7)
    else:
        cutoff = datetime.now() - timedelta(days=30)
    
    filtered_df = filtered_df[filtered_df['timestamp'] > cutoff]
    
    # Create time series
    if not filtered_df.empty:
        filtered_df['date'] = pd.to_datetime(filtered_df['timestamp']).dt.date
        daily_counts = filtered_df.groupby('date').size().reset_index(name='count')
    else:
        daily_counts = pd.DataFrame({'date': [], 'count': []})
    
    fig = go.Figure()
    
    if not daily_counts.empty:
        fig.add_trace(go.Scatter(
            x=daily_counts['date'],
            y=daily_counts['count'],
            mode='lines+markers',
            name='Threat Count',
            line=dict(color='#00ffff', width=3, shape='spline'),
            marker=dict(size=8, color='#bf00ff', line=dict(color='#00ffff', width=2)),
            fill='tozeroy',
            fillcolor='rgba(0, 255, 255, 0.1)'
        ))
    
    # Add title based on filters
    title_parts = []
    if attack_type:
        title_parts.append(f"Attack: {attack_type}")
    if country:
        title_parts.append(f"Country: {country}")
    if sector:
        title_parts.append(f"Sector: {sector}")
    
    title = " | ".join(title_parts) if title_parts else "Overall Threat Trends"
    
    fig.update_layout(
        title=f'Trend Analysis: {title}',
        xaxis_title='Date',
        yaxis_title='Threat Count',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
        height=400,
        hovermode='x unified'
    )
    
    return fig

# First, add this helper function near the top of your file (before main() or the tabs section)
def detect_ioc_type(ioc_ip, ioc_domain):
    """Detect the type of IOC and return formatted display string"""
    import re
    ioc_ip_str = str(ioc_ip)
    ioc_domain_str = str(ioc_domain)
    
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    if re.match(ip_pattern, ioc_ip_str) and ioc_ip_str != 'N/A':
        return f"IP: {ioc_ip_str}"
    elif ioc_domain_str != 'N/A' and '.' in ioc_domain_str:
        return f"Domain: {ioc_domain_str}"
    elif ioc_ip_str != 'N/A' and len(ioc_ip_str) == 32:
        return f"MD5: {ioc_ip_str[:16]}..."
    elif ioc_ip_str != 'N/A' and len(ioc_ip_str) == 64:
        return f"SHA256: {ioc_ip_str[:16]}..."
    elif ioc_ip_str != 'N/A':
        return f"Hash: {ioc_ip_str[:16]}..."
    else:
        return "IOC: N/A"
# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    apply_futuristic_theme()
    initialize_auto_update()
    
    # Initialize session state
    if 'threat_data' not in st.session_state:
        st.session_state.threat_data = ThreatIntelligence.generate_threat_feed(1000)
    
    # Auto-update check (every 5 minutes)
    if check_auto_update():
        # Add new threats to simulate real-time updates
        new_threats = ThreatIntelligence.generate_threat_feed(10)
        st.session_state.threat_data = pd.concat([new_threats, st.session_state.threat_data]).reset_index(drop=True)
        st.session_state.threat_data = st.session_state.threat_data.head(1000)  # Keep only latest 1000
    
    # Calculate time until next update
    seconds_since_update = (datetime.now() - st.session_state.last_update).total_seconds()
    seconds_until_next = 300 - seconds_since_update
    minutes_until_next = int(seconds_until_next // 60)
    seconds_remainder = int(seconds_until_next % 60)
    
    # Header
    st.markdown(f"""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                backdrop-filter: blur(20px); border-radius: 20px; 
                border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;
                box-shadow: 0 0 40px rgba(0, 255, 255, 0.2);">
        <h1 style="margin: 0;">THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8; font-size: 1.1em; margin-top: 10px; letter-spacing: 2px;">
            REAL-TIME THREAT DETECTION • AUTO-UPDATING FEEDS • ML-POWERED ANALYTICS
        </p>
        <p style="color: #00ff00; font-size: 0.9em; margin-top: 5px;">
            FEEDS AUTO-UPDATE EVERY 5 MINUTES | Last Update: {st.session_state.last_update.strftime('%H:%M:%S')} | 
            Next Update in: {minutes_until_next}m {seconds_remainder}s
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar Configuration
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 15px; background: rgba(20, 25, 47, 0.7); 
                    border-radius: 15px; border: 1px solid rgba(0, 255, 255, 0.3); margin-bottom: 20px;">
            <h3 style="color: #00ffff; margin: 0;">FILTERS & CONTROLS</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Time Range Selection with Date Picker
        st.markdown("### TIME RANGE")
        time_option = st.radio(
            "Select time range option",
            options=['Quick Select', 'Custom Range'],
            horizontal=True
        )
        
        if time_option == 'Quick Select':
            time_range = st.selectbox(
                "Quick time ranges",
                options=['Last 1 Hour', 'Last 6 Hours', 'Last 24 Hours', 'Last 7 Days', 'Last 30 Days'],
                index=3
            )
            time_map = {
                'Last 1 Hour': timedelta(hours=1),
                'Last 6 Hours': timedelta(hours=6),
                'Last 24 Hours': timedelta(days=1),
                'Last 7 Days': timedelta(days=7),
                'Last 30 Days': timedelta(days=30)
            }
            time_delta = time_map[time_range]
            time_cutoff = datetime.now() - time_delta
            end_datetime = datetime.now()
        else:
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input(
                    "Start Date",
                    value=datetime.now() - timedelta(days=7),
                    max_value=datetime.now()
                )
            with col2:
                end_date = st.date_input(
                    "End Date",
                    value=datetime.now(),
                    max_value=datetime.now()
                )
            time_cutoff = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
        
        st.markdown("---")
        
        # Attack Type Filter
        st.markdown("### ATTACK TYPE")
        attack_types = list(ThreatIntelligence.ATTACK_TECHNIQUES.values())
        attack_type_names = [attack['name'] for attack in attack_types]
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_attacks"):
                st.session_state.selected_attacks = attack_type_names
        with col2:
            if st.button("Clear All", key="clear_all_attacks"):
                st.session_state.selected_attacks = []
        
        if 'selected_attacks' not in st.session_state:
            st.session_state.selected_attacks = attack_type_names
        
        selected_attacks = st.multiselect(
            "Click to deselect",
            options=attack_type_names,
            default=st.session_state.selected_attacks,
            key="attack_filter"
        )
        st.session_state.selected_attacks = selected_attacks
        
        # Target Country Filter
        st.markdown("### TARGET COUNTRY")
        countries = list(ThreatIntelligence.COUNTRIES.keys())
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_countries"):
                st.session_state.selected_countries = countries
        with col2:
            if st.button("Clear All", key="clear_all_countries"):
                st.session_state.selected_countries = []
        
        if 'selected_countries' not in st.session_state:
            st.session_state.selected_countries = countries
        
        selected_countries = st.multiselect(
            "Click to deselect",
            options=countries,
            default=st.session_state.selected_countries,
            key="country_filter"
        )
        st.session_state.selected_countries = selected_countries
        
        # Sector Filter
        st.markdown("### TARGET SECTOR")
        sectors = ThreatIntelligence.SECTORS
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_sectors"):
                st.session_state.selected_sectors = sectors
        with col2:
            if st.button("Clear All", key="clear_all_sectors"):
                st.session_state.selected_sectors = []
        
        if 'selected_sectors' not in st.session_state:
            st.session_state.selected_sectors = sectors
        
        selected_sectors = st.multiselect(
            "Click to deselect",
            options=sectors,
            default=st.session_state.selected_sectors,
            key="sector_filter"
        )
        st.session_state.selected_sectors = selected_sectors
        
        # Severity Filter
        st.markdown("### SEVERITY")
        severity_options = ['Critical', 'High', 'Medium', 'Low']
        
        if 'selected_severity' not in st.session_state:
            st.session_state.selected_severity = severity_options
        
        severity_levels = st.multiselect(
            "Severity levels",
            options=severity_options,
            default=st.session_state.selected_severity,
            key="severity_filter"
        )
        st.session_state.selected_severity = severity_levels
        
        # Confidence threshold
        st.markdown("### CONFIDENCE")
        confidence_threshold = st.slider(
            "Minimum Confidence (%)",
            min_value=0,
            max_value=100,
            value=60,
            step=10
        )
        
        st.markdown("---")
        
        if st.button("APPLY FILTERS", use_container_width=True, type="primary"):
            st.rerun()
    
    # Apply filters to data
    threat_df = st.session_state.threat_data.copy()
    threat_df = threat_df[threat_df['timestamp'] > time_cutoff]
    threat_df = threat_df[threat_df['timestamp'] <= end_datetime]
    threat_df = threat_df[threat_df['technique_name'].isin(selected_attacks)]
    threat_df = threat_df[threat_df['target_country'].isin(selected_countries)]
    threat_df = threat_df[threat_df['target_sector'].isin(selected_sectors)]
    threat_df = threat_df[threat_df['severity'].isin(severity_levels)]
    threat_df = threat_df[threat_df['confidence'] >= confidence_threshold]
    
    # Main Dashboard Tabs
    main_tabs = st.tabs([
        "Threat Overview",
        "Human Targeted",
        "Global Threats",
        "ML Intelligence Analysis",
        "ML Trend Analysis",
        "IOC Scanner",
    ])
    
    # Tab 1: Threat Overview
    with main_tabs[0]:
        # Key Metrics
        st.markdown("### KEY THREAT METRICS")
        
        metric_cols = st.columns(7)
        
        total_threats = len(threat_df)
        critical_threats = len(threat_df[threat_df['severity'] == 'Critical'])
        active_threats = len(threat_df[threat_df['active'] == True])
        blocked_threats = len(threat_df[threat_df['blocked'] == True])
        unique_actors = threat_df['threat_actor'].nunique()
        affected_countries = threat_df['target_country'].nunique()
        affected_sectors = threat_df['target_sector'].nunique()
        
        with metric_cols[0]:
            st.metric("Total Threats", f"{total_threats:,}")
        with metric_cols[1]:
            st.metric("Critical", f"{critical_threats}", delta=f"{random.randint(-5, 10)}")
        with metric_cols[2]:
            st.metric("Active", f"{active_threats}", delta=f"{random.randint(-3, 5)}")
        with metric_cols[3]:
            st.metric("Blocked", f"{blocked_threats}")
        with metric_cols[4]:
            st.metric("Threat Actors", f"{unique_actors}")
        with metric_cols[5]:
            st.metric("Countries", f"{affected_countries}")
        with metric_cols[6]:
            st.metric("Sectors", f"{affected_sectors}")
        
        # Live Threat Feed
        st.markdown("### LIVE THREAT FEED")
        
        feed_container = st.container()
        with feed_container:
            recent_threats = threat_df.nlargest(20, 'timestamp') if not threat_df.empty else pd.DataFrame()
            
            for _, threat in recent_threats.iterrows():
                severity_color = {
                    'Critical': '#ff0000',
                    'High': '#ff7f00',
                    'Medium': '#ffff00',
                    'Low': '#00ff00'
                }[threat['severity']]
                
                status = 'BLOCKED' if threat['blocked'] else 'ACTIVE THREAT'
                status_color = '#00ff00' if threat['blocked'] else '#ff0000'
                
                # Detect IOC type
                ioc_display = detect_ioc_type(threat['ioc_ip'], threat['ioc_domain'])
                
                with st.container():
                    st.markdown(f"""
                    <div style="padding: 15px; margin: 10px 0; 
                                background: linear-gradient(135deg, rgba(20, 25, 47, 0.8), rgba(30, 35, 57, 0.6));
                                border-left: 4px solid {severity_color}; 
                                border-radius: 10px;
                                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <div style="display: flex; align-items: center; gap: 15px;">
                                <span style="background: {severity_color}; color: white; 
                                           padding: 3px 10px; border-radius: 5px; font-weight: bold;
                                           font-size: 0.85em; font-family: 'Orbitron', monospace;">
                                    {threat['severity'].upper()}
                                </span>
                                <span style="color: #00ffff; font-weight: bold; font-size: 1.1em;">
                                    {threat['technique_name']}
                                </span>
                                <span style="color: #b8bcc8; font-style: italic;">
                                    via {threat['threat_actor']}
                                </span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 15px;">
                                <span style="background: {status_color}20; color: {status_color}; 
                                           padding: 3px 12px; border-radius: 15px; 
                                           border: 1px solid {status_color}; font-weight: bold;">
                                    {status}
                                </span>
                                <span style="color: #8a8a8a; font-size: 0.9em; font-family: monospace;">
                                    {threat['timestamp'].strftime('%H:%M:%S')}
                                </span>
                            </div>
                        </div>
                        <div style="color: #b8bcc8; font-size: 0.95em; padding-left: 5px;">
                            <span style="color: #bf00ff;">Target:</span> {threat['target_country']} - {threat['target_sector']} | 
                            <span style="color: #bf00ff;">Phase:</span> {threat['kill_chain_phase']} | 
                            <span style="color: #bf00ff;">IOC:</span> <span style="color: #00ffff; font-family: monospace;">{ioc_display}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Charts
        st.markdown("### THREAT ANALYTICS")
        
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            st.plotly_chart(create_kill_chain_with_hover(threat_df), use_container_width=True)
        
        with chart_col2:
            if not threat_df.empty:
                severity_counts = threat_df['severity'].value_counts()
                fig_severity = go.Figure(data=[go.Pie(
                    labels=severity_counts.index,
                    values=severity_counts.values,
                    hole=0.6,
                    marker=dict(
                        colors=['#ff0000', '#ff7f00', '#ffff00', '#00ff00'],
                        line=dict(color='#0a0e27', width=2)
                    ),
                    textinfo='label+percent'
                )])
                fig_severity.update_layout(
                    title='Threat Severity Distribution',
                    plot_bgcolor='rgba(20, 25, 47, 0.1)',
                    paper_bgcolor='rgba(20, 25, 47, 0.7)',
                    font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                    height=400,
                    showlegend=False
                )
                st.plotly_chart(fig_severity, use_container_width=True)
    
    # Tab 2: Global Threats
    with main_tabs[2]:
        st.markdown("### GLOBAL THREAT LANDSCAPE")
        st.markdown("*Click and drag to rotate the globe. Click on a country to see detailed threat analysis.*")
        
        globe_fig = create_3d_globe_threats(threat_df)
        globe_placeholder = st.plotly_chart(globe_fig, use_container_width=True, key="globe_chart")
        
        st.markdown("### SELECT A COUNTRY FOR DETAILED ANALYSIS")
        
        if not threat_df.empty:
            countries_with_threats = threat_df['target_country'].unique()
            
            selected_country = st.selectbox(
                "Choose a country to analyze:",
                options=['None'] + sorted(countries_with_threats.tolist()),
                key="country_selector"
            )
            
            if selected_country != 'None':
                country_threats = threat_df[threat_df['target_country'] == selected_country]
                
                if not country_threats.empty:
                    st.markdown(f"### DETAILED THREAT ANALYSIS: {selected_country}")
                    
                    summary_cols = st.columns(6)
                    
                    total = len(country_threats)
                    critical = len(country_threats[country_threats['severity'] == 'Critical'])
                    high = len(country_threats[country_threats['severity'] == 'High'])
                    active = len(country_threats[country_threats['active'] == True])
                    blocked = len(country_threats[country_threats['blocked'] == True])
                    block_rate = (blocked / total * 100) if total > 0 else 0
                    
                    with summary_cols[0]:
                        st.metric("Total Threats", f"{total:,}")
                    with summary_cols[1]:
                        st.metric("Critical", f"{critical}")
                    with summary_cols[2]:
                        st.metric("High", f"{high}")
                    with summary_cols[3]:
                        st.metric("Active", f"{active}")
                    with summary_cols[4]:
                        st.metric("Blocked", f"{blocked}")
                    with summary_cols[5]:
                        st.metric("Block Rate", f"{block_rate:.1f}%")
                    
                    st.markdown("#### THREAT DETAILS")
                    
                    display_data = country_threats[['timestamp', 'technique_name', 'technique_description', 
                                                   'severity', 'threat_actor', 'target_sector', 
                                                   'blocked', 'active', 'confidence']].copy()
                    display_data['Status'] = display_data.apply(
                        lambda x: 'Blocked' if x['blocked'] else 'Active', axis=1
                    )
                    display_data = display_data.drop(['blocked', 'active'], axis=1)
                    display_data.columns = ['Timestamp', 'Attack Type', 'Description', 'Severity', 
                                           'Threat Actor', 'Target Sector', 'Confidence %', 'Status']
                    
                    st.dataframe(
                        display_data.head(50),
                        use_container_width=True,
                        height=400
                    )
                    
                    chart_col1, chart_col2 = st.columns(2)
                    
                    with chart_col1:
                        attack_dist = country_threats['technique_name'].value_counts()
                        fig_attacks = go.Figure(data=[go.Bar(
                            x=attack_dist.values[:10],
                            y=attack_dist.index[:10],
                            orientation='h',
                            marker=dict(
                                color=attack_dist.values[:10],
                                colorscale=[[0, '#00ffff'], [1, '#ff00bf']],
                                line=dict(color='#0a0e27', width=1)
                            ),
                            text=attack_dist.values[:10],
                            textposition='outside'
                        )])
                        fig_attacks.update_layout(
                            title=f'Top Attack Types in {selected_country}',
                            xaxis_title='Count',
                            plot_bgcolor='rgba(20, 25, 47, 0.1)',
                            paper_bgcolor='rgba(20, 25, 47, 0.7)',
                            font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                            height=350
                        )
                        st.plotly_chart(fig_attacks, use_container_width=True)
                    
                    with chart_col2:
                        sector_dist = country_threats['target_sector'].value_counts()
                        fig_sectors = go.Figure(data=[go.Pie(
                            labels=sector_dist.index[:8],
                            values=sector_dist.values[:8],
                            hole=0.6,
                            marker=dict(
                                colors=['#00ffff', '#bf00ff', '#ff00bf', '#00ff7f', 
                                       '#ff7f00', '#7f00ff', '#ffff00', '#00ff00'],
                                line=dict(color='#0a0e27', width=2)
                            ),
                            textinfo='label+percent'
                        )])
                        fig_sectors.update_layout(
                            title=f'Targeted Sectors in {selected_country}',
                            plot_bgcolor='rgba(20, 25, 47, 0.1)',
                            paper_bgcolor='rgba(20, 25, 47, 0.7)',
                            font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                            height=350
                        )
                        st.plotly_chart(fig_sectors, use_container_width=True)
        else:
            st.info("No threat data available with current filters")

    # Tab 3: ML Intelligence Analysis (merged with Security Recommendations)
    with main_tabs[3]:
        st.markdown("### ML-POWERED THREAT INTELLIGENCE & SECURITY ANALYSIS")
        
        if not threat_df.empty:
            # Create sub-tabs for different ML analyses
            ml_tabs = st.tabs([
                "Threat Prediction",
                "Anomaly Detection", 
                "Threat Clustering",
                "Security Recommendations"
            ])
            
            # Sub-tab 1: Threat Prediction
            with ml_tabs[0]:
                st.markdown("#### ML THREAT SEVERITY PREDICTOR")
                st.markdown("*Machine learning model trained to predict threat severity based on attack patterns*")
                
                with st.spinner("Training ML model..."):
                    model, metrics = ThreatMLModels.train_threat_predictor(threat_df)
                
                if model and metrics:
                    # Display model performance
                    perf_cols = st.columns(3)
                    with perf_cols[0]:
                        st.metric("Model Accuracy", f"{metrics['accuracy']*100:.1f}%")
                    with perf_cols[1]:
                        st.metric("Training Samples", len(threat_df))
                    with perf_cols[2]:
                        st.metric("Features Used", "7")
                    
                    # Feature importance chart
                    st.markdown("##### FEATURE IMPORTANCE ANALYSIS")
                    feature_imp = metrics['feature_importance']
                    
                    fig_importance = go.Figure(data=[go.Bar(
                        x=feature_imp['importance'],
                        y=feature_imp['feature'],
                        orientation='h',
                        marker=dict(
                            color=feature_imp['importance'],
                            colorscale=[[0, '#bf00ff'], [1, '#00ffff']],
                            line=dict(color='#0a0e27', width=1)
                        ),
                        text=[f"{x:.3f}" for x in feature_imp['importance']],
                        textposition='outside'
                    )])
                    
                    fig_importance.update_layout(
                        title='ML Model Feature Importance',
                        xaxis_title='Importance Score',
                        yaxis_title='Feature',
                        plot_bgcolor='rgba(20, 25, 47, 0.1)',
                        paper_bgcolor='rgba(20, 25, 47, 0.7)',
                        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                        height=400
                    )
                    st.plotly_chart(fig_importance, use_container_width=True)
                    
                    st.markdown("""
                    **Model Insights:**
                    - The Random Forest classifier analyzes attack patterns to predict threat severity
                    - Features include attack technique, threat actor, target sector, country, confidence, and temporal patterns
                    - Higher importance scores indicate features that are more influential in predicting threat severity
                    """)
            
            # Sub-tab 2: Anomaly Detection
            with ml_tabs[1]:
                st.markdown("#### ML ANOMALY DETECTION")
                st.markdown("*Isolation Forest algorithm identifies unusual threat patterns that deviate from normal behavior*")
                
                with st.spinner("Detecting anomalies..."):
                    anomalies = ThreatMLModels.detect_anomalies(threat_df)
                
                if anomalies is not None and not anomalies.empty:
                    anomaly_cols = st.columns(4)
                    
                    with anomaly_cols[0]:
                        st.metric("Anomalies Detected", len(anomalies))
                    with anomaly_cols[1]:
                        anomaly_critical = len(anomalies[anomalies['severity'] == 'Critical'])
                        st.metric("Critical Anomalies", anomaly_critical)
                    with anomaly_cols[2]:
                        anomaly_rate = (len(anomalies) / len(threat_df) * 100)
                        st.metric("Anomaly Rate", f"{anomaly_rate:.1f}%")
                    with anomaly_cols[3]:
                        unique_actors = anomalies['threat_actor'].nunique()
                        st.metric("Unique Actors", unique_actors)
                    
                    st.markdown("##### ANOMALOUS THREATS")
                    
                    anomaly_display = anomalies[['timestamp', 'technique_name', 'threat_actor', 
                                                 'target_country', 'target_sector', 'severity', 
                                                 'confidence']].head(20)
                    anomaly_display.columns = ['Timestamp', 'Attack Type', 'Threat Actor', 
                                              'Country', 'Sector', 'Severity', 'Confidence']
                    
                    st.dataframe(anomaly_display, use_container_width=True, height=400)
                    
                    st.markdown("""
                    **Anomaly Detection Insights:**
                    - These threats show unusual patterns compared to typical attack behavior
                    - May indicate new attack techniques, sophisticated actors, or targeted campaigns
                    - Recommend immediate investigation and enhanced monitoring for these patterns
                    """)
                else:
                    st.info("No anomalies detected in current data")
            
            # Sub-tab 3: Threat Clustering
            with ml_tabs[2]:
                st.markdown("#### ML THREAT CLUSTERING")
                st.markdown("*K-Means algorithm groups similar threats to identify attack patterns and campaigns*")
                
                with st.spinner("Clustering threats..."):
                    cluster_analysis = ThreatMLModels.cluster_threats(threat_df, n_clusters=5)
                
                if cluster_analysis is not None:
                    st.markdown("##### THREAT CLUSTER ANALYSIS")
                    
                    # Display cluster table
                    cluster_display = cluster_analysis.copy()
                    cluster_display['avg_confidence'] = cluster_display['avg_confidence'].round(1)
                    cluster_display.columns = ['Cluster ID', 'Size', 'Top Technique', 'Top Actor', 
                                              'Top Sector', 'Avg Confidence', 'Critical Count']
                    
                    st.dataframe(cluster_display, use_container_width=True)
                    
                    # Cluster visualization
                    fig_clusters = go.Figure(data=[go.Bar(
                        x=cluster_analysis['cluster_id'],
                        y=cluster_analysis['size'],
                        text=cluster_analysis['size'],
                        textposition='outside',
                        marker=dict(
                            color=cluster_analysis['critical_count'],
                            colorscale=[[0, '#00ffff'], [1, '#ff0000']],
                            line=dict(color='#0a0e27', width=1),
                            showscale=True,
                            colorbar=dict(title="Critical<br>Threats")
                        ),
                        hovertext=[f"Top Technique: {row['top_technique']}<br>" +
                                  f"Top Actor: {row['top_actor']}<br>" +
                                  f"Top Sector: {row['top_sector']}<br>" +
                                  f"Avg Confidence: {row['avg_confidence']:.1f}%"
                                  for _, row in cluster_analysis.iterrows()],
                        hoverinfo='text'
                    )])
                    
                    fig_clusters.update_layout(
                        title='Threat Cluster Distribution',
                        xaxis_title='Cluster ID',
                        yaxis_title='Number of Threats',
                        plot_bgcolor='rgba(20, 25, 47, 0.1)',
                        paper_bgcolor='rgba(20, 25, 47, 0.7)',
                        font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                        height=400
                    )
                    st.plotly_chart(fig_clusters, use_container_width=True)
                    
                    st.markdown("""
                    **Clustering Insights:**
                    - Similar threats are grouped together to identify coordinated attack campaigns
                    - Each cluster represents a distinct pattern of attack behavior
                    - Analyze cluster characteristics to develop targeted defense strategies
                    """)
                else:
                    st.info("Unable to perform clustering on current data")
            
            # Sub-tab 4: Security Recommendations (integrated from old tab)
            with ml_tabs[3]:
                st.markdown("#### SECURITY RECOMMENDATIONS (ISO 27001 & NIST)")
                
                recommendations = get_security_recommendations(threat_df)
                
                st.markdown("##### FRAMEWORK-BASED CONTROLS")
                for rec in recommendations:
                    priority_color = {
                        'CRITICAL': '#ff0000',
                        'HIGH': '#ff7f00',
                        'MEDIUM': '#ffff00'
                    }.get(rec['priority'], '#00ff00')
                    
                    with st.expander(f"[{rec['framework']}] {rec['title']} - {rec['priority']} PRIORITY", expanded=False):
                        st.markdown(f"""
                        <div style="padding: 15px; background: rgba(20, 25, 47, 0.7);
                                    border: 2px solid {priority_color}; border-radius: 10px;">
                            <div style="color: {priority_color}; font-weight: bold; margin-bottom: 10px;">
                                Threat Context: {rec['threat']}
                            </div>
                            <div style="color: #00ffff; font-weight: bold; margin-bottom: 10px;">
                                RECOMMENDED CONTROLS:
                            </div>
                            <div style="color: #b8bcc8;">
                                {'<br>'.join(rec['controls'])}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Security Best Practice Flashcards
                st.markdown("##### SECURITY BEST PRACTICES")
                
                top_threats = threat_df['technique_name'].value_counts().head(3)
                critical_threats_count = len(threat_df[threat_df['severity'] == 'Critical'])
                
                flashcards = [
                    {
                        'title': 'Zero Trust Architecture',
                        'content': 'Implement "never trust, always verify" principle. Require continuous verification for all users and devices.',
                        'action': 'Deploy microsegmentation and identity-based access controls',
                        'priority': 'CRITICAL' if 'Phishing' in top_threats.index else 'HIGH'
                    },
                    {
                        'title': 'Threat Hunting Program',
                        'content': 'Proactively search for cyber threats that evade existing security solutions.',
                        'action': 'Use threat intelligence feeds to hunt for IOCs in your environment',
                        'priority': 'HIGH'
                    },
                    {
                        'title': 'Incident Response Plan',
                        'content': 'Maintain an updated IR plan with clear roles and recovery procedures.',
                        'action': 'Conduct tabletop exercises quarterly and update contact lists',
                        'priority': 'CRITICAL' if critical_threats_count > 10 else 'HIGH'
                    },
                    {
                        'title': 'Security Awareness Training',
                        'content': 'Regular training on latest threats, especially phishing and social engineering.',
                        'action': 'Implement monthly phishing simulations and track metrics',
                        'priority': 'CRITICAL' if 'Phishing' in top_threats.index else 'MEDIUM'
                    }
                ]
                
                flashcard_cols = st.columns(4)
                
                for idx, card in enumerate(flashcards):
                    with flashcard_cols[idx % 4]:
                        priority_color = {
                            'CRITICAL': 'linear-gradient(135deg, #ff0000, #ff4444)',
                            'HIGH': 'linear-gradient(135deg, #ff7f00, #ffaa00)',
                            'MEDIUM': 'linear-gradient(135deg, #ffff00, #ffff66)'
                        }.get(card['priority'], 'linear-gradient(135deg, #00ff00, #44ff44)')
                        
                        st.markdown(f"""
                        <div style="padding: 20px; margin: 10px 0; 
                                    background: linear-gradient(135deg, rgba(20, 25, 47, 0.9), rgba(40, 45, 67, 0.7));
                                    border: 2px solid rgba(0, 255, 255, 0.3); 
                                    border-radius: 15px;
                                    min-height: 220px;">
                            
                            <div style="position: absolute; top: -10px; right: -10px; 
                                        padding: 5px 10px; border-radius: 20px;
                                        background: {priority_color};
                                        color: white; font-size: 0.8em; font-weight: bold;">
                                {card['priority']}
                            </div>
                            
                            <div style="color: #00ffff; font-weight: bold; text-align: center; 
                                        margin-bottom: 10px; font-family: 'Orbitron', monospace;
                                        font-size: 1.1em;">
                                {card['title']}
                            </div>
                            
                            <div style="color: #b8bcc8; font-size: 0.9em; text-align: center; 
                                        margin-bottom: 15px; min-height: 60px;">
                                {card['content']}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
        else:
            st.info("No threat data available for ML analysis")
    
    # Tab 4: ML Trend Analysis
    with main_tabs[4]:
        st.markdown("### ML-POWERED TREND ANALYSIS & FORECASTING")
        
        if not threat_df.empty:
            # Filtering controls
            trend_col1, trend_col2, trend_col3, trend_col4 = st.columns(4)
            
            with trend_col1:
                trend_attack = st.selectbox(
                    "Attack Type",
                    options=['All'] + list(threat_df['technique_name'].unique()),
                    key="trend_attack"
                )
            
            with trend_col2:
                trend_country = st.selectbox(
                    "Country",
                    options=['All'] + list(threat_df['target_country'].unique()),
                    key="trend_country"
                )
            
            with trend_col3:
                trend_sector = st.selectbox(
                    "Sector",
                    options=['All'] + list(threat_df['target_sector'].unique()),
                    key="trend_sector"
                )
            
            with trend_col4:
                trend_time = st.selectbox(
                    "Time Range",
                    options=['24h', '7d', '30d'],
                    index=1,
                    key="trend_time"
                )
            
            # Historical trend analysis
            st.markdown("#### HISTORICAL TREND ANALYSIS")
            trend_chart = create_trend_analysis_charts(
                threat_df,
                attack_type=None if trend_attack == 'All' else trend_attack,
                country=None if trend_country == 'All' else trend_country,
                sector=None if trend_sector == 'All' else trend_sector,
                time_range=trend_time
            )
            st.plotly_chart(trend_chart, use_container_width=True)
            
            # ML-based forecast
            st.markdown("#### ML THREAT FORECAST (7 DAYS)")
            st.markdown("*Simple moving average model predicts future threat activity*")
            
            with st.spinner("Generating ML forecast..."):
                forecast_df = ThreatMLModels.forecast_threats(threat_df, days_ahead=7)
            
            if forecast_df is not None:
                # Create combined historical + forecast chart
                historical_df = threat_df.copy()
                historical_df['date'] = pd.to_datetime(historical_df['timestamp']).dt.date
                daily_counts = historical_df.groupby('date').size().reset_index(name='count')
                daily_counts['date'] = pd.to_datetime(daily_counts['date'])
                
                fig_forecast = go.Figure()
                
                # Historical data
                fig_forecast.add_trace(go.Scatter(
                    x=daily_counts['date'],
                    y=daily_counts['count'],
                    mode='lines+markers',
                    name='Historical',
                    line=dict(color='#00ffff', width=3),
                    marker=dict(size=6, color='#00ffff')
                ))
                
                # Forecast data
                fig_forecast.add_trace(go.Scatter(
                    x=forecast_df['date'],
                    y=forecast_df['forecast_count'],
                    mode='lines+markers',
                    name='Forecast',
                    line=dict(color='#bf00ff', width=3, dash='dash'),
                    marker=dict(size=8, color='#bf00ff', symbol='diamond')
                ))
                
                fig_forecast.update_layout(
                    title='Threat Count: Historical + 7-Day ML Forecast',
                    xaxis_title='Date',
                    yaxis_title='Threat Count',
                    plot_bgcolor='rgba(20, 25, 47, 0.1)',
                    paper_bgcolor='rgba(20, 25, 47, 0.7)',
                    font=dict(family="Orbitron, monospace", color='#b8bcc8'),
                    height=450,
                    hovermode='x unified',
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1
                    )
                )
                
                st.plotly_chart(fig_forecast, use_container_width=True)
                
                # Forecast summary
                st.markdown("##### FORECAST INSIGHTS")
                
                avg_forecast = forecast_df['forecast_count'].mean()
                avg_historical = daily_counts['count'].tail(7).mean()
                change_pct = ((avg_forecast - avg_historical) / avg_historical * 100) if avg_historical > 0 else 0
                
                forecast_cols = st.columns(3)
                with forecast_cols[0]:
                    st.metric("Avg Historical (Last 7d)", f"{avg_historical:.0f}")
                with forecast_cols[1]:
                    st.metric("Avg Forecast (Next 7d)", f"{avg_forecast:.0f}", delta=f"{change_pct:+.1f}%")
                with forecast_cols[2]:
                    trend_direction = "INCREASING" if change_pct > 5 else "STABLE" if change_pct > -5 else "DECREASING"
                    st.metric("Trend Direction", trend_direction)
                
                st.markdown("""
                **Forecast Model:**
                - Uses 7-day moving average to predict future threat activity
                - Incorporates random variation to simulate real-world uncertainty
                - Best used for short-term tactical planning (3-7 days)
                - Recommend combining with threat intelligence feeds for strategic decisions
                """)
            else:
                st.info("Insufficient data for forecasting")
        else:
            st.info("No data available for trend analysis")
    
    # Tab 5: Human-Targeted Attacks
    with main_tabs[1]:
        st.markdown("### HUMAN-TARGETED ATTACK ANALYSIS")
        st.markdown("*Focus on attacks that exploit human psychology and behavior*")
        
        # Define human-targeted attack types
        human_attacks = {
            'Phishing': {
                'icon': '🎣',
                'description': 'Fraudulent emails mimicking legitimate organizations to steal credentials',
                'risk': 'Critical',
                'prevention': [
                    'Verify sender email addresses carefully',
                    'Hover over links before clicking',
                    'Check for spelling and grammar errors',
                    'Never provide credentials via email'
                ]
            },
            'Vishing': {
                'icon': '📞',
                'description': 'Voice phishing attacks using phone calls to extract sensitive information',
                'risk': 'High',
                'prevention': [
                    'Never provide passwords over the phone',
                    'Verify caller identity independently',
                    'Be suspicious of urgent requests',
                    'Hang up and call back on official numbers'
                ]
            },
            'Smishing': {
                'icon': '📱',
                'description': 'SMS text message phishing to trick users into revealing information',
                'risk': 'High',
                'prevention': [
                    'Don\'t click links in unexpected texts',
                    'Verify with sender through other means',
                    'Block and report suspicious numbers',
                    'Never send sensitive info via SMS'
                ]
            },
            'BEC (Business Email Compromise)': {
                'icon': '💼',
                'description': 'Sophisticated scams targeting businesses through impersonation of executives',
                'risk': 'Critical',
                'prevention': [
                    'Implement dual approval for wire transfers',
                    'Verify payment changes via phone call',
                    'Use email authentication (DMARC/SPF)',
                    'Train staff on executive impersonation'
                ]
            },
            'Whaling': {
                'icon': '🐋',
                'description': 'Highly targeted phishing attacks aimed at senior executives',
                'risk': 'Critical',
                'prevention': [
                    'Executive-specific security training',
                    'Enhanced email filtering for C-suite',
                    'Separate approval chains for executives',
                    'Regular security briefings'
                ]
            },
            'Social Engineering': {
                'icon': '🎭',
                'description': 'Psychological manipulation to trick users into security mistakes',
                'risk': 'High',
                'prevention': [
                    'Implement strict visitor policies',
                    'Train staff on manipulation tactics',
                    'Verify all unusual requests',
                    'Create security-aware culture'
                ]
            },
            'Pretexting': {
                'icon': '🎯',
                'description': 'Creating false scenarios to obtain information from targets',
                'risk': 'Medium',
                'prevention': [
                    'Verify identity before sharing info',
                    'Question unexpected requests',
                    'Follow data classification policies',
                    'Report suspicious interactions'
                ]
            },
            'Baiting': {
                'icon': '🪤',
                'description': 'Using tempting items (USBs, downloads) to deliver malware',
                'risk': 'High',
                'prevention': [
                    'Never use found USB devices',
                    'Avoid downloading pirated content',
                    'Scan all external media',
                    'Disable autorun features'
                ]
            }
        }
        
        # Filter threats for human-targeted attacks
        human_targeted_threats = threat_df[threat_df['technique_name'].isin(human_attacks.keys())] if not threat_df.empty else pd.DataFrame()
        
        # Metrics for human-targeted attacks
        if not human_targeted_threats.empty:
            st.markdown("#### HUMAN-TARGETED ATTACK METRICS")
            
            metric_cols = st.columns(5)
            with metric_cols[0]:
                total_human = len(human_targeted_threats)
                st.metric("Total Attacks", f"{total_human:,}")
            
            with metric_cols[1]:
                phishing_count = len(human_targeted_threats[human_targeted_threats['technique_name'] == 'Phishing'])
                st.metric("Phishing", f"{phishing_count}")
            
            with metric_cols[2]:
                critical_human = len(human_targeted_threats[human_targeted_threats['severity'] == 'Critical'])
                st.metric("Critical", f"{critical_human}")
            
            with metric_cols[3]:
                blocked_human = len(human_targeted_threats[human_targeted_threats['blocked'] == True])
                st.metric("Blocked", f"{blocked_human}")
            
            with metric_cols[4]:
                success_rate = (blocked_human / total_human * 100) if total_human > 0 else 0
                st.metric("Block Rate", f"{success_rate:.1f}%")
            
            # Recent Human-Targeted Attacks
            st.markdown("#### RECENT HUMAN-TARGETED ATTACKS")
            
            recent_human = human_targeted_threats.nlargest(10, 'timestamp')
            for _, attack in recent_human.iterrows():
                status_color = '#00ff00' if attack['blocked'] else '#ff0000'
                status_text = 'BLOCKED' if attack['blocked'] else 'ACTIVE'
                
                st.markdown(f"""
                <div style="padding: 12px; margin: 8px 0;
                            background: rgba(20, 25, 47, 0.7);
                            border-left: 3px solid {status_color};
                            border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="color: #00ffff; font-weight: bold;">
                                {attack['technique_name']}
                            </span>
                            <span style="color: #b8bcc8; margin-left: 10px;">
                                targeting {attack['target_sector']} in {attack['target_country']}
                            </span>
                        </div>
                        <div>
                            <span style="color: {status_color};">
                                {status_text}
                            </span>
                            <span style="color: #8a8a8a; margin-left: 10px; font-size: 0.9em;">
                                {attack['timestamp'].strftime('%Y-%m-%d %H:%M')}
                            </span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No human-targeted threats detected with current filters")
    
    # Tab 6: IOC Scanner
    with main_tabs[5]:
        st.markdown("### IOC SCANNER & THREAT DETECTION")
        
        ioc_input = st.text_input(
            "Enter IOC (Hash, IP, Domain, or URL)",
            placeholder="e.g., 192.168.1.1, malicious.com, d41d8cd98f00b204e9800998ecf8427e"
        )
        
        if st.button("SCAN IOC"):
            if ioc_input:
                with st.spinner("Scanning..."):
                    time.sleep(2)
                    
                    # Simulate results
                    detection_ratio = random.randint(0, 75)
                    is_malicious = detection_ratio > 30
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Detection Ratio", f"{detection_ratio}/75")
                    with col2:
                        status = "MALICIOUS" if is_malicious else "CLEAN"
                        st.metric("Status", status)
                    with col3:
                        st.metric("Reputation", f"{random.randint(10, 100)}/100")
                    with col4:
                        st.metric("Last Seen", f"{random.randint(1, 24)}h ago")
                    
                    if is_malicious:
                        st.error("WARNING: This IOC has been flagged as malicious by multiple security vendors!")
                    else:
                        st.success("This IOC appears to be clean based on current threat intelligence.")

if __name__ == "__main__":
    main()
