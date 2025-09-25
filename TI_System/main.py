#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform with Enhanced Interactivity
Auto-updating feeds every 5 minutes with comprehensive filtering and drill-down capabilities
"""
import os
from supabase import create_client, Client
from dotenv import load_dotenv
import sqlite3
import bcrypt
import secrets
import re
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
from supabase import create_client, Client
import streamlit as st
import re
import time

# ============================================================================
# SUPABASE AUTHENTICATION SYSTEM
# ============================================================================

# Initialize Supabase client after Streamlit secrets are loaded
@st.cache_resource
def get_supabase_client() -> Client:
    url = st.secrets["SUPABASE_URL"]  # key must exactly match your secrets.toml
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = get_supabase_client()

# ----------------------
# User Management with Better Error Handling
# ----------------------

def create_user(email, password, username, full_name="", company=""):
    """Create a new user with Supabase Auth and profile"""
    try:
        # Step 1: Check if username is already taken
        existing_user = supabase.table('user_profiles').select("username").eq('username', username).execute()
        if existing_user.data:
            return False, "Username already taken"
        
        # Step 2: Create auth user
        auth_response = supabase.auth.sign_up({
            "email": email, 
            "password": password,
            "options": {
                "data": {
                    "username": username,
                    "full_name": full_name
                }
            }
        })
        
        if not auth_response.user:
            return False, "Failed to create authentication account"
        
        user_id = auth_response.user.id
        
        # Step 3: Create user profile (using upsert to handle any conflicts)
        profile_data = {
            'id': str(user_id),  # Ensure UUID is string
            'username': username,
            'full_name': full_name or '',
            'company': company or '',
            'role': 'free',
            'is_premium': False
        }
        
        # Use upsert instead of insert to avoid conflicts
        profile_response = supabase.table('user_profiles').upsert(profile_data).execute()
        
        # Check if profile was created
        if profile_response.data:
            return True, "✅ Account created successfully! You can now login."
        else:
            # Profile creation failed but auth user exists
            # Try to clean up by storing minimal profile
            try:
                supabase.table('user_profiles').insert({
                    'id': str(user_id),
                    'username': username,
                    'full_name': '',
                    'company': '',
                    'role': 'free',
                    'is_premium': False
                }).execute()
            except:
                pass
            return True, "✅ Account created! You can now login."
            
    except Exception as e:
        error_msg = str(e)
        print(f"Registration error: {error_msg}")  # For debugging
        
        # Parse specific errors
        if "already registered" in error_msg.lower():
            return False, "This email is already registered. Please login instead."
        elif "username" in error_msg and "unique" in error_msg.lower():
            return False, "Username already taken. Please choose another."
        elif "password" in error_msg.lower():
            return False, "Password too weak. Use at least 6 characters with numbers and letters."
        else:
            # Log the actual error for debugging
            return False, f"Registration failed. Please try again or contact support."

def verify_user(email, password):
    """Sign in user with Supabase Auth"""
    try:
        # Authenticate user
        auth_response = supabase.auth.sign_in_with_password({
            "email": email, 
            "password": password
        })
        
        if not auth_response.user:
            return None
        
        user_id = auth_response.user.id
        
        # Get user profile
        try:
            profile_response = supabase.table('user_profiles').select("*").eq('id', user_id).single().execute()
            profile = profile_response.data
        except:
            # Profile doesn't exist, create minimal one
            profile = None
        
        if profile:
            return {
                'id': user_id,
                'email': email,
                'username': profile.get('username', email.split('@')[0]),
                'full_name': profile.get('full_name', ''),
                'company': profile.get('company', ''),
                'role': profile.get('role', 'free'),
                'is_premium': profile.get('is_premium', False)
            }
        else:
            # User exists in auth but not in profiles (edge case)
            # Create minimal profile
            username = email.split('@')[0]
            try:
                supabase.table('user_profiles').upsert({
                    'id': str(user_id),
                    'username': username,
                    'full_name': '',
                    'company': '',
                    'role': 'free',
                    'is_premium': False
                }).execute()
            except:
                pass
            
            return {
                'id': user_id,
                'email': email,
                'username': username,
                'role': 'free',
                'is_premium': False
            }
            
    except Exception as e:
        print(f"Login error: {str(e)}")  # For debugging
        return None

# ----------------------
# Enhanced Validation
# ----------------------

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email) is not None

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Username is valid"

# ----------------------
# Enhanced Login/Register Page
# ----------------------

def show_login_page():
    apply_futuristic_theme()

    st.markdown("""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.9);
                border-radius: 20px; border: 2px solid #00ffff; margin-bottom: 30px;">
        <h1 style="margin: 0;">🛡️ THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8;">Secure Cloud Access Portal</p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

    # Login tab
    with tab1:
        st.markdown("### Welcome Back")
        with st.form("login_form", clear_on_submit=True):
            email = st.text_input("Email", placeholder="your@email.com")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            col1, col2 = st.columns(2)
            with col1:
                submit = st.form_submit_button("LOGIN", type="primary", use_container_width=True)
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("[Forgot password?](#)")

            if submit:
                if not email or not password:
                    st.error("Please enter both email and password")
                elif not validate_email(email):
                    st.error("Please enter a valid email address")
                else:
                    with st.spinner("Authenticating..."):
                        user = verify_user(email, password)
                        if user:
                            st.session_state.authenticated = True
                            st.session_state.user = user
                            st.success(f"✅ Welcome back, {user['username']}!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Invalid email or password. Please try again.")

    # Register tab  
    with tab2:
        st.markdown("### Create Account")
        with st.form("register_form", clear_on_submit=False):
            col1, col2 = st.columns(2)
            
            with col1:
                reg_name = st.text_input("Full Name*", placeholder="John Doe")
                reg_email = st.text_input("Email*", placeholder="john@example.com")
                reg_username = st.text_input("Username*", placeholder="johndoe",
                                            help="3+ characters, letters/numbers/underscore only")
            
            with col2:
                reg_company = st.text_input("Company", placeholder="Optional")
                reg_password = st.text_input("Password*", type="password", 
                                           placeholder="Min 6 chars with letters & numbers")
                reg_password2 = st.text_input("Confirm Password*", type="password",
                                             placeholder="Re-enter password")
            
            terms = st.checkbox("I agree to Terms of Service")
            register = st.form_submit_button("CREATE ACCOUNT", type="primary", use_container_width=True)

            if register:
                # Validation
                errors = []
                
                if not all([reg_name, reg_email, reg_username, reg_password]):
                    errors.append("All fields marked with * are required")
                
                if reg_email and not validate_email(reg_email):
                    errors.append("Invalid email format")
                
                if reg_username:
                    valid_username, username_msg = validate_username(reg_username)
                    if not valid_username:
                        errors.append(username_msg)
                
                if reg_password != reg_password2:
                    errors.append("Passwords don't match")
                elif reg_password:
                    valid_password, password_msg = validate_password(reg_password)
                    if not valid_password:
                        errors.append(password_msg)
                
                if not terms:
                    errors.append("You must accept the Terms of Service")
                
                # Show errors or create account
                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    with st.spinner("Creating your account..."):
                        success, message = create_user(
                            email=reg_email,
                            password=reg_password,
                            username=reg_username,
                            full_name=reg_name,
                            company=reg_company
                        )
                        
                        if success:
                            st.success(message)
                            st.info("👉 Please switch to the Login tab to access your account")
                            # Clear form values
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")

# ----------------------
# Page Config
# ----------------------

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
# DATA GENERATION AND FEEDS INTEGRATION
# ============================================================================

# @st.cache_data(ttl=600)  # Cache the data for 10 minutes
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
        "Malwarebytes": "https://blog.malwarebytes.com/feed/" # Commercial feed
    }
    
    all_articles = []
    for source, url in feeds.items():
        entries = get_rss_feed(url)
        for entry in entries:
            # Check for a valid publication date
            pub_date = entry.get('published_parsed')
            if pub_date:
                # Use a specific time zone for consistency if needed, e.g., UTC
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
                'is_human_targeted': True # News articles are relevant to human-targeted attacks
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
        'notes': 'Phishing is a common initial vector — defenses should combine prevention, detection, and rapid response (credential resets, log analysis).'
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
        'permissions_required': 'None — external network access sufficient',
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
        'notes': 'Preparation (contracts with providers, runbooks) is key — operational playbooks reduce downtime during an attack.'
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
        'notes': 'Scripting is commonly used for both benign admin tasks and malicious activity — robust logging + allowlisting reduce risk.'
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
        'notes': 'Memory-only techniques are harder to detect via file-based controls — focus on behavioral/telemetry-based detection.'
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
    # Already in your list
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

    # Nordic countries
    'Denmark': {'lat': 56.0, 'lon': 10.0, 'risk_level': 0.5},
    'Finland': {'lat': 64.0, 'lon': 26.0, 'risk_level': 0.6},
    'Iceland': {'lat': 65.0, 'lon': -18.0, 'risk_level': 0.4},
    'Norway': {'lat': 61.0, 'lon': 8.0, 'risk_level': 0.6},
    'Sweden': {'lat': 63.0, 'lon': 16.0, 'risk_level': 0.6},

    # Baltic countries
    'Estonia': {'lat': 59.0, 'lon': 26.0, 'risk_level': 0.5},
    'Latvia': {'lat': 57.0, 'lon': 25.0, 'risk_level': 0.5},
    'Lithuania': {'lat': 55.0, 'lon': 24.0, 'risk_level': 0.5},

    # Vietnam
    'Vietnam': {'lat': 14.0, 'lon': 108.0, 'risk_level': 0.6},

    # Remaining EU members (some duplicates above, but listed for completeness)
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
    
    recommendations = []
    
    # ISO 27001 based recommendations
    recommendations.append({
        'framework': 'ISO 27001',
        'priority': 'HIGH',
        'title': 'Information Security Management System (ISMS) Review',
        'threat': f'Multiple threat vectors detected across {len(threat_data["technique_name"].unique())} attack types',
        'controls': [
            '🔸 A.12.1.1 - Documented operating procedures',
            '🔸 A.12.6.1 - Management of technical vulnerabilities',
            '🔸 A.13.1.1 - Network controls and segmentation',
            '🔸 A.14.2.9 - System acceptance testing',
            '🔸 A.16.1.1 - Incident response procedures'
        ]
    })
    
    # NIST Cybersecurity Framework recommendations
    recommendations.append({
        'framework': 'NIST CSF',
        'priority': 'CRITICAL',
        'title': 'NIST Framework Core Functions Activation',
        'threat': f'Critical threats detected: {len(threat_data[threat_data["severity"] == "Critical"])} instances',
        'controls': [
            '🔸 IDENTIFY (ID.RA): Conduct immediate risk assessment',
            '🔸 PROTECT (PR.AC): Strengthen access control measures',
            '🔸 DETECT (DE.CM): Enhance continuous monitoring',
            '🔸 RESPOND (RS.AN): Activate incident analysis procedures',
            '🔸 RECOVER (RC.RP): Update recovery planning'
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
                    '🔸 Implement DMARC policy with p=reject',
                    '🔸 Deploy DKIM signing for all domains',
                    '🔸 Configure SPF records with -all',
                    '🔸 Enable ATP/Safe Links protection',
                    '🔸 Conduct phishing simulation training (NIST SP 800-50)'
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
                showscale=False,  # Remove the color scale ruler
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

# ============================================================================
# POPUP MODAL FUNCTIONS
# ============================================================================

def show_threat_details_popup(threats_df, filter_type='all'):
    """Display threat details in a popup-style expander"""
    
    with st.expander(f"📋 Threat Details - {filter_type}", expanded=True):
        if filter_type == 'critical':
            display_df = threats_df[threats_df['severity'] == 'Critical']
        elif filter_type == 'active':
            display_df = threats_df[threats_df['active'] == True]
        else:
            display_df = threats_df
        
        # Display summary
        st.markdown(f"""
        <div style="padding: 10px; background: rgba(20, 25, 47, 0.7); border: 1px solid #00ffff; border-radius: 10px; margin-bottom: 10px;">
            <span style="color: #00ffff; font-weight: bold;">Total Threats:</span> {len(display_df)} | 
            <span style="color: #ff0000; font-weight: bold;">Critical:</span> {len(display_df[display_df['severity'] == 'Critical'])} | 
            <span style="color: #ffff00; font-weight: bold;">Active:</span> {len(display_df[display_df['active'] == True])}
        </div>
        """, unsafe_allow_html=True)
        
        # Display detailed table
        if not display_df.empty:
            st.dataframe(
                display_df[['threat_id', 'timestamp', 'technique_name', 'severity', 
                           'target_country', 'target_sector', 'confidence', 'active']].head(50),
                use_container_width=True,
                height=400
            )


# MAIN FUNCTION ----------------------

def main():
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    
    # Check authentication
    if not st.session_state.authenticated:
        show_login_page()
        return
    
    # User is authenticated - show dashboard
    apply_futuristic_theme()
    initialize_auto_update()
    
    # Get user info
    user = st.session_state.user
    is_premium = user.get('is_premium', False)
    
    # Initialize session state
    if 'threat_data' not in st.session_state:
        st.session_state.threat_data = ThreatIntelligence.generate_threat_feed(1000)
    
    # Auto-update check (every 5 minutes)
    if check_auto_update():
        new_threats = ThreatIntelligence.generate_threat_feed(10)
        st.session_state.threat_data = pd.concat([new_threats, st.session_state.threat_data]).reset_index(drop=True)
        st.session_state.threat_data = st.session_state.threat_data.head(1000)
    
    # Calculate time until next update
    seconds_since_update = (datetime.now() - st.session_state.last_update).total_seconds()
    seconds_until_next = 300 - seconds_since_update
    minutes_until_next = int(seconds_until_next // 60)
    seconds_remainder = int(seconds_until_next % 60)
    
    # Header with user info and logout
    col1, col2, col3 = st.columns([6, 2, 1])
    
  #  with col1:
   #     st.markdown(f"""
    #    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
     #               backdrop-filter: blur(20px); border-radius: 20px; 
      #              border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;
       #             box-shadow: 0 0 40px rgba(0, 255, 255, 0.2);">
        #    <h1 style="margin: 0;">THREAT INTELLIGENCE PLATFORM</h1>
         #   <p style="color: #b8bcc8; font-size: 1.1em; margin-top: 10px; letter-spacing: 2px;">
          #      REAL-TIME THREAT DETECTION • AUTO-UPDATING FEEDS • PREDICTIVE ANALYTICS
           # </p>
            #<p style="color: #00ff00; font-size: 0.9em; margin-top: 5px;">
             #   🟢 FEEDS AUTO-UPDATE EVERY 5 MINUTES | Last Update: {st.session_state.last_update.strftime('%H:%M:%S')} | 
              #  Next Update in: {minutes_until_next}m {seconds_remainder}s
            #</p>
        #</div>
        #""", unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div style="padding: 15px; background: rgba(20, 25, 47, 0.8); 
                    border-radius: 10px; border: 1px solid #00ffff; text-align: center;">
            <p style="margin: 0; color: #00ffff;">👤 {user['username']}</p>
            <p style="margin: 0; color: {'gold' if is_premium else '#b8bcc8'}; font-size: 0.9em;">
                {'⭐ PREMIUM' if is_premium else '🆓 FREE'}
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        if st.button("🚪 Logout", use_container_width=True):
            supabase.auth.sign_out()
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()
    
    # REST OF YOUR EXISTING CODE CONTINUES HERE (Sidebar and all tabs)
    # The entire sidebar code and tabs code remains exactly the same

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
    seconds_until_next = 300 - seconds_since_update  # 5 minutes = 300 seconds
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
            REAL-TIME THREAT DETECTION • AUTO-UPDATING FEEDS • PREDICTIVE ANALYTICS
        </p>
        <p style="color: #00ff00; font-size: 0.9em; margin-top: 5px;">
            🟢 FEEDS AUTO-UPDATE EVERY 5 MINUTES | Last Update: {st.session_state.last_update.strftime('%H:%M:%S')} | 
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
        st.markdown("### ⏰ TIME RANGE")
        time_option = st.radio(
            "Select time range option",
            options=['Quick Select', 'Custom Range'],
            horizontal=True
        )
        
        if time_option == 'Quick Select':
            time_range = st.selectbox(
                "Quick time ranges",
                options=['Last 1 Hour', 'Last 6 Hours', 'Last 24 Hours', 'Last 7 Days', 'Last 30 Days'],
                index=3  # Default to Last 7 Days
            )
            # Map time range to filter
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
            # Convert to datetime for filtering
            time_cutoff = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
        
        st.markdown("---")
        
        # Attack Type Filter - All selected by default
        st.markdown("### 🎯 ATTACK TYPE")
        attack_types = list(ThreatIntelligence.ATTACK_TECHNIQUES.values())
        attack_type_names = [attack['name'] for attack in attack_types]
        
        # Select/Deselect All buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_attacks"):
                st.session_state.selected_attacks = attack_type_names
        with col2:
            if st.button("Clear All", key="clear_all_attacks"):
                st.session_state.selected_attacks = []
        
        if 'selected_attacks' not in st.session_state:
            st.session_state.selected_attacks = attack_type_names  # All selected by default
        
        selected_attacks = st.multiselect(
            "Click to deselect",
            options=attack_type_names,
            default=st.session_state.selected_attacks,
            key="attack_filter"
        )
        st.session_state.selected_attacks = selected_attacks
        
        # Target Country Filter - All selected by default
        st.markdown("### 🌍 TARGET COUNTRY")
        countries = list(ThreatIntelligence.COUNTRIES.keys())
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_countries"):
                st.session_state.selected_countries = countries
        with col2:
            if st.button("Clear All", key="clear_all_countries"):
                st.session_state.selected_countries = []
        
        if 'selected_countries' not in st.session_state:
            st.session_state.selected_countries = countries  # All selected by default
        
        selected_countries = st.multiselect(
            "Click to deselect",
            options=countries,
            default=st.session_state.selected_countries,
            key="country_filter"
        )
        st.session_state.selected_countries = selected_countries
        
        # Sector Filter - All selected by default
        st.markdown("### 🏢 TARGET SECTOR")
        sectors = ThreatIntelligence.SECTORS
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="select_all_sectors"):
                st.session_state.selected_sectors = sectors
        with col2:
            if st.button("Clear All", key="clear_all_sectors"):
                st.session_state.selected_sectors = []
        
        if 'selected_sectors' not in st.session_state:
            st.session_state.selected_sectors = sectors  # All selected by default
        
        selected_sectors = st.multiselect(
            "Click to deselect",
            options=sectors,
            default=st.session_state.selected_sectors,
            key="sector_filter"
        )
        st.session_state.selected_sectors = selected_sectors
        
        # Severity Filter - All selected by default
        st.markdown("### ⚠️ SEVERITY")
        severity_options = ['Critical', 'High', 'Medium', 'Low']
        
        if 'selected_severity' not in st.session_state:
            st.session_state.selected_severity = severity_options  # All selected by default
        
        severity_levels = st.multiselect(
            "Severity levels",
            options=severity_options,
            default=st.session_state.selected_severity,
            key="severity_filter"
        )
        st.session_state.selected_severity = severity_levels
        
        # Confidence threshold
        st.markdown("### 🎯 CONFIDENCE")
        confidence_threshold = st.slider(
            "Minimum Confidence (%)",
            min_value=0,
            max_value=100,
            value=60,
            step=10
        )
        
        st.markdown("---")
        
        if st.button("🔄 APPLY FILTERS", use_container_width=True, type="primary"):
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
        "🎯 Threat Overview",
        "👤 Human Targeted",
        "🌍 Global Threats",
        "📊 Intelligence Analysis",
        "💡 Security Recommendations",
        "📈 Trend Analysis",
        "🔍 IOC Scanner",
    ])
    
    # Tab 1: Threat Overview
    with main_tabs[0]:
        # Key Metrics
        st.markdown("### 📊 KEY THREAT METRICS")
        
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
        
        # Live Threat Feed with proper styling
        st.markdown("### 🔴 LIVE THREAT FEED")
        
        # Create a container for the scrollable feed
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
                
                status = '🛡️ BLOCKED' if threat['blocked'] else '⚠️ ACTIVE'
                status_color = '#00ff00' if threat['blocked'] else '#ff0000'
                
                # Create properly styled threat cards
                with st.container():
                    st.markdown(f"""
                    <div style="padding: 15px; margin: 10px 0; 
                                background: linear-gradient(135deg, rgba(20, 25, 47, 0.8), rgba(30, 35, 57, 0.6));
                                border-left: 4px solid {severity_color}; 
                                border-radius: 10px;
                                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
                                transition: all 0.3s ease;">
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
                            <span style="color: #bf00ff;">Confidence:</span> <span style="color: #00ffff;">{threat['confidence']}%</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        # Charts
        st.markdown("### 📊 THREAT ANALYTICS")
        
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            # Kill Chain with hover descriptions
            st.plotly_chart(create_kill_chain_with_hover(threat_df), use_container_width=True)
        
        with chart_col2:
            # Severity distribution
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
        st.markdown("### 🌍 GLOBAL THREAT LANDSCAPE")
        st.markdown("*Click and drag to rotate the globe. Click on a country to see detailed threat analysis.*")
        
        # 3D Interactive Globe
        globe_fig = create_3d_globe_threats(threat_df)
        
        # Make the globe interactive with click events
        globe_placeholder = st.plotly_chart(globe_fig, use_container_width=True, key="globe_chart")
        
        # Country selector for detailed view
        st.markdown("### 📊 SELECT A COUNTRY FOR DETAILED ANALYSIS")
        
        if not threat_df.empty:
            # Get list of countries with threats
            countries_with_threats = threat_df['target_country'].unique()
            
            # Create a selectbox for country selection
            selected_country = st.selectbox(
                "Choose a country to analyze:",
                options=['None'] + sorted(countries_with_threats.tolist()),
                key="country_selector"
            )
            
            # Show detailed analysis if a country is selected
            if selected_country != 'None':
                country_threats = threat_df[threat_df['target_country'] == selected_country]
                
                if not country_threats.empty:
                    st.markdown(f"### 🎯 DETAILED THREAT ANALYSIS: {selected_country}")
                    
                    # Summary metrics
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
                    
                    # Detailed threat table with better styling
                    st.markdown("#### 📋 THREAT DETAILS")
                    
                    # Prepare display data
                    display_data = country_threats[['timestamp', 'technique_name', 'technique_description', 
                                                   'severity', 'threat_actor', 'target_sector', 
                                                   'blocked', 'active', 'confidence']].copy()
                    display_data['Status'] = display_data.apply(
                        lambda x: '🛡️ Blocked' if x['blocked'] else '⚠️ Active', axis=1
                    )
                    display_data = display_data.drop(['blocked', 'active'], axis=1)
                    display_data.columns = ['Timestamp', 'Attack Type', 'Description', 'Severity', 
                                           'Threat Actor', 'Target Sector', 'Confidence %', 'Status']
                    
                    # Display the styled table
                    st.dataframe(
                        display_data.head(50),
                        use_container_width=True,
                        height=400
                    )
                    
                    # Attack distribution charts
                    chart_col1, chart_col2 = st.columns(2)
                    
                    with chart_col1:
                        # Attack types distribution
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
                        # Sectors targeted
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



    # Tab 3: Intelligence Analysis
    with main_tabs[3]:
       # if not is_premium:
        #    st.markdown("""
         #   <div style="padding: 40px; background: rgba(20, 25, 47, 0.95);
          #          border: 2px solid gold; border-radius: 20px; text-align: center;">
           #     <h2>🔒 Premium Feature</h2>
            #    <p>This feature requires a Premium subscription</p>
             #   <p>Contact admin to upgrade your account</p>
            #</div>
            #""", unsafe_allow_html=True)
        #else:
    
        
         if not threat_df.empty:
            anal_col1, anal_col2 = st.columns(2)
            
            with anal_col1:
                st.markdown("#### 🎯 ATTACK TECHNIQUES (Click for details)")
                
                technique_stats = threat_df.groupby(['technique_id', 'technique_name', 'technique_description']).size().reset_index(name='count')
                technique_stats = technique_stats.nlargest(5, 'count')
                
                for idx, row in technique_stats.iterrows():
                    with st.expander(f"{row['technique_id']}: {row['technique_name']} ({row['count']} attacks)"):
                        st.markdown(f"**Description:** {row['technique_description']}")
                        
                        # Get threats for this technique
                        technique_threats = threat_df[threat_df['technique_id'] == row['technique_id']]
                        
                        # Show affected countries and sectors
                        affected_countries = technique_threats['target_country'].value_counts().head(5)
                        affected_sectors = technique_threats['target_sector'].value_counts().head(5)
                        
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.markdown("**Top Affected Countries:**")
                            for country, count in affected_countries.items():
                                st.markdown(f"• {country}: {count} attacks")
                        
                        with col_b:
                            st.markdown("**Top Affected Sectors:**")
                            for sector, count in affected_sectors.items():
                                st.markdown(f"• {sector}: {count} attacks")
            
            with anal_col2:
                st.markdown("#### 🎭 THREAT ACTORS (Click for details)")
                
                actor_stats = threat_df['threat_actor'].value_counts().head(5)
                
                for actor, count in actor_stats.items():
                    actor_info = ThreatIntelligence.THREAT_ACTORS.get(actor, {})
                    
                    with st.expander(f"{actor} ({count} attacks) - {actor_info.get('origin', 'Unknown')}"):
                        st.markdown(f"**Description:** {actor_info.get('description', 'No description available')}")
                        st.markdown(f"**Sophistication:** {actor_info.get('sophistication', 'Unknown')}")
                        
                        # Get threats for this actor
                        actor_threats = threat_df[threat_df['threat_actor'] == actor]
                        
                        # Show attack types and targets
                        attack_types = actor_threats['technique_name'].value_counts().head(3)
                        target_countries = actor_threats['target_country'].value_counts().head(3)
                        target_sectors = actor_threats['target_sector'].value_counts().head(3)
                        
                        st.markdown("**Primary Attack Types:**")
                        for attack, count in attack_types.items():
                            st.markdown(f"• {attack}: {count} instances")
                        
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.markdown("**Target Countries:**")
                            for country, count in target_countries.items():
                                st.markdown(f"• {country}: {count}")
                        
                        with col_b:
                            st.markdown("**Target Sectors:**")
                            for sector, count in target_sectors.items():
                                st.markdown(f"• {sector}: {count}")
         else:
            st.info("No threat data available with current filters")

    # Tab 3: Human-Targeted Attacks
    with main_tabs[1]:
        st.markdown("### 👤 HUMAN-TARGETED ATTACK ANALYSIS")
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
            st.markdown("#### 📊 HUMAN-TARGETED ATTACK METRICS")
            
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
        if not human_targeted_threats.empty:
            st.markdown("#### 🔴 RECENT HUMAN-TARGETED ATTACKS")
            
            recent_human = human_targeted_threats.nlargest(10, 'timestamp')
            for _, attack in recent_human.iterrows():
                status_color = '#00ff00' if attack['blocked'] else '#ff0000'
                status_text = '🛡️ Blocked' if attack['blocked'] else '⚠️ Active'
                
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
            st.info("No threat data available with current filters")


    # Tab 4: Security Recommendations
    with main_tabs[4]:
        st.markdown("### 💡 SECURITY RECOMMENDATIONS (ISO 27001 & NIST)")
        
        recommendations = get_security_recommendations(threat_df)
        
        # Framework-based recommendations
        st.markdown("#### 📋 FRAMEWORK-BASED CONTROLS")
        for rec in recommendations:
            priority_color = {
                'CRITICAL': '#ff0000',
                'HIGH': '#ff7f00',
                'MEDIUM': '#ffff00'
            }.get(rec['priority'], '#00ff00')
            
            with st.expander(f"⚠️ [{rec['framework']}] {rec['title']} - {rec['priority']} PRIORITY", expanded=False):
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
        st.markdown("#### 📚 SECURITY BEST PRACTICES FLASHCARDS")
        
        # Define flashcards based on current threats
        top_threats = threat_df['technique_name'].value_counts().head(3) if not threat_df.empty else pd.Series()
        
        flashcards = [
            {
                'title': 'Zero Trust Architecture',
                'icon': '🔐',
                'content': 'Implement "never trust, always verify" principle. Require continuous verification for all users and devices.',
                'action': 'Deploy microsegmentation and identity-based access controls',
                'priority': 'CRITICAL' if 'Phishing' in top_threats.index else 'HIGH'
            },
            {
                'title': 'Threat Hunting Program',
                'icon': '🎯',
                'content': 'Proactively search for cyber threats that evade existing security solutions.',
                'action': 'Use threat intelligence feeds to hunt for IOCs in your environment',
                'priority': 'HIGH'
            },
            {
                'title': 'Incident Response Plan',
                'icon': '📋',
                'content': 'Maintain an updated IR plan with clear roles and recovery procedures.',
                'action': 'Conduct tabletop exercises quarterly and update contact lists',
                'priority': 'CRITICAL' if critical_threats > 10 else 'HIGH'
            },
            {
                'title': 'Security Awareness Training',
                'icon': '🎓',
                'content': 'Regular training on latest threats, especially phishing and social engineering.',
                'action': 'Implement monthly phishing simulations and track metrics',
                'priority': 'CRITICAL' if 'Phishing' in top_threats.index else 'MEDIUM'
            }
        ]
        
        # Display flashcards in a grid
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
                            min-height: 250px; 
                            position: relative;">
                    
                    <div style="position: absolute; top: -10px; right: -10px; 
                                padding: 5px 10px; border-radius: 20px;
                                background: {priority_color};
                                color: white; font-size: 0.8em; font-weight: bold;">
                        {card['priority']}
                    </div>
                    
                    <div style="font-size: 3em; text-align: center; margin-bottom: 15px;">
                        {card['icon']}
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
    
    # Tab 5: Trend Analysis
    with main_tabs[5]:
        st.markdown("### 📈 CUSTOMIZABLE TREND ANALYSIS")
        
        if not threat_df.empty:
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
            
            # Create trend chart
            trend_chart = create_trend_analysis_charts(
                threat_df,
                attack_type=None if trend_attack == 'All' else trend_attack,
                country=None if trend_country == 'All' else trend_country,
                sector=None if trend_sector == 'All' else trend_sector,
                time_range=trend_time
            )
            
            st.plotly_chart(trend_chart, use_container_width=True)
        else:
            st.info("No data available for trend analysis")
    
    # Tab 6: IOC Scanner
    with main_tabs[6]:
        st.markdown("### 🔍 IOC SCANNER & THREAT DETECTION")
        
        ioc_input = st.text_input(
            "Enter IOC (Hash, IP, Domain, or URL)",
            placeholder="e.g., 192.168.1.1, malicious.com, d41d8cd98f00b204e9800998ecf8427e"
        )
        
        if st.button("🔍 SCAN IOC"):
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

if __name__ == "__main__":
    # Run the main function
    main()
