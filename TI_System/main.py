#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pycountry
import os
import requests
from io import BytesIO
import glob
from importlib import util
import datetime

# -------------------------------
# MODERN STYLING & CONFIG
# -------------------------------
st.set_page_config(
    page_title="NIMBLR Threat Intelligence", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for futuristic dark theme with neon yellow
st.markdown("""
<style>
    /* Main theme */
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
        color: #ffffff;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #111111 0%, #222222 100%);
        border-right: 2px solid #ffff00;
        box-shadow: 0 0 20px rgba(255, 255, 0, 0.3);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #ffff00;
        text-shadow: 0 0 10px rgba(255, 255, 0, 0.5);
        font-family: 'Courier New', monospace;
    }
    
    /* Metrics */
    .metric-container {
        background: linear-gradient(145deg, #1a1a1a, #2a2a2a);
        border: 1px solid #ffff00;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 0 15px rgba(255, 255, 0, 0.2);
        margin: 10px 0;
    }
    
    /* Risk score styling */
    .risk-high { color: #ff4444; font-weight: bold; }
    .risk-medium { color: #ffaa00; font-weight: bold; }
    .risk-low { color: #44ff44; font-weight: bold; }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(45deg, #ffff00, #cccc00);
        color: #000000;
        border: none;
        border-radius: 5px;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        box-shadow: 0 0 20px rgba(255, 255, 0, 0.8);
        transform: translateY(-2px);
    }
    
    /* Select boxes */
    .stSelectbox > div > div {
        background-color: #2a2a2a;
        border: 1px solid #ffff00;
    }
    
    /* Multi-select */
    .stMultiSelect > div > div {
        background-color: #2a2a2a;
        border: 1px solid #ffff00;
    }
    
    /* Data frames */
    .dataframe {
        background-color: #1a1a1a;
        border: 1px solid #ffff00;
    }
    
    /* Navigation */
    .stRadio > div {
        background: linear-gradient(145deg, #2a2a2a, #1a1a1a);
        border-radius: 10px;
        padding: 10px;
        border: 1px solid #ffff00;
    }
    
    /* Footer */
    .footer {
        background: linear-gradient(90deg, #ffff00, #cccc00);
        color: #000000;
        padding: 10px;
        text-align: center;
        margin-top: 50px;
        border-radius: 5px;
        font-weight: bold;
    }
    
    /* Glowing text effect */
    .glow-text {
        color: #ffff00;
        text-shadow: 0 0 5px #ffff00, 0 0 10px #ffff00, 0 0 15px #ffff00;
    }
</style>
""", unsafe_allow_html=True)

# NIMBLR branding header
st.markdown("""
<div style="text-align: center; padding: 20px; background: linear-gradient(90deg, #111111, #222222); border-radius: 10px; margin-bottom: 30px; border: 2px solid #ffff00; box-shadow: 0 0 20px rgba(255, 255, 0, 0.3);">
    <h1 class="glow-text">THREAT INTELLIGENCE REPORT</h1>
</div>
""", unsafe_allow_html=True)

GITHUB_USER = "CyberSwoldier"
GITHUB_REPO = "Threat-Intelligence-NIMBLR"
GITHUB_BRANCH = "main"
REPORTS_FOLDER = "reports"
API_URL = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{REPORTS_FOLDER}?ref={GITHUB_BRANCH}"

# -------------------------------
# FETCH threat_intel.py (optional)
# -------------------------------
GITHUB_RAW_URL = "https://raw.githubusercontent.com/CyberSwoldier/Threat-Intelligence-Report/main/threat_intel.py"
try:
    r = requests.get(GITHUB_RAW_URL)
    r.raise_for_status()
    with open("threat_intel.py", "w", encoding="utf-8") as f:
        f.write(r.text)
except Exception:
    pass

try:
    spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
    threat_intel = util.module_from_spec(spec)
    spec.loader.exec_module(threat_intel)
except Exception:
    threat_intel = None

# -------------------------------
# ENHANCED RISK SCORING FUNCTIONS WITH REGIONAL FOCUS
# -------------------------------
def get_nordic_baltic_countries():
    """Return list of Nordic and Baltic countries"""
    return [
        "Sweden", "Norway", "Denmark", "Finland", "Iceland",
        "Estonia", "Latvia", "Lithuania"
    ]

def calculate_iso_risk_score(ttp_count, country_count, source_count, regional_focus=False):
    """Calculate risk score based on ISO 27005 framework"""
    # Adjust weights for regional focus
    regional_multiplier = 1.2 if regional_focus else 1.0
    
    # Threat frequency weight (based on TTP count)
    threat_frequency = min(ttp_count / 50, 1.0) * 30 * regional_multiplier
    
    # Geographic spread weight (based on countries affected)
    geographic_spread = min(country_count / 20, 1.0) * 25 * regional_multiplier
    
    # Source diversity weight (multiple sources indicate broader threat)
    source_diversity = min(source_count / 10, 1.0) * 20
    
    # Base threat level
    base_threat = 25
    
    total_score = threat_frequency + geographic_spread + source_diversity + base_threat
    return min(total_score, 100)

def calculate_nist_risk_score(ttp_count, country_count, unique_techniques, regional_focus=False):
    """Calculate risk score based on NIST SP 800-30 framework"""
    # Adjust for regional focus
    regional_multiplier = 1.15 if regional_focus else 1.0
    
    # Likelihood based on technique diversity
    likelihood = min(len(unique_techniques) / 30, 1.0) * 40 * regional_multiplier
    
    # Impact based on geographical spread
    impact = min(country_count / 15, 1.0) * 35 * regional_multiplier
    
    # Vulnerability based on TTP frequency
    vulnerability = min(ttp_count / 40, 1.0) * 25
    
    total_score = likelihood + impact + vulnerability
    return min(total_score, 100)

def get_security_awareness_recommendations(iso_score, nist_score, top_ttps, affected_countries):
    """Generate detailed security awareness recommendations based on threat analysis using NIMBLR Security offerings"""
    avg_risk = (iso_score + nist_score) / 2
    nordic_baltic = get_nordic_baltic_countries()
    regional_impact = any(country in nordic_baltic for country in affected_countries)
    
    recommendations = {
        "priority_level": "",
        "nimblr_simulations": [],
        "nimblr_courses": [],
        "technical_measures": [],
        "regional_considerations": []
    }
    
    # Priority level determination
    if avg_risk >= 75:
        recommendations["priority_level"] = "CRITICAL - Immediate Action Required"
        
        recommendations["nimblr_simulations"] = [
            "Advanced Spear-Phishing Simulations (Internal Impersonation)",
            "CEO Fraud & Wire Transfer Simulations",
            "Ransomware Distribution via Email Attachments",
            "Office 365 Credential Harvesting Simulations",
            "Social Engineering Phone Call Simulations",
            "Malicious Link Simulations (Document/PDF-based)",
            "Supply Chain Attack Email Simulations"
        ]
        
        recommendations["nimblr_courses"] = [
            "Zero-Day Classes: Advanced Persistent Threats in Nordic Region",
            "Micro Training: Executive-Targeted Social Engineering",
            "Zero-Day Classes: Nation-State Attack Vectors",
            "Micro Training: Critical Infrastructure Protection",
            "Zero-Day Classes: Supply Chain Security Risks",
            "Micro Training: Incident Response for Leadership"
        ]
        
    elif avg_risk >= 50:
        recommendations["priority_level"] = "ELEVATED - Enhanced Monitoring"
        
        recommendations["nimblr_simulations"] = [
            "Business Email Compromise (BEC) Simulations",
            "Fake Security Alert Simulations",
            "Document-Based Malware Simulations",
            "Social Media Impersonation Attacks",
            "Urgent Payment Request Simulations",
            "Fake IT Support Email Simulations",
            "Seasonal/Holiday-Themed Phishing"
        ]
        
        recommendations["nimblr_courses"] = [
            "Micro Training: Email Security Fundamentals",
            "Zero-Day Classes: Current Ransomware Trends",
            "Micro Training: Password Security & MFA",
            "Zero-Day Classes: Business Email Compromise Prevention",
            "Micro Training: Safe Remote Work Practices",
            "Zero-Day Classes: Cloud Security Awareness"
        ]
        
    else:
        recommendations["priority_level"] = "STANDARD - Maintain Vigilance"
        
        recommendations["nimblr_simulations"] = [
            "General Phishing Awareness Simulations",
            "Fake Prize/Gift Card Simulations",
            "Basic Password Reset Simulations",
            "USB/Physical Security Simulations",
            "Social Media Friend Request Tests",
            "Basic Malware Download Simulations"
        ]
        
        recommendations["nimblr_courses"] = [
            "Micro Training: Phishing Recognition Basics",
            "Micro Training: Password Hygiene",
            "Micro Training: Safe Browsing Practices",
            "Micro Training: Social Media Security",
            "Micro Training: Physical Security Awareness",
            "Micro Training: Data Protection Basics"
        ]
    
    # Technical measures based on common TTPs
    common_ttps = [ttp.lower() for ttp in top_ttps[:5] if ttp]
    
    if any("phishing" in ttp or "email" in ttp for ttp in common_ttps):
        recommendations["technical_measures"].append("NIMBLR Email Security Gateway Integration")
        recommendations["technical_measures"].append("Advanced Phishing Simulation Whitelisting")
    
    if any("malware" in ttp or "trojan" in ttp for ttp in common_ttps):
        recommendations["technical_measures"].append("Enhanced Malware Simulation Delivery")
        recommendations["technical_measures"].append("Real-time Threat Intelligence Integration")
    
    if any("lateral" in ttp or "movement" in ttp for ttp in common_ttps):
        recommendations["technical_measures"].append("Internal Network Phishing Simulations")
        recommendations["technical_measures"].append("Cross-Department Social Engineering Tests")
    
    if any("credential" in ttp or "password" in ttp for ttp in common_ttps):
        recommendations["technical_measures"].append("Credential Harvesting Simulations")
        recommendations["technical_measures"].append("MFA Bypass Attempt Simulations")
    
    # Regional considerations for Nordic/Baltic with NIMBLR integration
    if regional_impact:
        recommendations["regional_considerations"] = [
            "Deploy Nordic-language Phishing Simulations (Swedish, Norwegian, Danish, Finnish)",
            "Implement region-specific compliance training (NIS2, GDPR, DORA)",
            "Configure simulations for Nordic business culture and communication styles",
            "Monitor Nordic threat intelligence feeds for Zero-Day Classes",
            "Coordinate with regional cybersecurity frameworks via NIMBLR reporting",
            "Customize simulations for Nordic/Baltic government and financial sectors"
        ]
    
    return recommendations

def get_trend_based_course_ideas(trend_data, selected_countries):
    """Generate new course and simulation ideas based on trending threats"""
    course_ideas = {
        "emerging_courses": [],
        "simulation_scenarios": [],
        "zero_day_classes": []
    }
    
    if not trend_data.empty:
        # Analyze trending TTPs
        trend_analysis = trend_data.groupby(['TTP', 'report_date']).size().reset_index(name='count')
        
        # Get TTPs with increasing trends
        trending_up = []
        for ttp in trend_analysis['TTP'].unique():
            ttp_data = trend_analysis[trend_analysis['TTP'] == ttp].sort_values('report_date')
            if len(ttp_data) > 1:
                recent_avg = ttp_data.tail(2)['count'].mean()
                older_avg = ttp_data.head(2)['count'].mean()
                if recent_avg > older_avg * 1.2:  # 20% increase
                    trending_up.append(ttp)
        
        # Generate course ideas based on trends
        for ttp in trending_up[:3]:  # Top 3 trending threats
            ttp_lower = ttp.lower()
            
            if "ai" in ttp_lower or "deepfake" in ttp_lower:
                course_ideas["emerging_courses"].append("AI-Generated Content Detection Training")
                course_ideas["simulation_scenarios"].append("Deepfake Voice Call Simulations")
                course_ideas["zero_day_classes"].append("AI-Powered Social Engineering Threats")
            
            elif "supply chain" in ttp_lower or "third party" in ttp_lower:
                course_ideas["emerging_courses"].append("Supply Chain Risk Assessment Training")
                course_ideas["simulation_scenarios"].append("Vendor Impersonation Simulations")
                course_ideas["zero_day_classes"].append("Third-Party Data Breach Notifications")
            
            elif "cloud" in ttp_lower or "saas" in ttp_lower:
                course_ideas["emerging_courses"].append("Multi-Cloud Security Awareness")
                course_ideas["simulation_scenarios"].append("Fake Cloud Service Notifications")
                course_ideas["zero_day_classes"].append("Cloud Configuration Attack Vectors")
            
            elif "mobile" in ttp_lower or "app" in ttp_lower:
                course_ideas["emerging_courses"].append("Mobile Device Threat Landscape")
                course_ideas["simulation_scenarios"].append("Malicious App Installation Tests")
                course_ideas["zero_day_classes"].append("BYOD Security Risks")
            
            elif "iot" in ttp_lower or "smart" in ttp_lower:
                course_ideas["emerging_courses"].append("IoT Security for Business Environments")
                course_ideas["simulation_scenarios"].append("Smart Device Compromise Scenarios")
                course_ideas["zero_day_classes"].append("Connected Device Privacy Risks")
        
        # Regional trend analysis
        nordic_baltic = get_nordic_baltic_countries()
        if selected_countries and any(c in nordic_baltic for c in selected_countries):
            course_ideas["emerging_courses"].append("Nordic Regulatory Compliance Update (NIS2)")
            course_ideas["simulation_scenarios"].append("Regional Government Impersonation Attacks")
            course_ideas["zero_day_classes"].append("Geopolitical Cyber Threats to Nordic Region")
    
    # Add baseline emerging threat courses
    if not course_ideas["emerging_courses"]:
        course_ideas["emerging_courses"] = [
            "Quantum Computing Impact on Encryption",
            "Remote Work Security Evolution",
            "Social Engineering via AI Chatbots"
        ]
        
    if not course_ideas["simulation_scenarios"]:
        course_ideas["simulation_scenarios"] = [
            "AI-Enhanced Phishing Campaign Simulations",
            "Hybrid Work Environment Attack Scenarios",
            "Next-Generation Ransomware Simulations"
        ]
        
    if not course_ideas["zero_day_classes"]:
        course_ideas["zero_day_classes"] = [
            "Emerging Threat Landscape 2025",
            "Post-Quantum Cryptography Preparation",
            "Advanced Persistent Threat Evolution"
        ]
    
    return course_ideas

def get_risk_level(score):
    """Determine risk level based on score"""
    if score >= 75:
        return "HIGH", "#ff4444"
    elif score >= 50:
        return "MEDIUM", "#ffaa00"
    else:
        return "LOW", "#44ff44"

# -------------------------------
# ENHANCED PLOTTING FUNCTIONS
# -------------------------------
def create_modern_plot_theme():
    """Return consistent modern theme for all plots"""
    return {
        'paper_bgcolor': '#0a0a0a',
        'plot_bgcolor': '#1a1a1a',
        'font': {'color': '#ffffff', 'family': 'Courier New'},
        'colorway': ['#ffff00', '#ffaa00', '#ff4444', '#44ff44', '#00aaff', '#aa44ff'],
        'margin': {'l': 0, 'r': 0, 't': 40, 'b': 20}
    }

def plot_risk_gauge(score, title, framework):
    """Create a modern gauge chart for risk scores"""
    level, color = get_risk_level(score)
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"{framework} Risk Score", 'font': {'color': '#ffff00', 'size': 16}},
        delta = {'reference': 50, 'increasing': {'color': "#ff4444"}, 'decreasing': {'color': "#44ff44"}},
        gauge = {
            'axis': {'range': [None, 100], 'tickcolor': '#ffff00'},
            'bar': {'color': color, 'thickness': 0.8},
            'bgcolor': '#2a2a2a',
            'borderwidth': 2,
            'bordercolor': '#ffff00',
            'steps': [
                {'range': [0, 50], 'color': 'rgba(68, 255, 68, 0.2)'},
                {'range': [50, 75], 'color': 'rgba(255, 170, 0, 0.2)'},
                {'range': [75, 100], 'color': 'rgba(255, 68, 68, 0.2)'}
            ],
            'threshold': {
                'line': {'color': "#ffffff", 'width': 4},
                'thickness': 0.75,
                'value': score
            }
        }
    ))
    
    # Create theme but override font settings
    theme = create_modern_plot_theme()
    theme['font'] = {'color': '#ffffff', 'size': 12, 'family': 'Courier New'}
    theme['height'] = 300
    
    fig.update_layout(**theme)
    
    return fig

def plot_heatmap(df, x_col, y_col, title, x_order=None, y_order=None, height=500):
    if df.empty:
        st.info("⚠️ No data available to display heatmap.")
        return
        
    pivot = df.pivot(index=y_col, columns=x_col, values="count").fillna(0)
    if y_order:
        pivot = pivot.reindex(index=y_order, fill_value=0)
    if x_order:
        pivot = pivot.reindex(columns=x_order, fill_value=0)

    z_values = pivot.values
    text_values = np.where(z_values > 0, z_values.astype(int), "")

    fig = go.Figure(go.Heatmap(
        z=z_values,
        x=list(pivot.columns),
        y=list(pivot.index),
        colorscale=[[0, '#1a1a1a'], [0.5, '#ffaa00'], [1, '#ffff00']],
        text=text_values,
        texttemplate="%{text}",
        textfont={"size": 10, "color": "#ffffff"},
        hovertemplate=f"{x_col}: %{{x}}<br>{y_col}: %{{y}}<br>Count: %{{z}}<extra></extra>",
        showscale=True,
        #colorbar={'bgcolor': '#2a2a2a', 'bordercolor': '#ffff00', 'borderwidth': 1},
        xgap=2,
        ygap=2
    ))

    fig.update_layout(
        **create_modern_plot_theme(),
        title={'text': title, 'y': 0.95, 'x': 0.5, 'xanchor': 'center'},
        height=height,
        xaxis={'showgrid': False, 'tickangle': 45},
        yaxis={'showgrid': False}
    )
    st.plotly_chart(fig, use_container_width=True)

# -------------------------------
# FETCH REPORTS
# -------------------------------
def fetch_reports(local_folder="reports"):
    os.makedirs(local_folder, exist_ok=True)
    try:
        r = requests.get(API_URL)
        r.raise_for_status()
        files = r.json()
    except Exception as e:
        st.error(f"❌ Failed to list files from GitHub: {e}")
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
                    st.sidebar.success(f"✅ Fetched {name}")
                except Exception as e:
                    st.sidebar.warning(f"⚠️ Failed {name}: {e}")
                    continue
            downloaded.append(local_path)
    return downloaded

# -------------------------------
# LOAD REPORTS
# -------------------------------
def load_reports(folder="reports"):
    files = glob.glob(f"{folder}/ttp_reports_*.xlsx")
    all_data = []
    for f in files:
        try:
            xls = pd.ExcelFile(f)
            sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
            if "Human_Attacks" not in xls.sheet_names:
                st.warning(f"⚠️ 'Human_Attacks' sheet not found in {f}, using '{sheet_name}' instead.")
            df = pd.read_excel(xls, sheet_name=sheet_name)
            date_str = os.path.basename(f).replace("ttp_reports_","").replace(".xlsx","")
            df["report_date"] = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
            all_data.append(df)
        except Exception as e:
            st.warning(f"⚠️ Could not read {f}: {e}")
            continue
    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        combined = combined.dropna(subset=["report_date"])
        if combined.empty:
            st.error("❌ No valid data after combining reports.")
            st.stop()
        return combined
    else:
        st.error("❌ No report files found.")
        st.stop()

# -------------------------------
# FETCH & LOAD
# -------------------------------
fetch_reports(REPORTS_FOLDER)
items = load_reports(REPORTS_FOLDER)

# -------------------------------
# DETECT COLUMNS
# -------------------------------
ttp_columns = [c for c in items.columns if c.lower().startswith("ttp_desc")]
country_columns = [c for c in items.columns if c.lower().startswith("country_")]

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def country_to_iso3(name):
    try:
        return pycountry.countries.lookup(name).alpha_3
    except LookupError:
        return None

# -------------------------------
# ENHANCED SIDEBAR NAVIGATION
# -------------------------------
st.sidebar.markdown("""
<div style="text-align: center; padding: 15px; background: linear-gradient(45deg, #ffff00, #cccc00); border-radius: 10px; margin-bottom: 20px;">
    <h3 style="color: #000000; margin: 0;"> NAVIGATION</h3>
</div>
""", unsafe_allow_html=True)

page = st.sidebar.radio(
    "Select Intelligence Module:",
    ["🏠 Dashboard", "📈 Trends", "ℹ️ About"],
    label_visibility="collapsed"
)

# -------------------------------
# RISK ASSESSMENT SIDEBAR
# -------------------------------
if page == "🏠 Dashboard":
    st.sidebar.markdown("""
    <div style="margin-top: 30px; padding: 15px; background: linear-gradient(145deg, #2a2a2a, #1a1a1a); border: 1px solid #ffff00; border-radius: 10px;">
        <h4 class="glow-text"> RISK ASSESSMENT</h4>
    </div>
    """, unsafe_allow_html=True)

# -------------------------------
# ABOUT PAGE
# -------------------------------
if page == "ℹ️ About":
    st.markdown("""
    <div style="padding: 30px; background: linear-gradient(145deg, #1a1a1a, #2a2a2a); border: 2px solid #ffff00; border-radius: 15px; margin: 20px 0;">
        <h2 class="glow-text"> Threat Intelligence Platform</h2>
        <p style="font-size: 16px; line-height: 1.6;">
        This advanced cybersecurity intelligence dashboard provides real-time threat analysis updated every Friday, 
        delivering comprehensive insights from the past 7 days of global threat landscape.
        </p>
        
        <h3 style="color: #ffff00; margin-top: 30px;">🎯 Core Features</h3>
        <ul style="font-size: 14px; line-height: 1.8;">
            <li><strong>Dashboard Module:</strong> Interactive threat visualization with global mapping, MITRE ATT&CK techniques analysis, and risk scoring based on ISO 27005 and NIST SP 800-30 frameworks</li>
            <li><strong>Trends Module:</strong> Multi-temporal analysis for tracking threat evolution and identifying emerging patterns across different time periods</li>
            <li><strong>Advanced Search:</strong> Intelligent data mining capabilities with Excel export functionality for detailed investigation</li>
            <li><strong>Risk Assessment:</strong> Real-time risk scoring using industry-standard frameworks with detailed explanations and recommendations</li>
        </ul>
        
        <h3 style="color: #ffff00; margin-top: 30px;">🔬 Risk Assessment Frameworks</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
            <div style="background: #222222; padding: 15px; border-radius: 10px; border-left: 4px solid #ffff00;">
                <h4 style="color: #ffff00;">ISO 27005</h4>
                <p style="font-size: 13px;">Information security risk management standard focusing on threat frequency, geographic spread, and source diversity.</p>
            </div>
            <div style="background: #222222; padding: 15px; border-radius: 10px; border-left: 4px solid #ffaa00;">
                <h4 style="color: #ffaa00;">NIST SP 800-30</h4>
                <p style="font-size: 13px;">Risk assessment methodology evaluating likelihood, impact, and vulnerability based on technique diversity and geographic coverage.</p>
            </div>
        </div>
        
        <div style="margin-top: 40px; padding: 20px; background: linear-gradient(45deg, #ffff00, #cccc00); border-radius: 10px;">
            <p style="color: #000000; font-weight: bold; text-align: center; margin: 0;">
                🚀 Developed by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank" style="color: #000000;">Ricardo Mendes Pinto</a> for NIMBLR AB
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# -------------------------------
# DASHBOARD PAGE
# -------------------------------
if page == "🏠 Dashboard":
    st.markdown('<h2 class="glow-text"> WEEKLY THREAT INTELLIGENCE OVERVIEW</h2>', unsafe_allow_html=True)

    report_dates = sorted(items['report_date'].dt.date.unique(), reverse=True)
    selected_date = st.selectbox(
        "Select Intelligence Report Period", 
        report_dates, 
        index=0,
        help="Choose a specific week to analyze threat intelligence data"
    )
    selected_report = items[items['report_date'].dt.date == selected_date]

    # Multi-country filter with Nordic/Baltic default
    all_countries = []
    if country_columns:
        all_countries = pd.Series(pd.concat([selected_report[col] for col in country_columns], ignore_index=True))
        all_countries = sorted(all_countries.dropna().unique().tolist())
    
    # Default to Nordic/Baltic countries if they exist in the data
    nordic_baltic_countries = get_nordic_baltic_countries()
    default_countries = [country for country in nordic_baltic_countries if country in all_countries]
    
    selected_countries = st.multiselect(
        "Geographic Filter (Nordic/Baltic regions selected by default)",
        options=all_countries,
        default=default_countries,
        help="Filter analysis by specific countries or regions. Nordic/Baltic focus for regional threat assessment."
    )

    # Calculate metrics for risk assessment
    if ttp_columns:
        all_ttps = pd.Series(pd.concat([selected_report[col] for col in ttp_columns], ignore_index=True))
        all_ttps_flat = []
        unique_techniques = set()
        for val in all_ttps:
            if isinstance(val, (list, tuple, set)):
                all_ttps_flat.extend([str(x) for x in val if x not in [None, "None"]])
                unique_techniques.update([str(x) for x in val if x not in [None, "None"]])
            elif pd.notna(val) and str(val) != "None":
                all_ttps_flat.append(str(val))
                unique_techniques.add(str(val))
        unique_ttps_count = len(unique_techniques)
        total_ttp_count = len(all_ttps_flat)
    else:
        unique_ttps_count = 0
        total_ttp_count = 0
        unique_techniques = set()

    country_count = len([c for c in all_countries if c in selected_countries]) if selected_countries else len(all_countries)
    sources_count = selected_report['source'].nunique() if 'source' in selected_report.columns else 0
    
    # Determine if we're focusing on Nordic/Baltic region
    nordic_baltic_countries = get_nordic_baltic_countries()
    regional_focus = bool(selected_countries and any(c in nordic_baltic_countries for c in selected_countries))

    # Calculate risk scores with regional focus
    iso_score = calculate_iso_risk_score(total_ttp_count, country_count, sources_count, regional_focus)
    nist_score = calculate_nist_risk_score(total_ttp_count, country_count, unique_techniques, regional_focus)
    
    iso_level, iso_color = get_risk_level(iso_score)
    nist_level, nist_color = get_risk_level(nist_score)

    # Risk Assessment Sidebar
    with st.sidebar:
        # ISO Risk Score
        st.plotly_chart(
            plot_risk_gauge(iso_score, "ISO 27005 Risk Assessment", "ISO"), 
            use_container_width=True
        )
        
        st.markdown(f"""
        <div style="background: linear-gradient(145deg, #2a2a2a, #1a1a1a); padding: 10px; border-radius: 8px; margin-bottom: 15px; border: 1px solid {iso_color};">
            <p style="margin: 0; font-size: 12px;"><strong>Risk Level:</strong> <span style="color: {iso_color};">{iso_level}</span></p>
            <p style="margin: 5px 0 0 0; font-size: 11px; color: #cccccc;">
                Based on threat frequency ({total_ttp_count} TTPs), geographic spread ({country_count} countries), and source diversity ({sources_count} sources).
                {'<br><strong>Nordic/Baltic Focus Active</strong>' if regional_focus else ''}
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # NIST Risk Score
        st.plotly_chart(
            plot_risk_gauge(nist_score, "NIST SP 800-30 Risk Assessment", "NIST"), 
            use_container_width=True
        )
        
        st.markdown(f"""
        <div style="background: linear-gradient(145deg, #2a2a2a, #1a1a1a); padding: 10px; border-radius: 8px; margin-bottom: 15px; border: 1px solid {nist_color};">
            <p style="margin: 0; font-size: 12px;"><strong>Risk Level:</strong> <span style="color: {nist_color};">{nist_level}</span></p>
            <p style="margin: 5px 0 0 0; font-size: 11px; color: #cccccc;">
                Based on technique diversity ({unique_ttps_count} unique), geographic impact, and vulnerability assessment.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Get top TTPs for recommendations
        if country_columns and ttp_columns:
            melted_for_recs = selected_report.melt(id_vars=country_columns, value_vars=ttp_columns,
                                          var_name="ttp_col", value_name="TTP")
            if any(melted_for_recs["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
                melted_for_recs = melted_for_recs.explode("TTP")
            melted_for_recs = melted_for_recs.dropna(subset=["TTP"])
            melted_for_recs = melted_for_recs[melted_for_recs["TTP"] != "None"]
            
            if selected_countries:
                country_filter = melted_for_recs[country_columns].apply(
                    lambda row: any(country in selected_countries for country in row.values if pd.notna(country)), 
                    axis=1
                )
                melted_for_recs = melted_for_recs[country_filter]
            
            top_ttps_list = melted_for_recs["TTP"].value_counts().head(5).index.tolist()
            affected_countries_list = selected_countries if selected_countries else all_countries
        else:
            top_ttps_list = []
            affected_countries_list = []
        
        # Generate security awareness recommendations
        recommendations = get_security_awareness_recommendations(
            iso_score, nist_score, top_ttps_list, affected_countries_list
        )
        
       

    # Main dashboard metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-container">
            <h3 style="margin: 0; color: #ffff00;">🎯 {unique_ttps_count}</h3>
            <p style="margin: 5px 0 0 0; color: #cccccc;">MITRE TTPs</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-container">
            <h3 style="margin: 0; color: #ffff00;">📡 {sources_count}</h3>
            <p style="margin: 5px 0 0 0; color: #cccccc;">Intel Sources</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-container">
            <h3 style="margin: 0; color: {iso_color};">🛡️ {iso_score:.0f}</h3>
            <p style="margin: 5px 0 0 0; color: #cccccc;">ISO Risk Score</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-container">
            <h3 style="margin: 0; color: {nist_color};">🔒 {nist_score:.0f}</h3>
            <p style="margin: 5px 0 0 0; color: #cccccc;">NIST Risk Score</p>
        </div>
        """, unsafe_allow_html=True)

    # Main content continues with enhanced styling...
    if country_columns and ttp_columns:
        melted = selected_report.melt(id_vars=country_columns, value_vars=ttp_columns,
                                      var_name="ttp_col", value_name="TTP")
        if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
            melted = melted.explode("TTP")
        melted = melted.dropna(subset=["TTP"])
        melted = melted[melted["TTP"] != "None"]
        melted = melted.melt(id_vars=["TTP"], value_vars=country_columns,
                             var_name="country_col", value_name="country")
        melted = melted.dropna(subset=["country"])
        melted = melted[melted["country"] != "None"]

        if selected_countries:
            melted = melted[melted["country"].isin(selected_countries)]

        if not melted.empty:
            # Enhanced globe and TTP visualization
            col_globe, col_ttp = st.columns([1, 1.5])
            
            # Enhanced Globe
            all_countries_series = pd.Series(pd.concat([selected_report[col] for col in country_columns], ignore_index=True))
            all_countries_series = all_countries_series.dropna()[all_countries_series != "None"]
            if selected_countries:
                all_countries_series = all_countries_series[all_countries_series.isin(selected_countries)]
            iso_codes = all_countries_series.map(country_to_iso3).dropna().unique()
            all_iso = [c.alpha_3 for c in pycountry.countries]
            z_values = [1 if code in iso_codes else 0 for code in all_iso]
            
            fig_globe = go.Figure(go.Choropleth(
                locations=all_iso, 
                z=z_values,
                colorscale=[[0, '#1a1a1a'], [1, '#ffff00']],
                showscale=False, 
                marker_line_color='#ffff00', 
                marker_line_width=1
            ))
            fig_globe.update_geos(
                projection_type="orthographic",
                showcoastlines=True, coastlinecolor="#ffff00",
                showland=True, landcolor="#2a2a2a",
                showocean=True, oceancolor="#0a0a0a",
                showframe=False, bgcolor="#0a0a0a"
            )
            fig_globe.update_layout(
                **create_modern_plot_theme(),
                title={'text': '🌍 Global Threat Distribution', 'y': 0.95, 'x': 0.5, 'xanchor': 'center'},
                height=400
            )
            col_globe.plotly_chart(fig_globe, use_container_width=True)

            # Enhanced Top MITRE Techniques
            ttp_counts = melted.groupby("TTP").size().reset_index(name="count").sort_values("count", ascending=False).head(10)
            
            fig_ttp = go.Figure(go.Bar(
                x=ttp_counts["count"], 
                y=ttp_counts["TTP"],
                orientation="h",
                text=ttp_counts["count"], 
                textposition="auto",
                marker=dict(
                    color=ttp_counts["count"], 
                    colorscale=[[0, '#ffaa00'], [1, '#ffff00']],
                    line=dict(color='#ffff00', width=1)
                ),
                hovertemplate="<b>%{y}</b><br>Occurrences: %{x}<extra></extra>"
            ))
            fig_ttp.update_layout(
                **create_modern_plot_theme(),
                title={'text': '🎯 Top MITRE ATT&CK Techniques', 'y': 0.95, 'x': 0.5, 'xanchor': 'center'},
                height=400,
                yaxis=dict(automargin=True, tickfont=dict(size=10))
            )
            col_ttp.plotly_chart(fig_ttp, use_container_width=True)

            # Enhanced Country Analysis
            country_counts = melted.groupby("country").size().reset_index(name="count").sort_values("count", ascending=False)
            
            st.markdown('<h3 class="glow-text"> Geographic Threat Distribution</h3>', unsafe_allow_html=True)
            
            fig_country = go.Figure(go.Bar(
                x=country_counts["country"], 
                y=country_counts["count"],
                text=country_counts["count"], 
                textposition="auto",
                marker=dict(
                    color=country_counts["count"], 
                    colorscale=[[0, '#ffaa00'], [1, '#ffff00']],
                    line=dict(color='#ffff00', width=1)
                ),
                hovertemplate="<b>%{x}</b><br>Threat Events: %{y}<extra></extra>"
            ))
            fig_country.update_layout(
                **create_modern_plot_theme(),
                height=400,
                xaxis=dict(tickangle=45, tickfont=dict(size=10)),
                yaxis=dict(title=dict(text="Threat Events", font=dict(color='#ffff00')))
            )
            st.plotly_chart(fig_country, use_container_width=True)

            # Enhanced Heatmap
            st.markdown('<h3 class="glow-text"> Threat Technique Heatmap</h3>', unsafe_allow_html=True)
            heat_data = melted.groupby(["country", "TTP"]).size().reset_index(name="count")
            plot_heatmap(heat_data, x_col="country", y_col="TTP",
                         title="MITRE Techniques × Geographic Distribution", height=600)

    # Enhanced Search & Download Section
    st.markdown("""
    <div style="margin-top: 40px; padding: 20px; background: linear-gradient(145deg, #1a1a1a, #2a2a2a); border: 2px solid #ffff00; border-radius: 15px;">
        <h3 class="glow-text">DATA MINING</h3>
    </div>
    """, unsafe_allow_html=True)
    
    search_col1, search_col2 = st.columns([3, 1])
    
    with search_col1:
        search_term = st.text_input(
            "Advanced Search Query", 
            "",
            help="Search across all threat intelligence data fields",
            placeholder="Enter keywords, TTPs, countries, or IOCs..."
        )
    
    with search_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button(" Execute Search", use_container_width=True)
    
    if search_term and (search_button or search_term):
        with st.spinner("🔄 Analyzing threat data..."):
            mask = items.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
            filtered_items = items[mask]
            
            if not filtered_items.empty:
                st.success(f"✅ Found {len(filtered_items)} matching threat intelligence records")
                
                # Enhanced data display
                st.markdown("### 📋 Search Results")
                
                # Display dataframe without styling that can cause type conflicts
                st.dataframe(
                    filtered_items,
                    use_container_width=True,
                    height=400
                )
                
                # Download functionality
                output = BytesIO()
                with pd.ExcelWriter(output, engine="openpyxl") as writer:
                    filtered_items.to_excel(writer, index=False, sheet_name="Threat_Intelligence_Results")
                output.seek(0)
                
                st.download_button(
                    label="📥 Download Intelligence Report",
                    data=output,
                    file_name=f"nimblr_threat_intel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    help="Download filtered results as Excel report"
                )
            else:
                st.warning("⚠️ No matching threat intelligence found. Try different search terms.")
    elif not search_term:
        st.info("Enter search terms (ex1: Portugal; ex2: Phishing) to analyze threat intelligence data")

# -------------------------------
# ENHANCED TRENDS PAGE
# -------------------------------
if page == "📈 Trends":
    st.markdown('<h2 class="glow-text"> THREAT INTELLIGENCE TRENDS</h2>', unsafe_allow_html=True)

    report_dates = sorted(items['report_date'].dt.date.unique())
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        selected_dates = st.multiselect(
            "🗓️ Select Analysis Periods (weeks to compare)",
            options=report_dates,
            default=report_dates[-4:] if len(report_dates) >= 4 else report_dates,
            help="Choose multiple weeks to analyze threat evolution patterns"
        )
    
    with col2:
        all_countries = []
        if country_columns:
            all_countries = pd.Series(pd.concat([items[col] for col in country_columns], ignore_index=True))
            all_countries = sorted(all_countries.dropna().unique().tolist())
        selected_country = st.selectbox(
            "🌍 Geographic Focus", 
            ["All Regions"] + all_countries,
            help="Focus analysis on specific country or global view"
        )

    if not selected_dates:
        st.warning("⚠️ Please select at least one analysis period to continue.")
        st.stop()

    # Filter and process trend data
    trend_data = items[items['report_date'].dt.date.isin(selected_dates)]
    if selected_country != "All Regions":
        trend_data = trend_data[
            trend_data[country_columns].apply(lambda row: selected_country in row.values, axis=1)
        ]

    if not trend_data.empty and ttp_columns and country_columns:
        # Process trend analysis
        melted = trend_data.melt(id_vars=country_columns + ['report_date'],
                                 value_vars=ttp_columns,
                                 var_name="ttp_col", value_name="TTP")

        if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
            melted = melted.explode("TTP")
        melted = melted.dropna(subset=["TTP"])
        melted = melted[melted["TTP"] != "None"]

        melted = melted.melt(id_vars=['report_date', 'TTP'],
                             value_vars=country_columns,
                             var_name="country_col", value_name="country")
        melted = melted.dropna(subset=["country"])
        melted = melted[melted["country"] != "None"]

        if selected_country != "All Regions":
            melted = melted[melted["country"] == selected_country]

        # Calculate trends
        ttp_counts = melted.groupby(["report_date", "TTP"]).size().reset_index(name="count")

        # Ensure all dates appear for each TTP
        all_combinations = pd.MultiIndex.from_product(
            [selected_dates, ttp_counts["TTP"].unique()],
            names=["report_date", "TTP"]
        )
        ttp_counts = ttp_counts.set_index(["report_date", "TTP"]).reindex(all_combinations, fill_value=0).reset_index()

        # Enhanced trend visualization
        st.markdown('<h3 class="glow-text"> Technique Evolution Timeline</h3>', unsafe_allow_html=True)
        
        # Get top techniques for better visualization
        top_ttps = melted.groupby("TTP").size().sort_values(ascending=False).head(8).index
        trend_subset = ttp_counts[ttp_counts["TTP"].isin(top_ttps)]
        
        fig_ttp_trend = go.Figure()
        
        colors = ['#ffff00', '#ffaa00', '#ff4444', '#44ff44', '#00aaff', '#aa44ff', '#ff8844', '#44ffaa']
        
        for i, ttp in enumerate(top_ttps):
            subset = trend_subset[trend_subset["TTP"] == ttp].sort_values("report_date")
            color = colors[i % len(colors)]
            
            fig_ttp_trend.add_trace(go.Scatter(
                x=subset["report_date"], 
                y=subset["count"],
                mode="lines+markers", 
                name=ttp,
                line=dict(color=color, width=3),
                marker=dict(size=8, color=color, line=dict(color='#ffffff', width=1)),
                hovertemplate=f"<b>{ttp}</b><br>Date: %{{x}}<br>Occurrences: %{{y}}<extra></extra>"
            ))

        # Create a clean theme without conflicts
        trend_theme = create_modern_plot_theme()
        trend_theme.update({
            'height': 500,
            'xaxis': dict(title=dict(text="Report Period", font=dict(color='#ffff00'))),
            'yaxis': dict(title=dict(text="Threat Occurrences", font=dict(color='#ffff00')), rangemode="tozero"),
            'legend': dict(bgcolor='rgba(42, 42, 42, 0.8)', bordercolor='#ffff00', borderwidth=1)
        })
        
        fig_ttp_trend.update_layout(**trend_theme)
        st.plotly_chart(fig_ttp_trend, use_container_width=True)
        
        # Generate trend-based course recommendations
        trend_melted = trend_data.melt(id_vars=country_columns + ['report_date'],
                                       value_vars=ttp_columns,
                                       var_name="ttp_col", value_name="TTP") if ttp_columns else pd.DataFrame()
        
        if not trend_melted.empty:
            if any(trend_melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
                trend_melted = trend_melted.explode("TTP")
            trend_melted = trend_melted.dropna(subset=["TTP"])
            trend_melted = trend_melted[trend_melted["TTP"] != "None"]
            
            if selected_country != "All Regions":
                trend_melted = trend_melted.melt(id_vars=['report_date', 'TTP'],
                                                 value_vars=country_columns,
                                                 var_name="country_col", value_name="country")
                trend_melted = trend_melted.dropna(subset=["country"])
                trend_melted = trend_melted[trend_melted["country"] == selected_country]
            
            # Get course ideas based on trends
            course_ideas = get_trend_based_course_ideas(trend_melted, [selected_country] if selected_country != "All Regions" else [])
            
            # Display course recommendations
            st.markdown('<h3 class="glow-text">💡 NIMBLR Course Development Ideas</h3>', unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("""
                <div style="background: linear-gradient(145deg, #2a2a2a, #1a1a1a); padding: 15px; border-radius: 10px; border: 1px solid #ffff00; height: 300px;">
                    <h4 style="color: #ffff00; margin-top: 0;">Emerging Courses</h4>
                """, unsafe_allow_html=True)
                for course in course_ideas["emerging_courses"]:
                    st.markdown(f"""
                    <p style="font-size: 11px; color: #cccccc; margin: 8px 0;">• {course}</p>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                <div style="background: linear-gradient(145deg, #2a2a2a, #1a1a1a); padding: 15px; border-radius: 10px; border: 1px solid #ffaa00; height: 300px;">
                    <h4 style="color: #ffaa00; margin-top: 0;">New Simulations</h4>
                """, unsafe_allow_html=True)
                for simulation in course_ideas["simulation_scenarios"]:
                    st.markdown(f"""
                    <p style="font-size: 11px; color: #cccccc; margin: 8px 0;">• {simulation}</p>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col3:
                st.markdown("""
                <div style="background: linear-gradient(145deg, #2a2a2a, #1a1a1a); padding: 15px; border-radius: 10px; border: 1px solid #44ff44; height: 300px;">
                    <h4 style="color: #44ff44; margin-top: 0;">Zero-Day Classes</h4>
                """, unsafe_allow_html=True)
                for zero_day in course_ideas["zero_day_classes"]:
                    st.markdown(f"""
                    <p style="font-size: 11px; color: #cccccc; margin: 8px 0;">• {zero_day}</p>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
        
        # Trend analysis summary
        latest_period = max(selected_dates)
        previous_period = sorted(selected_dates)[-2] if len(selected_dates) > 1 else latest_period
        
        latest_data = ttp_counts[ttp_counts["report_date"] == latest_period]
        previous_data = ttp_counts[ttp_counts["report_date"] == previous_period]
        
        total_latest = latest_data["count"].sum()
        total_previous = previous_data["count"].sum()
        
        if total_previous > 0:
            trend_change = ((total_latest - total_previous) / total_previous) * 100
            trend_direction = "📈" if trend_change > 0 else "📉" if trend_change < 0 else "➡️"
            trend_color = "#ff4444" if trend_change > 0 else "#44ff44" if trend_change < 0 else "#ffff00"
        else:
            trend_change = 0
            trend_direction = "➡️"
            trend_color = "#ffff00"
        
        st.markdown(f"""
        <div style="padding: 20px; background: linear-gradient(145deg, #2a2a2a, #1a1a1a); border: 2px solid {trend_color}; border-radius: 10px; margin-top: 20px;">
            <h4 style="color: {trend_color}; margin-top: 0;">{trend_direction} Trend Analysis Summary</h4>
            <p style="font-size: 14px; margin-bottom: 10px;">
                <strong>Period Change:</strong> <span style="color: {trend_color};">{trend_change:+.1f}%</span> 
                from {previous_period} to {latest_period}
            </p>
            <p style="font-size: 12px; color: #cccccc; margin: 0;">
                Total threat events: {total_latest} (latest) vs {total_previous} (previous)
                {f" | Focus: {selected_country}" if selected_country != "All Regions" else " | Global Analysis"}
            </p>
        </div>
        """, unsafe_allow_html=True)

# -------------------------------
# ENHANCED FOOTER
# -------------------------------
st.markdown("""
<div class="footer" style="margin-top: 50px;">
    <p style="margin: 0;">
        Developed by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank" style="color: #000000; font-weight: bold;">Ricardo Mendes Pinto</a> | 
        Powered by MITRE ATT&CK Framework
    </p>
</div>
""", unsafe_allow_html=True)
