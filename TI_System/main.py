#!/usr/bin/env python3
"""
Enhanced main entry point for the Professional Threat Intelligence Dashboard
"""
import streamlit as st
from datetime import datetime, timedelta
from modules.config import Config
from modules.data_fetcher import DataFetcher
from modules.data_processor import DataProcessor
from modules.ui_components import UIComponents
from modules.database_manager import DatabaseManager
import pandas as pd

def main():
    # Initialize components
    config = Config()
    ui = UIComponents()
    
    # Initialize other components
    try:
        data_fetcher = DataFetcher(config)
        data_processor = DataProcessor()
        
        # Try to load data
        data_fetcher.fetch_reports()
        items = data_processor.load_reports(config.REPORTS_FOLDER)
        
        # Detect columns
        ttp_columns = data_processor.get_ttp_columns(items)
        country_columns = data_processor.get_country_columns(items)
        
    except Exception as e:
        st.error(f"Error loading data: {e}")
        st.info("Using sample data for demonstration")
        # Create sample data
        items = create_sample_data()
        ttp_columns = ['ttp_desc_1', 'ttp_desc_2', 'ttp_desc_3']
        country_columns = ['country_1', 'country_2', 'country_3']
    
    # Render simple title without container
    st.markdown("""
    <h1 style="text-align: center; color: #00d4ff; font-size: 3rem; font-weight: 800; 
               text-shadow: 0 0 20px rgba(0, 212, 255, 0.3); margin-bottom: 2rem;">
        🛡️ Threat Intelligence Dashboard
    </h1>
    """, unsafe_allow_html=True)
    
    # Sidebar for filters and navigation
    st.sidebar.title("🔍 Navigation & Filters")
    
    # Page selector
    page = st.sidebar.radio(
        "Select Page:",
        ["📊 Main Dashboard", "📈 Trends Analysis", "📋 Executive Summary", "ℹ️ About"]
    )
    
    if page == "📊 Main Dashboard":
        render_dashboard_page(items, ttp_columns, country_columns, ui, data_processor)
    elif page == "📈 Trends Analysis":
        render_trends_page(items, ttp_columns, country_columns, ui, data_processor)
    elif page == "📋 Executive Summary":
        render_executive_summary_page(items, ttp_columns, country_columns, ui, data_processor)
    elif page == "ℹ️ About":
        render_about_page(ui)
    
    # Footer
    ui.render_footer()

def create_sample_data():
    """Create enhanced sample data with proper date ranges"""
    import random
    from datetime import timedelta
    
    # Sample data with proper date distribution
    base_date = datetime.now() - timedelta(days=90)  # Start 90 days ago
    
    sample_data = []
    for i in range(150):
        # Create dates spread over the last 90 days
        days_offset = random.randint(0, 89)
        report_date = base_date + timedelta(days=days_offset)
        
        # More realistic threat distribution
        threat_types = [
            "Phishing (T1566.002)", "Ransomware (T1486)", "Malware (T1055)",
            "Social Engineering (T1566)", "Credential Dumping (T1003)",
            "PowerShell (T1059.001)", "Brute Force (T1110)", "Data Exfiltration (T1041)"
        ]
        
        countries = [
            "United States", "China", "Russia", "Germany", "United Kingdom",
            "Japan", "France", "South Korea", "India", "Brazil", "Canada"
        ]
        
        sources = ["CyberNews", "ThreatPost", "BleepingComputer", "KrebsOnSecurity", "SecurityWeek"]
        
        # Select 1-2 countries and 1-3 TTPs per incident
        selected_countries = random.sample(countries, random.randint(1, 2))
        selected_ttps = random.sample(threat_types, random.randint(1, 3))
        
        record = {
            'id': i + 1,
            'report_date': report_date,
            'title': f"Cyber Incident {i+1}: {selected_ttps[0].split('(')[0].strip()}",
            'source': random.choice(sources),
            'threat_actor': random.choice(['APT28', 'APT29', 'Lazarus', 'FIN7', 'Unknown', 'Conti', 'REvil']),
            'url': f"https://example.com/threat-{i+1}",
            'content': f"Sample threat intelligence content for incident {i+1}.",
            'severity': random.choice(['low', 'medium', 'high', 'critical'])
        }
        
        # Add country columns
        for j, country in enumerate(selected_countries):
            record[f'country_{j+1}'] = country
        for j in range(len(selected_countries), 5):
            record[f'country_{j+1}'] = None
            
        # Add TTP columns  
        for j, ttp in enumerate(selected_ttps):
            record[f'ttp_desc_{j+1}'] = ttp
        for j in range(len(selected_ttps), 6):
            record[f'ttp_desc_{j+1}'] = None
        
        sample_data.append(record)
    
    return pd.DataFrame(sample_data)

def render_dashboard_page(items, ttp_columns, country_columns, ui, data_processor):
    """Render the main dashboard page"""
    
    # Time range selector
    time_range = st.sidebar.selectbox(
        "📅 Time Range",
        ["Last 7 Days", "Last 14 Days", "Last 30 Days", "Last 90 Days"],
        index=2  # Default to 30 days
    )
    
    # Get days back from selection
    days_map = {
        "Last 7 Days": 7,
        "Last 14 Days": 14,
        "Last 30 Days": 30,
        "Last 90 Days": 90
    }
    days_back = days_map[time_range]
    
    # Filter data by date
    cutoff_date = datetime.now() - timedelta(days=days_back)
    if 'report_date' in items.columns:
        recent_items = items[items['report_date'] >= cutoff_date].copy()
    else:
        recent_items = items.copy()
    
    # Country filter
    if country_columns:
        all_countries = data_processor.get_unique_countries(recent_items, country_columns)
        selected_countries = st.sidebar.multiselect(
            "🌍 Filter by Countries",
            options=all_countries,
            default=[]
        )
    else:
        selected_countries = []
    
    # Apply country filter BEFORE calculating metrics
    if selected_countries and country_columns:
        mask = recent_items[country_columns].apply(
            lambda row: any(country in str(val) for val in row.values for country in selected_countries), axis=1
        )
        filtered_items = recent_items[mask].copy()
    else:
        filtered_items = recent_items.copy()
    
    # Calculate accurate metrics from filtered data
    total_threats = len(filtered_items)
    unique_countries = len(data_processor.get_unique_countries(filtered_items, country_columns)) if country_columns else 0
    unique_sources = filtered_items['source'].nunique() if 'source' in filtered_items.columns else 0
    
    # Calculate unique TTPs accurately
    all_ttps = []
    if ttp_columns:
        for col in ttp_columns:
            if col in filtered_items.columns:
                ttps_in_col = filtered_items[col].dropna()
                for ttp in ttps_in_col:
                    if ttp and str(ttp) != 'None':
                        all_ttps.append(str(ttp))
    unique_ttps = len(set(all_ttps))
    

    
    st.markdown("---")
    
    # Create visualizations if we have data
    if not filtered_items.empty and country_columns and ttp_columns:
        
        # Prepare data for visualizations
        melted_data = data_processor.prepare_melted_data(
            filtered_items, country_columns, ttp_columns, selected_countries
        )
        
        if not melted_data.empty:
            
            # Create two columns for globe and bar chart
            col1, col2 = st.columns([1, 1.5])
            
            with col1:
                # Globe in container
                st.markdown("""
                <div class="chart-container">
                    <h3 class="chart-title">
                        <span class="chart-icon"></span>
                        🌍 Global Threat Distribution
                    </h3>
                </div>
                """, unsafe_allow_html=True)
                
                country_counts = melted_data['country'].value_counts().to_dict()
                globe_fig = ui.create_professional_globe(country_counts)
                st.plotly_chart(globe_fig, use_container_width=True)
            
            with col2:
                # Bar chart in container
                st.markdown("""
                <div class="chart-container">
                    <h3 class="chart-title">
                        <span class="chart-icon"></span>
                        🎯 Top Attack Techniques
                    </h3>
                </div>
                """, unsafe_allow_html=True)
                
                ttp_counts = melted_data['TTP'].value_counts().head(10).to_dict()
                bar_fig = ui.create_professional_bar_chart(ttp_counts, "", "h")
                st.plotly_chart(bar_fig, use_container_width=True)
            
            # Heatmap in container
            st.markdown("""
            <div class="chart-container">
                <h3 class="chart-title">
                    <span class="chart-icon"></span>
                    🔥 Attack Techniques vs Countries
                </h3>
            </div>
            """, unsafe_allow_html=True)
            
            heatmap_data = melted_data.groupby(['country', 'TTP']).size().reset_index(name='count')
            heatmap_fig = ui.create_professional_heatmap(heatmap_data, 'country', 'TTP', 'count')
            st.plotly_chart(heatmap_fig, use_container_width=True)
    
    # Search and data table section
    st.markdown("""
    <div class="chart-container">
        <h3 class="chart-title">
            <span class="chart-icon"></span>
            🔍 Data Search & Analysis
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    search_term = st.text_input("🔎 Search in threat data:", placeholder="Enter keywords to search...")
    
    show_table = st.checkbox("📊 Show data table")
    
    if search_term:
        search_results = data_processor.filter_data_by_search(filtered_items, search_term)
        if not search_results.empty:
            st.success(f"Found {len(search_results)} results for '{search_term}'")
            if show_table:
                st.dataframe(search_results, use_container_width=True)
            ui.create_download_button(search_results, f"search_results_{datetime.now().strftime('%Y%m%d')}.xlsx", "Download Search Results")
        else:
            st.info("No results found for your search.")
    elif show_table:
        st.dataframe(filtered_items.head(50), use_container_width=True)  # Show first 50 rows
        ui.create_download_button(filtered_items, f"threat_data_{datetime.now().strftime('%Y%m%d')}.xlsx", "Download All Data")

def render_trends_page(items, ttp_columns, country_columns, ui, data_processor):
    """Render improved trends analysis page"""
    
    st.subheader("📈 Threat Intelligence Trends")
    
    # Date selection for trends
    if 'report_date' in items.columns:
        available_dates = sorted(items['report_date'].dt.date.unique(), reverse=True)
        selected_dates = st.sidebar.multiselect(
            "📅 Select Report Periods",
            options=available_dates,
            default=available_dates[:6] if len(available_dates) >= 6 else available_dates
        )
    else:
        st.error("No date information available for trends analysis")
        return
    
    if not selected_dates:
        st.warning("Please select at least one report date.")
        return
    
    # Filter by selected dates
    trend_data = items[items['report_date'].dt.date.isin(selected_dates)].copy()
    
    # Country selector for trends
    if country_columns:
        all_countries = data_processor.get_unique_countries(trend_data, country_columns)
        selected_country = st.sidebar.selectbox("🌍 Focus Country", ["All Countries"] + all_countries)
    else:
        selected_country = "All Countries"
    
    # Filter by country if not "All"
    if selected_country != "All Countries" and country_columns:
        mask = trend_data[country_columns].apply(
            lambda row: selected_country in str(row.values), axis=1
        )
        trend_data = trend_data[mask].copy()
    
    if not trend_data.empty and ttp_columns:
        # Create weekly aggregation for better trend visualization
        trend_data['week'] = trend_data['report_date'].dt.to_period('W').astype(str)
        
        # Prepare trend data
        melted_trend = data_processor.prepare_melted_data(trend_data, country_columns, ttp_columns)
        
        if not melted_trend.empty:
            # Add week information
            week_mapping = trend_data[['report_date', 'week']].drop_duplicates()
            melted_trend = melted_trend.merge(
                trend_data[['report_date']], 
                left_index=True, right_index=True, how='left'
            )
            melted_trend = melted_trend.merge(week_mapping, on='report_date', how='left')
            
            # Create trends by week
            ttp_trends = melted_trend.groupby(['week', 'TTP']).size().reset_index(name='count')
            ttp_trends = ttp_trends.sort_values('week')
            
            # Show top TTPs over time
            top_ttps = melted_trend['TTP'].value_counts().head(5).index.tolist()
            ttp_trends_filtered = ttp_trends[ttp_trends['TTP'].isin(top_ttps)]
            
            if not ttp_trends_filtered.empty:
                st.write(f"**Trends for {selected_country}** (Top 5 Attack Techniques)")
                
                trend_fig = ui.create_trend_chart(ttp_trends_filtered, 'week', 'count', 'TTP')
                st.plotly_chart(trend_fig, use_container_width=True)
                
                # Summary statistics
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📊 Period Summary")
                    total_incidents = len(melted_trend)
                    weeks_analyzed = len(ttp_trends['week'].unique())
                    avg_per_week = total_incidents / weeks_analyzed if weeks_analyzed > 0 else 0
                    
                    st.metric("Total Incidents", total_incidents)
                    st.metric("Weeks Analyzed", weeks_analyzed)
                    st.metric("Avg. per Week", f"{avg_per_week:.1f}")
                
                with col2:
                    st.subheader("🎯 Top Techniques")
                    for i, (ttp, count) in enumerate(melted_trend['TTP'].value_counts().head(5).items(), 1):
                        st.write(f"{i}. **{ttp.split('(')[0].strip()}**: {count}")
            else:
                st.info("No trend data available for the selected filters.")
    else:
        st.info("No data available for trends analysis with current filters.")

def render_executive_summary_page(items, ttp_columns, country_columns, ui, data_processor):
    """Render executive summary as separate page"""
    
    st.subheader("📋 Executive Summary")
    
    # Time range for summary
    time_range = st.selectbox(
        "📅 Summary Period",
        ["Last 7 Days", "Last 14 Days", "Last 30 Days", "Last 90 Days"],
        index=2
    )
    
    days_map = {
        "Last 7 Days": 7,
        "Last 14 Days": 14,
        "Last 30 Days": 30,
        "Last 90 Days": 90
    }
    days_back = days_map[time_range]
    
    # Filter data
    cutoff_date = datetime.now() - timedelta(days=days_back)
    if 'report_date' in items.columns:
        recent_items = items[items['report_date'] >= cutoff_date].copy()
    else:
        recent_items = items.copy()
    
    # Calculate comprehensive metrics
    total_threats = len(recent_items)
    unique_countries = len(data_processor.get_unique_countries(recent_items, country_columns))
    unique_sources = recent_items['source'].nunique() if 'source' in recent_items.columns else 0
    
    # Calculate human-targeted vs general
    if 'severity' in recent_items.columns:
        critical_threats = len(recent_items[recent_items['severity'] == 'critical'])
        high_threats = len(recent_items[recent_items['severity'] == 'high'])
    else:
        critical_threats = int(total_threats * 0.15)  # Estimate
        high_threats = int(total_threats * 0.35)
    
    # Generate executive summary text
    summary_text = f"""
    **Threat Intelligence Analysis for {time_range}**
    
    During the past {days_back} days, our threat intelligence system identified **{total_threats}** security incidents 
    across **{unique_countries}** countries from **{unique_sources}** intelligence sources.
    
    **Key Findings:**
    • **{critical_threats}** critical-severity threats requiring immediate attention
    • **{high_threats}** high-severity threats affecting critical infrastructure  
    • **{unique_countries}** countries experienced targeted cyber activities
    • **{int(total_threats/days_back)}** average threats detected daily
    
    **Risk Assessment:**
    {get_risk_assessment(critical_threats, total_threats)}
    
    **Recommendations:**
    • Enhance monitoring for countries with increasing threat activity
    • Focus on defense against the most prevalent attack techniques
    • Implement additional controls for critical and high-severity threats
    • Maintain situational awareness of emerging threat actors
    """
    
    # Display summary
    ui.render_executive_summary(summary_text, {
        "Total Threats": total_threats,
        "Critical Severity": critical_threats,
        "Affected Countries": unique_countries,
        "Intelligence Sources": unique_sources
    })

def get_risk_assessment(critical_threats, total_threats):
    """Generate risk assessment based on threat levels"""
    if total_threats == 0:
        return "No significant threats detected in the analysis period."
    
    critical_ratio = critical_threats / total_threats
    
    if critical_ratio > 0.2:
        return "**HIGH RISK**: Significant number of critical threats detected. Immediate action recommended."
    elif critical_ratio > 0.1:
        return "**MEDIUM RISK**: Moderate critical threat activity. Enhanced monitoring advised."
    else:
        return "**LOW-MEDIUM RISK**: Manageable threat levels with standard security measures adequate."

def render_about_page(ui):
    """Render the about page"""
    
    st.subheader("ℹ️ About This System")
    
    st.markdown("""
    ## 🛡️ Professional Threat Intelligence Dashboard
    
    This advanced threat intelligence platform provides real-time monitoring and analysis of cybersecurity threats 
    from multiple authoritative sources worldwide.
    
    ### ✨ Key Features
    
    **Real-time Intelligence**
    • Automated data collection from 20+ premium cybersecurity sources
    • Continuous threat landscape monitoring with advanced filtering
    • Real-time updates and alerting for critical threats
    
    **Advanced Analytics**
    • MITRE ATT&CK framework integration for standardized threat classification
    • Geospatial threat mapping with country-specific intelligence
    • Trend analysis and predictive threat modeling
    
    **Professional Visualizations**
    • Interactive global threat distribution maps
    • Dynamic charts and heatmaps for pattern recognition
    • Executive-level reporting with actionable insights
    
    ### 🔧 Technical Architecture
    
    • **Backend**: Python with advanced data processing pipelines
    • **Frontend**: Streamlit with professional custom styling
    • **Data Visualization**: Plotly for interactive, enterprise-grade charts
    • **Intelligence Sources**: RSS feeds, OTX AlienVault, premium threat feeds
    • **Data Storage**: Optimized SQLite with advanced indexing
    • **Security**: Multi-layer security with API key management
    
    ### 📊 Data Sources
    
    Our intelligence feeds include major cybersecurity publications, government advisories, 
    threat research organizations, and commercial threat intelligence providers.
    
    ### 🎯 Target Audience
    
    • **Security Operations Centers (SOCs)**
    • **Chief Information Security Officers (CISOs)**  
    • **Threat Intelligence Analysts**
    • **Incident Response Teams**
    • **Security Researchers**
    
    ---
    
    **Contact**: [Ricardo Mendes Pinto](https://www.linkedin.com/in/ricardopinto110993/) | Professional Cybersecurity Solutions
    """)

if __name__ == "__main__":
    main()
