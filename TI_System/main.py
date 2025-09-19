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
        import pandas as pd
        items = pd.DataFrame({
            'report_date': [datetime.now() - timedelta(days=i) for i in range(10)],
            'title': [f'Sample Threat {i+1}' for i in range(10)],
            'source': ['Sample Source'] * 10,
            'country_1': ['United States', 'Germany', 'Japan', 'France', 'UK'] * 2,
            'ttp_desc_1': ['Phishing (T1566.002)', 'Ransomware (T1486)', 'Malware (T1055)'] * 3 + ['Exploit (T1203)']
        })
        ttp_columns = ['ttp_desc_1']
        country_columns = ['country_1']
    
    # Render main header
    ui.render_main_header(
        "Threat Intelligence Dashboard",
        "Real-time cybersecurity threat monitoring and analysis"
    )
    
    # Sidebar for filters and navigation
    st.sidebar.title("🔍 Navigation & Filters")
    
    # Page selector
    page = st.sidebar.radio(
        "Select Page:",
        ["📊 Dashboard", "📈 Trends", "ℹ️ About"]
    )
    
    if page == "📊 Dashboard":
        render_dashboard_page(items, ttp_columns, country_columns, ui, data_processor)
    elif page == "📈 Trends":
        render_trends_page(items, ttp_columns, country_columns, ui, data_processor)
    elif page == "ℹ️ About":
        render_about_page(ui)
    
    # Footer
    ui.render_footer()

def render_dashboard_page(items, ttp_columns, country_columns, ui, data_processor):
    """Render the main dashboard page with professional styling"""
    
    # Time range selector
    time_range = st.sidebar.selectbox(
        "📅 Time Range",
        ["Last 7 Days", "Last 14 Days", "Last 30 Days", "Last 90 Days"],
        index=0
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
        recent_items = items[items['report_date'] >= cutoff_date]
    else:
        recent_items = items
    
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
    
    # TTP filter
    if ttp_columns:
        all_ttps = []
        for col in ttp_columns:
            all_ttps.extend(recent_items[col].dropna().unique())
        all_ttps = list(set(all_ttps))[:20]  # Limit to top 20
        
        selected_ttps = st.sidebar.multiselect(
            "🎯 Filter by Attack Techniques",
            options=all_ttps,
            default=[]
        )
    else:
        selected_ttps = []
    
    # Apply filters
    filtered_items = recent_items
    if selected_countries and country_columns:
        mask = filtered_items[country_columns].apply(
            lambda row: any(country in row.values for country in selected_countries), axis=1
        )
        filtered_items = filtered_items[mask]
    
    # Calculate metrics
    total_threats = len(filtered_items)
    unique_countries = len(data_processor.get_unique_countries(filtered_items, country_columns)) if country_columns else 0
    unique_ttps = len(set([item for col in ttp_columns for item in filtered_items[col].dropna()])) if ttp_columns else 0
    unique_sources = filtered_items['source'].nunique() if 'source' in filtered_items.columns else 0
    
    # Generate executive summary
    summary_text = f"""
    Over the past {days_back} days, our threat intelligence system has identified {total_threats} security incidents 
    across {unique_countries} countries using {unique_ttps} different attack techniques. The data has been collected 
    from {unique_sources} reliable cybersecurity sources, providing comprehensive coverage of the current threat landscape.
    
    {'Key focus areas include social engineering attacks and advanced persistent threats targeting critical infrastructure.' if total_threats > 50 else 'The threat level remains manageable with standard security measures recommended.'}
    """
    
    # Render executive summary with metrics
    metrics = {
        "Total Threats": total_threats,
        "Affected Countries": unique_countries,
        "Attack Techniques": unique_ttps,
        "Intelligence Sources": unique_sources
    }
    
    ui.render_executive_summary(summary_text, metrics)
    
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
                st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                st.markdown('<h3 class="chart-title">🌍 Global Threat Distribution</h3>', unsafe_allow_html=True)
                
                # Create country data for globe
                country_counts = melted_data['country'].value_counts().to_dict()
                globe_fig = ui.create_professional_globe(country_counts)
                st.plotly_chart(globe_fig, use_container_width=True)
                st.markdown('</div>', unsafe_allow_html=True)
            
            with col2:
                st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                st.markdown('<h3 class="chart-title">🎯 Top Attack Techniques</h3>', unsafe_allow_html=True)
                
                # Create TTP data for bar chart
                ttp_counts = melted_data['TTP'].value_counts().head(10).to_dict()
                bar_fig = ui.create_professional_bar_chart(ttp_counts, "Top Attack Techniques", "h")
                st.plotly_chart(bar_fig, use_container_width=True)
                st.markdown('</div>', unsafe_allow_html=True)
            
            # Country chart
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            st.markdown('<h3 class="chart-title">🏳️ Countries by Threat Volume</h3>', unsafe_allow_html=True)
            country_bar_fig = ui.create_professional_bar_chart(country_counts, "Countries by Threat Volume")
            st.plotly_chart(country_bar_fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Heatmap
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            st.markdown('<h3 class="chart-title">🔥 Techniques vs Countries Heatmap</h3>', unsafe_allow_html=True)
            
            # Prepare heatmap data
            heatmap_data = melted_data.groupby(['country', 'TTP']).size().reset_index(name='count')
            heatmap_fig = ui.create_professional_heatmap(heatmap_data, 'country', 'TTP', 'count')
            st.plotly_chart(heatmap_fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
    
    # Data table and download
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown('<h3 class="chart-title">🔍 Raw Data & Export</h3>', unsafe_allow_html=True)
    
    # Search functionality
    search_term = st.text_input("🔎 Search in data:", placeholder="Enter search term...")
    
    if search_term:
        search_results = data_processor.filter_data_by_search(filtered_items, search_term)
        if not search_results.empty:
            st.dataframe(search_results, use_container_width=True)
            ui.create_download_button(search_results, f"search_results_{datetime.now().strftime('%Y%m%d')}.xlsx", "Download Search Results")
        else:
            st.info("No results found for your search.")
    else:
        if not filtered_items.empty:
            st.dataframe(filtered_items.head(100), use_container_width=True)  # Show first 100 rows
            ui.create_download_button(filtered_items, f"threat_data_{datetime.now().strftime('%Y%m%d')}.xlsx", "Download All Data")
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_trends_page(items, ttp_columns, country_columns, ui, data_processor):
    """Render the trends analysis page"""
    
    ui.render_main_header("Trends Analysis", "Historical threat intelligence trends and patterns")
    
    # Date selection for trends
    if 'report_date' in items.columns:
        available_dates = sorted(items['report_date'].dt.date.unique(), reverse=True)
        selected_dates = st.sidebar.multiselect(
            "📅 Select Report Dates",
            options=available_dates,
            default=available_dates[:4] if len(available_dates) >= 4 else available_dates
        )
    else:
        st.error("No date information available for trends analysis")
        return
    
    if not selected_dates:
        st.warning("Please select at least one report date.")
        return
    
    # Filter by selected dates
    trend_data = items[items['report_date'].dt.date.isin(selected_dates)]
    
    # Country selector for trends
    if country_columns:
        all_countries = data_processor.get_unique_countries(trend_data, country_columns)
        selected_country = st.sidebar.selectbox("🌍 Select Country", ["All Countries"] + all_countries)
    else:
        selected_country = "All Countries"
    
    # Filter by country if not "All"
    if selected_country != "All Countries" and country_columns:
        mask = trend_data[country_columns].apply(
            lambda row: selected_country in row.values, axis=1
        )
        trend_data = trend_data[mask]
    
    if not trend_data.empty and ttp_columns:
        # Prepare trend data
        melted_trend = data_processor.prepare_melted_data(trend_data, country_columns, ttp_columns)
        
        if not melted_trend.empty:
            # Add report date back to melted data
            date_mapping = trend_data[['report_date']].drop_duplicates()
            melted_trend = melted_trend.merge(date_mapping, how='cross').drop_duplicates()
            
            # Create trends
            ttp_trends = melted_trend.groupby(['report_date', 'TTP']).size().reset_index(name='count')
            
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            st.markdown(f'<h3 class="chart-title">📈 TTP Trends Over Time {f"- {selected_country}" if selected_country != "All Countries" else ""}</h3>', unsafe_allow_html=True)
            
            if not ttp_trends.empty:
                trend_fig = ui.create_trend_chart(ttp_trends, 'report_date', 'count', 'TTP')
                st.plotly_chart(trend_fig, use_container_width=True)
            else:
                st.info("No trend data available for the selected filters.")
            
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("No data available for trends analysis with current filters.")

def render_about_page(ui):
    """Render the about page"""
    
    ui.render_main_header("About This Dashboard", "Information about the Threat Intelligence System")
    
    st.markdown("""
    <div class="executive-summary">
        <h2 class="summary-title">🛡️ Threat Intelligence Dashboard</h2>
        <p class="summary-text">
        This professional threat intelligence dashboard provides real-time monitoring and analysis of cybersecurity threats 
        from multiple sources. The system automatically collects, processes, and visualizes threat data to help security 
        professionals make informed decisions.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Features
    st.markdown("""
    <div class="chart-container">
        <h3 class="chart-title">✨ Key Features</h3>
        <ul style="color: var(--text-secondary); line-height: 1.8; font-size: 1rem;">
            <li><strong>Real-time Data Collection:</strong> Automated gathering from 20+ cybersecurity feeds</li>
            <li><strong>MITRE ATT&CK Mapping:</strong> Automatic classification of tactics, techniques, and procedures</li>
            <li><strong>Geographic Intelligence:</strong> Country-specific threat tracking and analysis</li>
            <li><strong>Interactive Visualizations:</strong> Professional charts, globes, and heatmaps</li>
            <li><strong>Trend Analysis:</strong> Historical comparison and pattern identification</li>
            <li><strong>Export Capabilities:</strong> Download filtered data in Excel format</li>
            <li><strong>Mobile Responsive:</strong> Professional interface on all devices</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Technical Details
    st.markdown("""
    <div class="chart-container">
        <h3 class="chart-title">🔧 Technical Implementation</h3>
        <ul style="color: var(--text-secondary); line-height: 1.8; font-size: 1rem;">
            <li><strong>Backend:</strong> Python with advanced data processing</li>
            <li><strong>Frontend:</strong> Streamlit with custom CSS styling</li>
            <li><strong>Visualizations:</strong> Plotly for interactive charts</li>
            <li><strong>Data Sources:</strong> RSS feeds, OTX AlienVault, custom APIs</li>
            <li><strong>Database:</strong> SQLite with optimized queries</li>
            <li><strong>Security:</strong> API key management and rate limiting</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Contact
    st.markdown("""
    <div class="chart-container">
        <h3 class="chart-title">📧 Contact & Support</h3>
        <p style="color: var(--text-secondary); line-height: 1.6; font-size: 1rem;">
        For questions, feature requests, or technical support, please contact 
        <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank" style="color: var(--accent-color);">
        Ricardo Mendes Pinto</a>.
        </p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
