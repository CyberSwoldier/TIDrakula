# ===========================
# About Page Module
# ===========================

"""
About page module for application information
File: modules/about_page.py
"""
import streamlit as st

class AboutPage:
    """Handles the about page"""
    
    def render(self):
        """Render the about page"""
        st.title("About This Dashboard")
        
        st.markdown("""
        This dashboard is updated every Friday and provides threat intelligence insights of the last 7 days.
        
        ## Features:
        - **Dashboard**: Select a report date to view metrics, globe, charts, and heatmaps of that week.
        - **Trends**: Select multiple reports and a country to analyze changes over time.
        - **Search**: Find specific data and export to Excel.
        
        ## Data Sources:
        - Reports are fetched from GitHub repository
        - Data includes MITRE TTPs, affected countries, and threat actor information
        - Updated weekly with 7-day rolling window
        
        ## Technical Details:
        - Built with Streamlit and Plotly
        - Data processing with Pandas
        - Country mapping with pycountry
        """)
        
        st.markdown("---")
        st.markdown("For more info, talk to [Ricardo Mendes Pinto](https://www.linkedin.com/in/ricardopinto110993/).")