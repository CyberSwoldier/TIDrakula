#!/usr/bin/env python3
"""
Main entry point for the Weekly Threat Intelligence Dashboard
"""
import streamlit as st
from modules.config import Config
from modules.data_fetcher import DataFetcher
from modules.data_processor import DataProcessor
from modules.ui_components import UIComponents
from modules.dashboard_page import DashboardPage
from modules.trends_page import TrendsPage
from modules.about_page import AboutPage

def main():
    # Initialize configuration
    config = Config()
    st.set_page_config(page_title=config.PAGE_TITLE, layout=config.LAYOUT)
    
    # Initialize components
    data_fetcher = DataFetcher(config)
    data_processor = DataProcessor()
    ui = UIComponents()
    
    # Fetch and load data
    data_fetcher.fetch_reports()
    items = data_processor.load_reports(config.REPORTS_FOLDER)
    
    # Detect columns
    ttp_columns = data_processor.get_ttp_columns(items)
    country_columns = data_processor.get_country_columns(items)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Select a page:", ["Dashboard", "Trends", "About"])
    
    # Route to appropriate page
    if page == "About":
        about_page = AboutPage()
        about_page.render()
    elif page == "Dashboard":
        dashboard_page = DashboardPage(items, ttp_columns, country_columns, ui, data_processor)
        dashboard_page.render()
    elif page == "Trends":
        trends_page = TrendsPage(items, ttp_columns, country_columns, ui, data_processor)
        trends_page.render()
    
    # Footer
    ui.render_footer()

if __name__ == "__main__":
    main()