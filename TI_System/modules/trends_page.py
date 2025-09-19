#!/usr/bin/env python3
"""
Trends page module for analyzing trends over time
File: modules/trends_page.py
"""
import streamlit as st
import pandas as pd

class TrendsPage:
    """Handles the trends analysis page"""
    
    def __init__(self, items, ttp_columns, country_columns, ui, data_processor):
        self.items = items
        self.ttp_columns = ttp_columns
        self.country_columns = country_columns
        self.ui = ui
        self.processor = data_processor
    
    def render(self):
        """Render the trends page"""
        st.title("Trends Over Time")
        
        # Date selection
        report_dates = sorted(self.items['report_date'].dt.date.unique(), reverse=True)
        selected_dates = st.multiselect(
            "Select reports (weeks) to compare",
            options=report_dates,
            default=report_dates[:4] if len(report_dates) >= 4 else report_dates
        )
        
        if not selected_dates:
            st.warning("Please select at least one report.")
            return
        
        # Country selection
        all_countries = self.processor.get_unique_countries(self.items, self.country_columns)
        selected_country = st.selectbox("Select a country", ["All"] + all_countries)
        
        # Filter data
        trend_data = self.items[self.items['report_date'].dt.date.isin(selected_dates)]
        
        if selected_country != "All" and self.country_columns:
            trend_data = trend_data[
                trend_data[self.country_columns].apply(
                    lambda row: selected_country in row.values, axis=1
                )
            ]
        
        # Prepare and visualize trends
        if not trend_data.empty and self.ttp_columns and self.country_columns:
            self._render_ttp_trends(trend_data, selected_country)
    
    def _render_ttp_trends(self, trend_data, selected_country):
        """Render TTP trends visualization"""
        melted = self.processor.prepare_melted_data(
            trend_data,
            self.country_columns,
            self.ttp_columns
        )
        
        if selected_country != "All":
            melted = melted[melted["country"] == selected_country]
        
        # Add report_date back
        melted = melted.merge(
            trend_data[['report_date']].drop_duplicates(),
            how='cross'
        ).drop_duplicates()
        
        ttp_counts = melted.groupby(["report_date", "TTP"]).size().reset_index(name="count")
        
        st.subheader("TTP Trends Over Time")
        
        if not ttp_counts.empty:
            fig = self.ui.plot_trend_line(ttp_counts)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available for the selected filters.")