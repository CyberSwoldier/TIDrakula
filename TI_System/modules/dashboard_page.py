#!/usr/bin/env python3
"""
Dashboard page module for the main dashboard view
"""
import streamlit as st
import pandas as pd
import pycountry

class DashboardPage:
    """Handles the main dashboard page"""
    
    def __init__(self, items, ttp_columns, country_columns, ui, data_processor):
        self.items = items
        self.ttp_columns = ttp_columns
        self.country_columns = country_columns
        self.ui = ui
        self.processor = data_processor
    
    def render(self):
        """Render the dashboard page"""
        st.title("Weekly Threat Intelligence Report")
        
        # Date selection
        report_dates = sorted(self.items['report_date'].dt.date.unique(), reverse=True)
        selected_date = st.selectbox("Select a report to view", report_dates, index=0)
        selected_report = self.items[self.items['report_date'].dt.date == selected_date]
        
        # Country filter
        all_countries = self.processor.get_unique_countries(selected_report, self.country_columns)
        selected_countries = st.multiselect(
            "🌍 Filter by Country (leave empty to show all)",
            options=all_countries,
            default=[]
        )
        
        # Metrics
        self._render_metrics(selected_report)
        
        # Visualizations
        if self.country_columns and self.ttp_columns:
            melted = self.processor.prepare_melted_data(
                selected_report,
                self.country_columns,
                self.ttp_columns,
                selected_countries
            )
            
            if not melted.empty:
                self._render_visualizations(selected_report, melted, selected_countries)
        
        # Search and download
        self._render_search_section()
    
    def _render_metrics(self, selected_report):
        """Render metrics section"""
        col1, col2 = st.columns(2)
        
        # TTP count
        unique_ttps_count = self._calculate_unique_ttps(selected_report)
        with col1:
            st.metric("MITRE TTPs", unique_ttps_count)
        
        # Sources count
        sources_count = selected_report['source'].nunique() if 'source' in selected_report.columns else 0
        with col2:
            st.metric("Sources", sources_count)
    
    def _calculate_unique_ttps(self, df):
        """Calculate unique TTPs count"""
        if not self.ttp_columns:
            return 0
        
        all_ttps = pd.Series(pd.concat([df[col] for col in self.ttp_columns], ignore_index=True))
        all_ttps_flat = []
        
        for val in all_ttps:
            if isinstance(val, (list, tuple, set)):
                all_ttps_flat.extend([str(x) for x in val if x not in [None, "None"]])
            elif pd.notna(val) and str(val) != "None":
                all_ttps_flat.append(str(val))
        
        return len(set(all_ttps_flat))
    
    def _render_visualizations(self, selected_report, melted, selected_countries):
        """Render all visualizations"""
        # Globe and TTP chart side by side
        col_globe, col_ttp = st.columns([1, 1.5])
        
        # Globe
        with col_globe:
            iso_codes = self._get_iso_codes(selected_report, selected_countries)
            fig_globe = self.ui.plot_globe(iso_codes)
            st.plotly_chart(fig_globe, use_container_width=True)
        
        # Top MITRE Techniques
        with col_ttp:
            ttp_counts = melted.groupby("TTP").size().reset_index(name="count")
            ttp_counts = ttp_counts.sort_values("count", ascending=False)
            fig_ttp = self.ui.plot_bar_chart(ttp_counts, "count", "TTP", orientation="h")
            st.plotly_chart(fig_ttp, use_container_width=True)
        
        # Countries bar chart
        st.subheader("Occurrences per Country")
        country_counts = melted.groupby("country").size().reset_index(name="count")
        country_counts = country_counts.sort_values("count", ascending=False)
        fig_country = self.ui.plot_bar_chart(country_counts, "country", "count")
        st.plotly_chart(fig_country, use_container_width=True)
        
        # Heatmap
        st.subheader("MITRE Techniques per Country")
        heat_data = melted.groupby(["country", "TTP"]).size().reset_index(name="count")
        self.ui.plot_heatmap(heat_data, x_col="country", y_col="TTP", title="", height=500)
    
    def _get_iso_codes(self, selected_report, selected_countries):
        """Get ISO codes for countries"""
        all_countries_series = pd.Series(
            pd.concat([selected_report[col] for col in self.country_columns], ignore_index=True)
        )
        all_countries_series = all_countries_series.dropna()
        all_countries_series = all_countries_series[all_countries_series != "None"]
        
        if selected_countries:
            all_countries_series = all_countries_series[all_countries_series.isin(selected_countries)]
        
        iso_codes = all_countries_series.map(self.processor.country_to_iso3).dropna().unique()
        return iso_codes
    
    def _render_search_section(self):
        """Render search and download section"""
        st.subheader("Raw Data Search & Download")
        search_term = st.text_input("Search in table", "")
        
        if search_term:
            filtered_items = self.processor.filter_data_by_search(self.items, search_term)
            
            if not filtered_items.empty:
                st.dataframe(filtered_items, use_container_width=True)
                self.ui.create_download_button(
                    filtered_items,
                    "filtered_results.xlsx",
                    "Download Filtered Results"
                )
            else:
                st.info("No results found.")
        else:
            st.info("Enter a search term to view results.")