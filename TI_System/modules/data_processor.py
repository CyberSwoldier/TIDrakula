#!/usr/bin/env python3
"""
Data processing module for handling threat intelligence data
"""
import os
import glob
import pandas as pd
import pycountry
import streamlit as st

class DataProcessor:
    """Handles data processing and transformation"""
    
    def load_reports(self, folder="reports"):
        """Load and combine all report files"""
        files = glob.glob(f"{folder}/ttp_reports_*.xlsx")
        all_data = []
        
        for f in files:
            try:
                xls = pd.ExcelFile(f)
                sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
                
                if "Human_Attacks" not in xls.sheet_names:
                    st.warning(f"'Human_Attacks' sheet not found in {f}, using '{sheet_name}' instead.")
                
                df = pd.read_excel(xls, sheet_name=sheet_name)
                date_str = os.path.basename(f).replace("ttp_reports_", "").replace(".xlsx", "")
                df["report_date"] = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
                all_data.append(df)
            except Exception as e:
                st.warning(f"Could not read {f}: {e}")
                continue
        
        if all_data:
            combined = pd.concat(all_data, ignore_index=True)
            combined = combined.dropna(subset=["report_date"])
            
            if combined.empty:
                st.error("No valid data after combining reports.")
                st.stop()
            return combined
        else:
            st.error("No report files found.")
            st.stop()
    
    @staticmethod
    def get_ttp_columns(df):
        """Get all TTP description columns"""
        return [c for c in df.columns if c.lower().startswith("ttp_desc")]
    
    @staticmethod
    def get_country_columns(df):
        """Get all country columns"""
        return [c for c in df.columns if c.lower().startswith("country_")]
    
    @staticmethod
    def country_to_iso3(name):
        """Convert country name to ISO3 code"""
        try:
            return pycountry.countries.lookup(name).alpha_3
        except LookupError:
            return None
    
    def prepare_melted_data(self, df, country_columns, ttp_columns, selected_countries=None):
        """Prepare melted data for visualization"""
        if not country_columns or not ttp_columns:
            return pd.DataFrame()
        
        melted = df.melt(
            id_vars=country_columns,
            value_vars=ttp_columns,
            var_name="ttp_col",
            value_name="TTP"
        )
        
        # Handle lists in TTP column
        if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
            melted = melted.explode("TTP")
        
        melted = melted.dropna(subset=["TTP"])
        melted = melted[melted["TTP"] != "None"]
        
        # Melt countries
        melted = melted.melt(
            id_vars=["TTP"],
            value_vars=country_columns,
            var_name="country_col",
            value_name="country"
        )
        
        melted = melted.dropna(subset=["country"])
        melted = melted[melted["country"] != "None"]
        
        # Apply country filter if specified
        if selected_countries:
            melted = melted[melted["country"].isin(selected_countries)]
        
        return melted
    
    def get_unique_countries(self, df, country_columns):
        """Get list of unique countries from dataframe"""
        if not country_columns:
            return []
        
        all_countries = pd.Series(
            pd.concat([df[col] for col in country_columns], ignore_index=True)
        )
        return sorted(all_countries.dropna().unique().tolist())
    
    def filter_data_by_search(self, df, search_term):
        """Filter dataframe by search term"""
        if not search_term:
            return df
        
        mask = df.apply(
            lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(),
            axis=1
        )
        return df[mask]