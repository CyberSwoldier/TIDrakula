#!/usr/bin/env python3
"""
UI components module for creating visualizations and interface elements
"""
import streamlit as st
import plotly.graph_objects as go
import numpy as np
import pandas as pd
import pycountry
from io import BytesIO

class UIComponents:
    """Handles all UI components and visualizations"""
    
    def plot_heatmap(self, df, x_col, y_col, title, x_order=None, y_order=None, height=500):
        """Create and display a heatmap"""
        if df.empty:
            st.info("No data available to display heatmap.")
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
            colorscale="YlOrBr",
            text=text_values,
            texttemplate="%{text}",
            textfont={"size": 10},
            hovertemplate=f"{x_col}: %{{x}}<br>{y_col}: %{{y}}<br>Count: %{{z}}<extra></extra>",
            showscale=False,
            xgap=1,
            ygap=1
        ))
        
        fig.update_layout(
            title=dict(text=title, y=0.95, font=dict(size=16)),
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            height=height,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=False),
            margin=dict(l=0, r=0, t=20, b=20)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def plot_globe(self, iso_codes, height=400):
        """Create and display a globe visualization"""
        all_iso = [c.alpha_3 for c in pycountry.countries]
        z_values = [1 if code in iso_codes else 0 for code in all_iso]
        
        fig_globe = go.Figure(go.Choropleth(
            locations=all_iso,
            z=z_values,
            colorscale=[[0, 'rgba(30,30,30,1)'], [1, 'yellow']],
            showscale=False,
            marker_line_color='lightblue',
            marker_line_width=0.5
        ))
        
        fig_globe.update_geos(
            projection_type="orthographic",
            showcoastlines=True,
            coastlinecolor="lightblue",
            showland=True,
            landcolor="#0E1117",
            showocean=True,
            oceancolor="#0E1117",
            showframe=False,
            bgcolor="#0E1117"
        )
        
        fig_globe.update_layout(
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            margin=dict(l=0, r=0, t=10, b=10),
            height=height
        )
        
        return fig_globe
    
    def plot_bar_chart(self, df, x_col, y_col, orientation="v", height=400, title=None):
        """Create and display a bar chart"""
        if orientation == "h":
            fig = go.Figure(go.Bar(
                x=df[x_col],
                y=df[y_col],
                orientation="h",
                text=df[x_col],
                textposition="auto",
                marker=dict(color=df[x_col], colorscale="YlOrBr")
            ))
        else:
            fig = go.Figure(go.Bar(
                x=df[x_col],
                y=df[y_col],
                text=df[y_col],
                textposition="auto",
                marker=dict(color=df[y_col], colorscale="YlOrBr")
            ))
        
        fig.update_layout(
            title=title,
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            height=height,
            margin=dict(l=0, r=0, t=10, b=10),
            yaxis=dict(automargin=True) if orientation == "h" else None
        )
        
        return fig
    
    def plot_trend_line(self, ttp_counts, height=500):
        """Create and display trend line chart"""
        fig = go.Figure()
        
        for ttp in ttp_counts["TTP"].unique():
            subset = ttp_counts[ttp_counts["TTP"] == ttp]
            fig.add_trace(go.Scatter(
                x=subset["report_date"],
                y=subset["count"],
                mode="lines+markers",
                name=ttp
            ))
        
        fig.update_layout(
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            height=height,
            margin=dict(l=0, r=0, t=20, b=20)
        )
        
        return fig
    
    def create_download_button(self, df, filename, label="Download Data"):
        """Create a download button for Excel export"""
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Filtered Data")
        output.seek(0)
        
        st.download_button(
            label=label,
            data=output,
            file_name=filename,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    
    def render_footer(self):
        """Render the footer"""
        st.markdown(
            """
            <hr style="margin-top:20px; margin-bottom:10px">
            <p style="text-align:center; color:grey; font-size:12px;">
            @ Created by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank">Ricardo Mendes Pinto</a>.
            </p>
            """,
            unsafe_allow_html=True
        )