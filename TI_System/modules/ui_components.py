#!/usr/bin/env python3
"""
Enhanced UI components module with professional styling for Streamlit
File: modules/ui_components.py
"""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import pandas as pd
import pycountry
from io import BytesIO

class UIComponents:
    """Enhanced UI components with professional styling"""
    
    def __init__(self):
        """Initialize UI components with custom styling"""
        self.setup_page_config()
        self.inject_custom_css()
    
    def setup_page_config(self):
        """Configure Streamlit page settings - only call once"""
        try:
            st.set_page_config(
                page_title="🛡️ Threat Intelligence Dashboard",
                page_icon="🛡️",
                layout="wide",
                initial_sidebar_state="expanded"
            )
        except:
            pass  # Already configured
    
    def inject_custom_css(self):
        """Inject custom CSS for professional styling"""
        st.markdown("""
        <style>
        /* Import Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        
        /* Global Variables */
        :root {
            --primary-bg: #0a0b0f;
            --secondary-bg: #1a1d23;
            --tertiary-bg: #2a2d35;
            --accent-color: #00d4ff;
            --warning-color: #ff9500;
            --danger-color: #ff3333;
            --success-color: #00ff88;
            --text-primary: #ffffff;
            --text-secondary: #b0b3b8;
            --border-color: #3a3d45;
        }
        
        /* Main App Styling */
        .stApp {
            background: linear-gradient(135deg, var(--primary-bg) 0%, #0f1419 100%);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
        }
        
        /* Header Styling */
        .main-header {
            background: linear-gradient(135deg, var(--secondary-bg), var(--tertiary-bg));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }
        
        .header-title {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent-color), #00a8cc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }
        
        .header-subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
            font-weight: 400;
        }
        
        /* Metric Cards */
        .metric-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .metric-card {
            background: linear-gradient(135deg, var(--secondary-bg), var(--tertiary-bg));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-color), var(--success-color));
        }
        
        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.2);
        }
        
        .metric-value {
            font-size: 3rem;
            font-weight: 800;
            color: var(--accent-color);
            margin-bottom: 0.5rem;
            line-height: 1;
        }
        
        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Chart Containers */
        .chart-container {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }
        
        .chart-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .chart-icon {
            width: 24px;
            height: 24px;
            background: var(--accent-color);
            border-radius: 6px;
            display: inline-block;
        }
        
        /* Sidebar Styling */
        .css-1d391kg {
            background: var(--secondary-bg);
            border-right: 1px solid var(--border-color);
        }
        
        /* Filter Styling */
        .filter-container {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        /* Executive Summary */
        .executive-summary {
            background: linear-gradient(135deg, var(--secondary-bg), var(--tertiary-bg));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }
        
        .summary-title {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--accent-color);
            margin-bottom: 1rem;
        }
        
        .summary-text {
            color: var(--text-secondary);
            line-height: 1.6;
            font-size: 1rem;
        }
        
        /* Button Styling */
        .stButton > button {
            background: linear-gradient(135deg, var(--accent-color), #00a8cc);
            border: none;
            color: white;
            font-weight: 600;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);
        }
        
        /* Selectbox Styling */
        .stSelectbox > div > div {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        
        /* Multiselect Styling */
        .stMultiSelect > div > div {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
        }
        
        /* DataFrame Styling */
        .stDataFrame {
            background: var(--secondary-bg);
            border-radius: 12px;
            overflow: hidden;
        }
        
        /* Loading Animation */
        .loading-animation {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 200px;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border-color);
            border-top: 3px solid var(--accent-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Mobile Responsiveness */
        @media (max-width: 768px) {
            .metric-row {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .header-title {
                font-size: 2rem;
            }
            
            .metric-value {
                font-size: 2rem;
            }
        }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--primary-bg);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--accent-color);
            border-radius: 4px;
        }
        </style>
        """, unsafe_allow_html=True)
    
    # ---------------- Header & Metrics ---------------- #
    def render_main_header(self, title: str, subtitle: str = ""):
        """Render the main dashboard header"""
        st.markdown(f"""
        <div class="main-header">
            <h1 class="header-title">🛡️ {title}</h1>
            {f'<p class="header-subtitle">{subtitle}</p>' if subtitle else ''}
        </div>
        """, unsafe_allow_html=True)
    
    def render_metric_cards(self, metrics: dict):
        """Render metric cards in a professional layout"""
        cols = st.columns(len(metrics))
        for i, (label, value) in enumerate(metrics.items()):
            with cols[i]:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{value:,}</div>
                    <div class="metric-label">{label}</div>
                </div>
                """, unsafe_allow_html=True)
    
    def render_executive_summary(self, summary_text: str, metrics: dict):
        """Render executive summary section"""
        st.markdown(f"""
        <div class="executive-summary">
            <div class="summary-text">{summary_text}</div>
        </div>
        """, unsafe_allow_html=True)
        self.render_metric_cards(metrics)
    
    # ---------------- Globe ---------------- #
    def create_professional_globe(self, country_data: dict, height: int = 400):
        """Create a globe highlighting affected countries with borders"""
        countries = list(country_data.keys())
        try:
            all_country_codes = [country.alpha_3 for country in pycountry.countries]
        except:
            all_country_codes = []
        
        affected_countries = []
        for country in countries:
            try:
                code = pycountry.countries.lookup(country).alpha_3
                affected_countries.append(code)
            except:
                continue
        
        z_data = []
        locations = []
        for code in all_country_codes:
            locations.append(code)
            z_data.append(1 if code in affected_countries else 0)
        
        fig = go.Figure(go.Choropleth(
            locations=locations,
            z=z_data,
            colorscale=[[0, '#1a1d23'], [1, '#00d4ff']],
            showscale=False,
            marker_line_color='white',  # keep borders visible
            marker_line_width=0.5,
            hovertemplate='<b>%{location}</b><br>Status: %{customdata}<extra></extra>',
            customdata=['Affected' if z == 1 else 'Not Affected' for z in z_data]
        ))
        
        fig.update_geos(
            projection_type="orthographic",
            showcoastlines=True,
            coastlinecolor="#00d4ff",
            showland=True,
            landcolor="#1a1d23",
            showocean=True,
            oceancolor="#0a0b0f",
            showframe=False,
            bgcolor="#0a0b0f"
        )
        
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=height,
            margin=dict(t=10, b=10, l=10, r=10)
        )
        
        return fig
    
    # ---------------- Charts ---------------- #
    def create_professional_bar_chart(self, data: dict, title: str, orientation: str = "v"):
        if orientation == "h":
            fig = go.Figure(go.Bar(
                y=list(data.keys()),
                x=list(data.values()),
                orientation='h',
                marker=dict(
                    color=list(data.values()),
                    colorscale=[[0, '#2a2d35'], [0.5, '#00a8cc'], [1, '#00d4ff']],
                    line=dict(color='#00d4ff', width=1)
                ),
                text=list(data.values()),
                textposition='inside',
                textfont=dict(color='white', size=12, family='Inter'),
                hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>'
            ))
        else:
            fig = go.Figure(go.Bar(
                x=list(data.keys()),
                y=list(data.values()),
                marker=dict(
                    color=list(data.values()),
                    colorscale=[[0, '#2a2d35'], [0.5, '#00a8cc'], [1, '#00d4ff']],
                    line=dict(color='#00d4ff', width=1)
                ),
                text=list(data.values()),
                textposition='inside',
                textfont=dict(color='white', size=12, family='Inter'),
                hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
            ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis=dict(gridcolor='#3a3d45', zerolinecolor='#3a3d45'),
            yaxis=dict(gridcolor='#3a3d45', zerolinecolor='#3a3d45'),
            margin=dict(t=20, b=40, l=40, r=40)
        )
        return fig
    
def create_professional_table_heatmap(self, data: pd.DataFrame, x_col: str, y_col: str, value_col: str):
    """
    Minimalistic table-like heatmap:
    - No colors on cells
    - Grid lines visible
    - Numbers displayed with spacing
    - Zeros hidden
    """
    pivot_data = data.pivot(index=y_col, columns=x_col, values=value_col).fillna(0)

    # Replace zeros with empty string for text
    text_values = pivot_data.values.astype(int).astype(str)
    text_values[pivot_data.values == 0] = ""

    # Create heatmap with transparent colors
    fig = go.Figure(go.Heatmap(
        z=np.zeros_like(pivot_data.values),  # all zero: no color
        x=list(pivot_data.columns),
        y=list(pivot_data.index),
        text=text_values,
        texttemplate="%{text}",
        textfont=dict(size=16, color="white", family='Inter'),
        colorscale=[[0, "rgba(0,0,0,0)"], [1, "rgba(0,0,0,0)"]],  # fully transparent
        showscale=False,
        xgap=2,  # space between columns
        ygap=2,  # space between rows
        hovertemplate=f'{x_col}: %{{x}}<br>{y_col}: %{{y}}<br>Count: %{{text}}<extra></extra>'
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(gridcolor='rgba(255,255,255,0.3)', zeroline=False, tickangle=-45),
        yaxis=dict(gridcolor='rgba(255,255,255,0.3)', zeroline=False, autorange='reversed'),
        margin=dict(t=20, b=80, l=150, r=20),
        height=500
    )

    return fig
    
    def create_trend_chart(self, data: pd.DataFrame, x_col: str, y_col: str, category_col: str):
        fig = go.Figure()
        categories = data[category_col].unique()[:10]
        colors = px.colors.qualitative.Set3
        for i, category in enumerate(categories):
            category_data = data[data[category_col] == category]
            fig.add_trace(go.Scatter(
                x=category_data[x_col],
                y=category_data[y_col],
                mode='lines+markers',
                name=category,
                line=dict(color=colors[i % len(colors)], width=3),
                marker=dict(size=6)
            ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis=dict(gridcolor='#3a3d45', zerolinecolor='#3a3d45'),
            yaxis=dict(gridcolor='#3a3d45', zerolinecolor='#3a3d45'),
            legend=dict(bgcolor='rgba(42, 45, 53, 0.8)', bordercolor='#3a3d45', font=dict(color='white')),
            height=400,
            margin=dict(t=20, b=40, l=40, r=40)
        )
        return fig
    
    # ---------------- Loading & Footer ---------------- #
    def render_loading_spinner(self, message: str = "Loading..."):
        st.markdown(f"""
        <div class="loading-animation">
            <div class="spinner"></div>
            <span style="margin-left: 1rem; color: var(--text-secondary);">{message}</span>
        </div>
        """, unsafe_allow_html=True)
    
    def render_chart_container(self, title: str, chart_func, *args, **kwargs):
        st.markdown(f"""
        <div class="chart-container">
            <h3 class="chart-title">
                <span class="chart-icon"></span>
                {title}
            </h3>
        </div>
        """, unsafe_allow_html=True)
        chart = chart_func(*args, **kwargs)
        st.plotly_chart(chart, use_container_width=True)
    
    def create_download_button(self, df: pd.DataFrame, filename: str, label: str = "Download Data"):
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Data")
        output.seek(0)
        st.download_button(
            label=f"📥 {label}",
            data=output,
            file_name=filename,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    
    def render_footer(self):
        st.markdown("""
        <div style="margin-top: 3rem; padding: 2rem 0; border-top: 1px solid var(--border-color);">
            <div style="text-align: center; color: var(--text-secondary); font-size: 0.9rem;">
                <p>🛡️ <strong>Professional Threat Intelligence Dashboard</strong></p>
                <p>Created with ❤️ by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank" 
                   style="color: var(--accent-color); text-decoration: none;">Ricardo Mendes Pinto</a></p>
                <p><em>Powered by Python, Streamlit & Advanced Analytics</em></p>
            </div>
        </div>
        """, unsafe_allow_html=True)
