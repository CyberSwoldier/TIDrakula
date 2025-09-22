"""
Futuristic UI Components for Cybersecurity Dashboard
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

def apply_futuristic_theme():
    """Apply futuristic CSS styling to the entire dashboard"""
    st.markdown("""
    <style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
    /* Main app background */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #151934 50%, #1a0033 100%);
        background-attachment: fixed;
    }
    
    /* Animated background effect */
    .stApp::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            radial-gradient(circle at 20% 80%, rgba(191, 0, 255, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 80% 20%, rgba(0, 255, 255, 0.1) 0%, transparent 50%);
        pointer-events: none;
        z-index: 0;
        animation: float 20s ease-in-out infinite;
    }
    
    @keyframes float {
        0%, 100% { transform: translate(0, 0); }
        33% { transform: translate(-20px, -20px); }
        66% { transform: translate(20px, -10px); }
    }
    
    /* Headers styling */
    h1 {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(90deg, #00ffff, #bf00ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-transform: uppercase;
        letter-spacing: 3px;
        font-weight: 900 !important;
        text-align: center;
        padding: 20px 0;
        font-size: 3em !important;
        text-shadow: 0 0 30px rgba(0, 255, 255, 0.5);
    }
    
    h2 {
        font-family: 'Orbitron', monospace !important;
        color: #00ffff !important;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-weight: 700 !important;
        margin-top: 2rem !important;
        text-shadow: 0 0 20px rgba(0, 255, 255, 0.4);
    }
    
    h3 {
        font-family: 'Orbitron', monospace !important;
        color: #bf00ff !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600 !important;
        text-shadow: 0 0 15px rgba(191, 0, 255, 0.4);
    }
    
    /* Sidebar styling */
    .css-1d391kg, [data-testid="stSidebar"] {
        background: rgba(20, 25, 47, 0.95);
        backdrop-filter: blur(20px);
        border-right: 2px solid rgba(0, 255, 255, 0.3);
    }
    
    .css-1d391kg .block-container {
        padding-top: 2rem;
    }
    
    /* Metric cards */
    [data-testid="metric-container"] {
        background: rgba(20, 25, 47, 0.7);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(0, 255, 255, 0.3);
        padding: 20px;
        border-radius: 15px;
        box-shadow: 
            0 0 20px rgba(0, 255, 255, 0.2),
            inset 0 0 20px rgba(191, 0, 255, 0.05);
        transition: all 0.3s ease;
    }
    
    [data-testid="metric-container"]:hover {
        transform: translateY(-5px);
        border-color: rgba(0, 255, 255, 0.5);
        box-shadow: 
            0 10px 40px rgba(0, 255, 255, 0.3),
            inset 0 0 30px rgba(191, 0, 255, 0.1);
    }
    
    [data-testid="metric-container"] label {
        font-family: 'Orbitron', monospace !important;
        color: #b8bcc8 !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.9em !important;
    }
    
    [data-testid="metric-container"] > div > div > div {
        font-family: 'Orbitron', monospace !important;
        font-size: 2.5em !important;
        font-weight: 700 !important;
        background: linear-gradient(45deg, #00ffff, #ff00bf);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    /* Selectbox and multiselect styling */
    .stSelectbox > div > div, .stMultiSelect > div > div {
        background: rgba(0, 0, 0, 0.4) !important;
        border: 1px solid rgba(0, 255, 255, 0.3) !important;
        border-radius: 10px !important;
        color: #ffffff !important;
        transition: all 0.3s ease;
    }
    
    .stSelectbox > div > div:hover, .stMultiSelect > div > div:hover {
        border-color: rgba(0, 255, 255, 0.6) !important;
        box-shadow: 0 0 15px rgba(0, 255, 255, 0.3) !important;
    }
    
    /* Date input styling */
    .stDateInput > div > div {
        background: rgba(0, 0, 0, 0.4) !important;
        border: 1px solid rgba(191, 0, 255, 0.3) !important;
        border-radius: 10px !important;
        color: #ffffff !important;
    }
    
    .stDateInput > div > div:hover {
        border-color: rgba(191, 0, 255, 0.6) !important;
        box-shadow: 0 0 15px rgba(191, 0, 255, 0.3) !important;
    }
    
    /* Button styling */
    .stButton > button {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(45deg, #00ffff, #bf00ff);
        color: #ffffff !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 10px 30px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(0, 255, 255, 0.3);
    }
    
    .stButton > button:hover {
        transform: translateY(-3px) !important;
        box-shadow: 0 6px 25px rgba(191, 0, 255, 0.4) !important;
        background: linear-gradient(45deg, #bf00ff, #ff00bf) !important;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        font-family: 'Orbitron', monospace !important;
        background: rgba(20, 25, 47, 0.7) !important;
        border: 1px solid rgba(255, 0, 191, 0.3) !important;
        border-radius: 10px !important;
        color: #ff00bf !important;
    }
    
    .streamlit-expanderHeader:hover {
        border-color: rgba(255, 0, 191, 0.5) !important;
        box-shadow: 0 0 20px rgba(255, 0, 191, 0.3) !important;
    }
    
    /* Info, warning, error boxes */
    .stAlert {
        background: rgba(20, 25, 47, 0.9) !important;
        border: 1px solid rgba(0, 255, 255, 0.4) !important;
        border-radius: 10px !important;
        color: #ffffff !important;
        backdrop-filter: blur(10px);
    }
    
    /* Tables */
    .dataframe {
        background: rgba(20, 25, 47, 0.7) !important;
        border: 1px solid rgba(0, 255, 255, 0.3) !important;
        border-radius: 10px !important;
        color: #ffffff !important;
    }
    
    .dataframe thead tr th {
        background: rgba(0, 255, 255, 0.1) !important;
        color: #00ffff !important;
        font-family: 'Orbitron', monospace !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .dataframe tbody tr:hover {
        background: rgba(191, 0, 255, 0.1) !important;
    }
    
    /* Plotly charts background */
    .js-plotly-plot {
        border-radius: 15px !important;
        overflow: hidden !important;
        box-shadow: 0 0 30px rgba(0, 255, 255, 0.2) !important;
    }
    
    /* Text color */
    p, span, div {
        color: #b8bcc8 !important;
    }
    
    /* Loading spinner */
    .stSpinner > div {
        border-color: #00ffff !important;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0a0e27;
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00ffff, #bf00ff);
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #bf00ff, #ff00bf);
    }
    
    /* Column containers */
    [data-testid="column"] {
        background: rgba(20, 25, 47, 0.3);
        backdrop-filter: blur(5px);
        border-radius: 15px;
        padding: 15px;
        border: 1px solid rgba(0, 255, 255, 0.1);
        margin: 5px;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        background: rgba(20, 25, 47, 0.5);
        border-radius: 10px;
        padding: 5px;
    }
    
    .stTabs [data-baseweb="tab"] {
        font-family: 'Orbitron', monospace !important;
        color: #b8bcc8 !important;
        background: transparent !important;
        border-radius: 8px !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(45deg, #00ffff, #bf00ff) !important;
        color: #ffffff !important;
    }
    
    /* Progress bar */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #00ffff, #bf00ff, #ff00bf) !important;
    }
    
    /* Caption text */
    .caption {
        font-family: 'Orbitron', monospace !important;
        color: #00ffff !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.8em !important;
    }
    </style>
    """, unsafe_allow_html=True)

def create_futuristic_header(title, subtitle=None):
    """Create a futuristic animated header"""
    header_html = f"""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                backdrop-filter: blur(20px); border-radius: 20px; 
                border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;
                box-shadow: 0 0 40px rgba(0, 255, 255, 0.2), inset 0 0 20px rgba(191, 0, 255, 0.05);">
        <h1 style="margin: 0; animation: glow 2s ease-in-out infinite alternate;">
            {title}
        </h1>
        {f'<p style="color: #b8bcc8; font-size: 1.1em; margin-top: 10px; letter-spacing: 2px; text-transform: uppercase;">{subtitle}</p>' if subtitle else ''}
    </div>
    <style>
        @keyframes glow {{
            from {{ text-shadow: 0 0 20px rgba(0, 255, 255, 0.5), 0 0 40px rgba(191, 0, 255, 0.3); }}
            to {{ text-shadow: 0 0 30px rgba(0, 255, 255, 0.7), 0 0 60px rgba(191, 0, 255, 0.5); }}
        }}
    </style>
    """
    st.markdown(header_html, unsafe_allow_html=True)

def create_metric_card(label, value, delta=None, delta_color="normal"):
    """Create a futuristic metric card with glow effect"""
    delta_html = ""
    if delta is not None:
        delta_symbol = "↑" if delta > 0 else "↓"
        delta_color_code = "#00ff00" if delta > 0 else "#ff0000"
        delta_html = f'<div style="color: {delta_color_code}; font-size: 1.2em;">{delta_symbol} {abs(delta)}%</div>'
    
    card_html = f"""
    <div style="background: rgba(20, 25, 47, 0.8); backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 255, 255, 0.3); border-radius: 15px;
                padding: 20px; text-align: center; height: 150px;
                transition: all 0.3s ease; cursor: pointer;
                box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);"
         onmouseover="this.style.transform='translateY(-5px)'; this.style.boxShadow='0 10px 40px rgba(0, 255, 255, 0.4)';"
         onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 0 20px rgba(0, 255, 255, 0.2)';">
        <div style="color: #b8bcc8; font-size: 0.9em; text-transform: uppercase; 
                    letter-spacing: 1px; margin-bottom: 10px; font-family: 'Orbitron', monospace;">
            {label}
        </div>
        <div style="font-size: 2.5em; font-weight: bold; font-family: 'Orbitron', monospace;
                    background: linear-gradient(45deg, #00ffff, #ff00bf);
                    -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            {value}
        </div>
        {delta_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)

def get_futuristic_plot_layout():
    """Get default layout configuration for Plotly charts with futuristic theme"""
    return dict(
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(
            family="Orbitron, monospace",
            color='#b8bcc8'
        ),
        title=dict(
            font=dict(
                size=20,
                color='#00ffff'
            )
        ),
        xaxis=dict(
            gridcolor='rgba(0, 255, 255, 0.1)',
            zerolinecolor='rgba(0, 255, 255, 0.2)',
            showgrid=True,
            zeroline=True
        ),
        yaxis=dict(
            gridcolor='rgba(191, 0, 255, 0.1)',
            zerolinecolor='rgba(191, 0, 255, 0.2)',
            showgrid=True,
            zeroline=True
        ),
        hoverlabel=dict(
            bgcolor='rgba(20, 25, 47, 0.9)',
            bordercolor='#00ffff',
            font=dict(
                family="Orbitron, monospace",
                color='#ffffff'
            )
        ),
        margin=dict(l=40, r=40, t=60, b=40),
        showlegend=True,
        legend=dict(
            bgcolor='rgba(20, 25, 47, 0.5)',
            bordercolor='rgba(0, 255, 255, 0.3)',
            borderwidth=1,
            font=dict(color='#b8bcc8')
        )
    )

def get_neon_color_palette():
    """Get neon color palette for charts"""
    return [
        '#00ffff',  # Cyan
        '#bf00ff',  # Purple
        '#ff00bf',  # Pink
        '#00ff7f',  # Spring Green
        '#ff7f00',  # Orange
        '#7f00ff',  # Violet
        '#ffff00',  # Yellow
        '#00ff00',  # Lime
        '#ff0000',  # Red
        '#0080ff'   # Sky Blue
    ]

def create_animated_line_chart(df, x_col, y_col, title=""):
    """Create an animated line chart with glow effect"""
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df[x_col],
        y=df[y_col],
        mode='lines+markers',
        line=dict(
            color='#00ffff',
            width=3,
            shape='spline'
        ),
        marker=dict(
            size=8,
            color='#bf00ff',
            line=dict(
                color='#00ffff',
                width=2
            )
        ),
        fill='tozeroy',
        fillcolor='rgba(0, 255, 255, 0.1)',
        hovertemplate='<b>%{x}</b><br>Value: %{y}<extra></extra>'
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['height'] = 400
    
    fig.update_layout(layout)
    
    return fig

def create_3d_scatter(df, x_col, y_col, z_col, color_col=None, title=""):
    """Create a 3D scatter plot with futuristic styling"""
    fig = go.Figure()
    
    colors = df[color_col] if color_col else '#00ffff'
    
    fig.add_trace(go.Scatter3d(
        x=df[x_col],
        y=df[y_col],
        z=df[z_col],
        mode='markers',
        marker=dict(
            size=8,
            color=colors,
            colorscale=[[0, '#00ffff'], [0.5, '#bf00ff'], [1, '#ff00bf']],
            opacity=0.8,
            line=dict(color='white', width=0.5)
        ),
        text=df.index if hasattr(df, 'index') else None,
        hovertemplate='<b>%{text}</b><br>X: %{x}<br>Y: %{y}<br>Z: %{z}<extra></extra>'
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['scene'] = dict(
        xaxis=dict(
            backgroundcolor='rgba(20, 25, 47, 0.1)',
            gridcolor='rgba(0, 255, 255, 0.1)',
            showbackground=True,
            zerolinecolor='rgba(0, 255, 255, 0.2)',
        ),
        yaxis=dict(
            backgroundcolor='rgba(20, 25, 47, 0.1)',
            gridcolor='rgba(191, 0, 255, 0.1)',
            showbackground=True,
            zerolinecolor='rgba(191, 0, 255, 0.2)',
        ),
        zaxis=dict(
            backgroundcolor='rgba(20, 25, 47, 0.1)',
            gridcolor='rgba(255, 0, 191, 0.1)',
            showbackground=True,
            zerolinecolor='rgba(255, 0, 191, 0.2)',
        )
    )
    layout['height'] = 500
    
    fig.update_layout(layout)
    
    return fig

def create_radar_chart(categories, values, title=""):
    """Create a radar chart with neon styling"""
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        line=dict(color='#ff00bf', width=2),
        fillcolor='rgba(255, 0, 191, 0.2)',
        marker=dict(
            color='#ff00bf',
            size=8,
            line=dict(color='white', width=2)
        ),
        hovertemplate='<b>%{theta}</b><br>Value: %{r}<extra></extra>'
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['polar'] = dict(
        bgcolor='rgba(20, 25, 47, 0.1)',
        radialaxis=dict(
            gridcolor='rgba(0, 255, 255, 0.1)',
            linecolor='rgba(0, 255, 255, 0.2)',
            range=[0, max(values) * 1.2]
        ),
        angularaxis=dict(
            gridcolor='rgba(191, 0, 255, 0.1)',
            linecolor='rgba(191, 0, 255, 0.2)'
        )
    )
    layout['height'] = 400
    
    fig.update_layout(layout)
    
    return fig

def create_heatmap(data, x_labels, y_labels, title=""):
    """Create a heatmap with futuristic color scheme"""
    fig = go.Figure(data=go.Heatmap(
        z=data,
        x=x_labels,
        y=y_labels,
        colorscale=[[0, '#0a0e27'], [0.25, '#00ffff'], [0.5, '#bf00ff'], 
                    [0.75, '#ff00bf'], [1, '#ffff00']],
        hovertemplate='<b>%{y} - %{x}</b><br>Value: %{z}<extra></extra>',
        colorbar=dict(
            bgcolor='rgba(20, 25, 47, 0.7)',
            bordercolor='#00ffff',
            borderwidth=1,
            tickfont=dict(color='#b8bcc8')
        )
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['height'] = 400
    
    fig.update_layout(layout)
    
    return fig

def create_gauge_chart(value, max_value, title=""):
    """Create a gauge chart with neon styling"""
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = value,
        domain = {'x': [0, 1], 'y': [0, 1]},
        delta = {'reference': max_value * 0.5},
        gauge = {
            'axis': {'range': [None, max_value], 'tickcolor': "#b8bcc8"},
            'bar': {'color': "#ff00bf"},
            'bgcolor': "rgba(20, 25, 47, 0.3)",
            'borderwidth': 2,
            'bordercolor': "#00ffff",
            'steps': [
                {'range': [0, max_value * 0.25], 'color': 'rgba(0, 255, 255, 0.2)'},
                {'range': [max_value * 0.25, max_value * 0.5], 'color': 'rgba(191, 0, 255, 0.2)'},
                {'range': [max_value * 0.5, max_value * 0.75], 'color': 'rgba(255, 0, 191, 0.2)'},
                {'range': [max_value * 0.75, max_value], 'color': 'rgba(255, 255, 0, 0.2)'}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': max_value * 0.9
            }
        }
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['height'] = 300
    
    fig.update_layout(layout)
    
    return fig

def create_animated_bar_chart(df, x_col, y_col, title="", color_sequence=None):
    """Create an animated bar chart with gradient colors"""
    if color_sequence is None:
        color_sequence = get_neon_color_palette()
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=df[x_col],
        y=df[y_col],
        marker=dict(
            color=df[y_col],
            colorscale=[[0, '#00ffff'], [0.5, '#bf00ff'], [1, '#ff00bf']],
            line=dict(color='rgba(255, 255, 255, 0.3)', width=1)
        ),
        hovertemplate='<b>%{x}</b><br>Value: %{y}<extra></extra>',
        text=df[y_col],
        textposition='outside',
        textfont=dict(color='#00ffff', size=12)
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['height'] = 400
    layout['showlegend'] = False
    
    fig.update_layout(layout)
    
    return fig

def create_donut_chart(labels, values, title=""):
    """Create a donut chart with neon colors"""
    colors = get_neon_color_palette()[:len(labels)]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(
            colors=colors,
            line=dict(color='#0a0e27', width=2)
        ),
        textinfo='label+percent',
        textfont=dict(color='#ffffff', size=12),
        hovertemplate='<b>%{label}</b><br>Value: %{value}<br>Percent: %{percent}<extra></extra>'
    )])
    
    # Add center text
    fig.add_annotation(
        text=title,
        x=0.5, y=0.5,
        font=dict(size=16, color='#00ffff', family="Orbitron, monospace"),
        showarrow=False
    )
    
    layout = get_futuristic_plot_layout()
    layout['showlegend'] = True
    layout['height'] = 400
    
    fig.update_layout(layout)
    
    return fig

def create_treemap(labels, parents, values, title=""):
    """Create a treemap with futuristic styling"""
    fig = go.Figure(go.Treemap(
        labels=labels,
        parents=parents,
        values=values,
        marker=dict(
            colorscale=[[0, '#0a0e27'], [0.33, '#00ffff'], 
                       [0.66, '#bf00ff'], [1, '#ff00bf']],
            line=dict(color='#0a0e27', width=2)
        ),
        textfont=dict(color='#ffffff', size=14, family="Orbitron, monospace"),
        hovertemplate='<b>%{label}</b><br>Value: %{value}<extra></extra>'
    ))
    
    layout = get_futuristic_plot_layout()
    layout['title'] = title
    layout['height'] = 500
    
    fig.update_layout(layout)
    
    return fig

def create_loading_animation():
    """Display a futuristic loading animation"""
    loading_html = """
    <div style="display: flex; justify-content: center; align-items: center; height: 200px;">
        <div style="width: 60px; height: 60px; border: 3px solid rgba(0, 255, 255, 0.1);
                    border-top: 3px solid #00ffff; border-radius: 50%;
                    animation: spin 1s linear infinite;">
        </div>
    </div>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
    """
    st.markdown(loading_html, unsafe_allow_html=True)

def create_alert_box(message, alert_type="info"):
    """Create a futuristic alert box"""
    colors = {
        "info": ("#00ffff", "rgba(0, 255, 255, 0.1)"),
        "warning": ("#ff7f00", "rgba(255, 127, 0, 0.1)"),
        "error": ("#ff0000", "rgba(255, 0, 0, 0.1)"),
        "success": ("#00ff00", "rgba(0, 255, 0, 0.1)")
    }
    
    color, bg_color = colors.get(alert_type, colors["info"])
    
    alert_html = f"""
    <div style="background: {bg_color}; border: 1px solid {color};
                border-radius: 10px; padding: 15px; margin: 10px 0;
                border-left: 4px solid {color};
                box-shadow: 0 0 15px {bg_color};">
        <p style="color: {color}; margin: 0; font-family: 'Orbitron', monospace;">
            {message}
        </p>
    </div>
    """
    st.markdown(alert_html, unsafe_allow_html=True)

def create_progress_bar(progress, label=""):
    """Create a futuristic progress bar"""
    progress = min(max(progress, 0), 100)  # Ensure progress is between 0 and 100
    
    progress_html = f"""
    <div style="margin: 20px 0;">
        {f'<p style="color: #b8bcc8; margin-bottom: 10px; font-family: Orbitron, monospace;">{label}</p>' if label else ''}
        <div style="background: rgba(20, 25, 47, 0.5); border: 1px solid rgba(0, 255, 255, 0.3);
                    border-radius: 20px; height: 30px; position: relative; overflow: hidden;">
            <div style="background: linear-gradient(90deg, #00ffff, #bf00ff, #ff00bf);
                        height: 100%; width: {progress}%; border-radius: 20px;
                        animation: pulse 2s ease-in-out infinite;
                        box-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
                        transition: width 0.5s ease;">
            </div>
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                        color: #ffffff; font-weight: bold; font-family: 'Orbitron', monospace;">
                {progress}%
            </div>
        </div>
    </div>
    <style>
        @keyframes pulse {{
            0%, 100% {{ opacity: 0.8; }}
            50% {{ opacity: 1; }}
        }}
    </style>
    """
    st.markdown(progress_html, unsafe_allow_html=True)

def create_data_table(df, max_rows=10):
    """Create a futuristic styled data table"""
    # Convert dataframe to HTML
    table_html = df.head(max_rows).to_html(index=False, escape=False)
    
    # Apply futuristic styling
    styled_table = f"""
    <div style="overflow-x: auto; margin: 20px 0;">
        <style>
            .futuristic-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                background: rgba(20, 25, 47, 0.7);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);
            }}
            .futuristic-table thead {{
                background: rgba(0, 255, 255, 0.1);
            }}
            .futuristic-table th {{
                padding: 12px;
                text-align: left;
                color: #00ffff;
                font-family: 'Orbitron', monospace;
                text-transform: uppercase;
                letter-spacing: 1px;
                border-bottom: 2px solid rgba(0, 255, 255, 0.3);
            }}
            .futuristic-table td {{
                padding: 10px;
                color: #b8bcc8;
                border-bottom: 1px solid rgba(191, 0, 255, 0.1);
                font-family: monospace;
            }}
            .futuristic-table tr:hover {{
                background: rgba(191, 0, 255, 0.1);
                transition: background 0.3s ease;
            }}
            .futuristic-table tr:last-child td {{
                border-bottom: none;
            }}
        </style>
        {table_html.replace('<table', '<table class="futuristic-table"')}
    </div>
    """
    st.markdown(styled_table, unsafe_allow_html=True)

def create_sidebar_nav(options):
    """Create a futuristic sidebar navigation"""
    nav_html = """
    <style>
        .nav-link {
            display: block;
            padding: 12px 20px;
            margin: 5px 0;
            background: rgba(20, 25, 47, 0.7);
            border: 1px solid rgba(0, 255, 255, 0.3);
            border-radius: 10px;
            color: #b8bcc8;
            text-decoration: none;
            transition: all 0.3s ease;
            font-family: 'Orbitron', monospace;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .nav-link:hover {
            background: rgba(0, 255, 255, 0.1);
            border-color: #00ffff;
            color: #00ffff;
            transform: translateX(5px);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.3);
        }
        .nav-link.active {
            background: linear-gradient(45deg, rgba(0, 255, 255, 0.2), rgba(191, 0, 255, 0.2));
            border-color: #bf00ff;
            color: #bf00ff;
        }
    </style>
    """
    
    st.sidebar.markdown(nav_html, unsafe_allow_html=True)
    
    selected = None
    for option in options:
        if st.sidebar.button(option, key=f"nav_{option}"):
            selected = option
    
    return selected

def create_kpi_dashboard(kpis):
    """Create a KPI dashboard with futuristic cards
    
    Args:
        kpis: List of dictionaries with keys: 'title', 'value', 'delta', 'icon'
    """
    cols = st.columns(len(kpis))
    
    for idx, (col, kpi) in enumerate(zip(cols, kpis)):
        with col:
            icon = kpi.get('icon', '📊')
            delta = kpi.get('delta', None)
            delta_color = 'success' if delta and delta > 0 else 'error' if delta and delta < 0 else 'normal'
            
            kpi_html = f"""
            <div style="background: linear-gradient(135deg, rgba(20, 25, 47, 0.9), rgba(40, 45, 67, 0.7));
                        border: 1px solid rgba(0, 255, 255, 0.3);
                        border-radius: 15px; padding: 20px; text-align: center;
                        min-height: 180px; position: relative; overflow: hidden;
                        transition: all 0.3s ease; cursor: pointer;"
                 onmouseover="this.style.transform='translateY(-10px) scale(1.02)'; this.style.borderColor='#00ffff'; this.style.boxShadow='0 20px 40px rgba(0, 255, 255, 0.4)';"
                 onmouseout="this.style.transform='translateY(0) scale(1)'; this.style.borderColor='rgba(0, 255, 255, 0.3)'; this.style.boxShadow='none';">
                
                <!-- Background animation -->
                <div style="position: absolute; top: -50%; right: -50%; width: 200%; height: 200%;
                            background: radial-gradient(circle, rgba(191, 0, 255, 0.1) 0%, transparent 70%);
                            animation: rotate 10s linear infinite;">
                </div>
                
                <!-- Content -->
                <div style="position: relative; z-index: 1;">
                    <div style="font-size: 2em; margin-bottom: 10px;">{icon}</div>
                    <div style="color: #b8bcc8; font-size: 0.9em; text-transform: uppercase;
                                letter-spacing: 1px; margin-bottom: 10px; font-family: 'Orbitron', monospace;">
                        {kpi['title']}
                    </div>
                    <div style="font-size: 2.5em; font-weight: bold; font-family: 'Orbitron', monospace;
                                background: linear-gradient(45deg, #00ffff, #ff00bf);
                                -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                        {kpi['value']}
                    </div>
            """
            
            if delta is not None:
                arrow = "↑" if delta > 0 else "↓" if delta < 0 else "→"
                color = "#00ff00" if delta > 0 else "#ff0000" if delta < 0 else "#ffff00"
                kpi_html += f"""
                    <div style="color: {color}; margin-top: 10px; font-size: 1.1em;
                                font-family: 'Orbitron', monospace;">
                        {arrow} {abs(delta)}%
                    </div>
                """
            
            kpi_html += """
                </div>
            </div>
            <style>
                @keyframes rotate {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
            </style>
            """
            
            st.markdown(kpi_html, unsafe_allow_html=True)

def create_timeline(events):
    """Create a futuristic timeline
    
    Args:
        events: List of dictionaries with keys: 'date', 'title', 'description'
    """
    timeline_html = """
    <div style="position: relative; padding: 20px;">
        <div style="position: absolute; left: 50%; top: 0; bottom: 0;
                    width: 2px; background: linear-gradient(180deg, #00ffff, #bf00ff, #ff00bf);
                    box-shadow: 0 0 10px rgba(0, 255, 255, 0.5);">
        </div>
    """
    
    for idx, event in enumerate(events):
        side = "left" if idx % 2 == 0 else "right"
        margin = "0 55% 30px 0" if side == "left" else "0 0 30px 55%"
        
        timeline_html += f"""
        <div style="margin: {margin}; position: relative;">
            <div style="background: rgba(20, 25, 47, 0.8); border: 1px solid rgba(0, 255, 255, 0.3);
                        border-radius: 10px; padding: 15px; transition: all 0.3s ease;"
                 onmouseover="this.style.transform='scale(1.05)'; this.style.borderColor='#00ffff'; this.style.boxShadow='0 0 20px rgba(0, 255, 255, 0.4)';"
                 onmouseout="this.style.transform='scale(1)'; this.style.borderColor='rgba(0, 255, 255, 0.3)'; this.style.boxShadow='none';">
                <div style="color: #00ffff; font-weight: bold; margin-bottom: 5px;
                            font-family: 'Orbitron', monospace;">
                    {event['date']}
                </div>
                <div style="color: #bf00ff; font-weight: bold; margin-bottom: 5px;
                            font-family: 'Orbitron', monospace; text-transform: uppercase;">
                    {event['title']}
                </div>
                <div style="color: #b8bcc8; font-size: 0.9em;">
                    {event['description']}
                </div>
            </div>
            <div style="position: absolute; {'right' if side == 'left' else 'left'}: -8px;
                        top: 20px; width: 12px; height: 12px;
                        background: radial-gradient(circle, #ff00bf, #bf00ff);
                        border: 2px solid #00ffff; border-radius: 50%;
                        box-shadow: 0 0 10px rgba(255, 0, 191, 0.5);">
            </div>
        </div>
        """
    
    timeline_html += "</div>"
    st.markdown(timeline_html, unsafe_allow_html=True)

def create_glowing_button(label, key=None):
    """Create a glowing button with futuristic styling"""
    button_html = f"""
    <button style="background: linear-gradient(45deg, #00ffff, #bf00ff);
                   color: white; border: none; border-radius: 25px;
                   padding: 12px 30px; font-size: 16px; font-weight: bold;
                   font-family: 'Orbitron', monospace; text-transform: uppercase;
                   letter-spacing: 2px; cursor: pointer; position: relative;
                   overflow: hidden; transition: all 0.3s ease;
                   box-shadow: 0 4px 15px rgba(0, 255, 255, 0.4);"
            onmouseover="this.style.transform='translateY(-3px)'; this.style.boxShadow='0 6px 25px rgba(191, 0, 255, 0.5)';"
            onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px rgba(0, 255, 255, 0.4)';">
        <span style="position: relative; z-index: 1;">{label}</span>
        <div style="position: absolute; top: -50%; left: -50%; width: 200%; height: 200%;
                    background: radial-gradient(circle, rgba(255, 255, 255, 0.3) 0%, transparent 70%);
                    animation: shimmer 3s infinite;">
        </div>
    </button>
    <style>
        @keyframes shimmer {{
            0% {{ transform: rotate(0deg); opacity: 0; }}
            50% {{ opacity: 1; }}
            100% {{ transform: rotate(360deg); opacity: 0; }}
        }}
    </style>
    """
    
    if st.markdown(button_html, unsafe_allow_html=True):
        return True
    return False
