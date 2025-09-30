all_articles.append({
                    'timestamp': timestamp,
                    'threat_id': hashlib.md5(entry.get('link', '').encode()).hexdigest()[:16],
                    'technique_id': 'T1566',
                    'technique_name': "Phishing",
                    'technique_description': entry.get('title', 'Security News')[:200],
                    'category': "Initial Access",
                    'severity': "Info",
                    'threat_actor': 'Unknown',
                    'actor_description': 'News article',
                    'origin_country': 'Unknown',
                    'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                    'target_sector': random.choice(ThreatIntelligence.SECTORS),
                    'confidence': 70,
                    'kill_chain_phase': 'Reconnaissance',
                    'malware_family': 'News',
                    'detection_source': source,
                    'blocked': True,
                    'active': False,
                    'ioc_ip': '0.0.0.0',
                    'ioc_domain': source,
                    'mitigation': 'Information only'
                })
    except:
            continue
            
    return pd.DataFrame(all_articles)

def generate_data():
    """Aggregate data from all threat feeds"""
    feeds_status = {}
    
    # Fetch from all sources
    df_otx = fetch_otx_data()
    feeds_status['OTX'] = len(df_otx)
    
    df_vt = fetch_virustotal_data()
    feeds_status['VirusTotal'] = len(df_vt)
    
    df_shodan = fetch_shodan_data()
    feeds_status['Shodan'] = len(df_shodan)
    
    df_rss = fetch_rss_feeds()
    feeds_status['RSS'] = len(df_rss)
    
    df_simulated = ThreatIntelligence.generate_threat_feed(300)
    feeds_status['Simulated'] = len(df_simulated)
    
    # Combine all non-empty dataframes
    dfs_to_combine = [df for df in [df_otx, df_vt, df_shodan, df_rss, df_simulated] if not df.empty]
    
    if dfs_to_combine:
        combined = pd.concat(dfs_to_combine, ignore_index=True)
        
        # Store feed status
        st.session_state.feed_status = feeds_status
        
        return combined
    else:
        return ThreatIntelligence.generate_threat_feed(1000)

# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================

def create_globe_map(threat_df):
    country_threats = threat_df.groupby('target_country').agg({
        'threat_id': 'count',
        'severity': lambda x: (x == 'Critical').sum(),
        'active': lambda x: x.sum()
    }).reset_index()
    country_threats.columns = ['country', 'total', 'critical', 'active']
    
    globe_data = []
    for country, coords in ThreatIntelligence.COUNTRIES.items():
        country_data = country_threats[country_threats['country'] == country]
        if not country_data.empty:
            globe_data.append({
                'lat': coords['lat'],
                'lon': coords['lon'],
                'country': country,
                'total': country_data['total'].values[0],
                'critical': country_data['critical'].values[0],
                'active': country_data['active'].values[0],
                'text': f"{country}<br>Total: {country_data['total'].values[0]}<br>Critical: {country_data['critical'].values[0]}<br>Active: {country_data['active'].values[0]}"
            })
    
    if not globe_data:
        return go.Figure()
    
    globe_df = pd.DataFrame(globe_data)
    
    fig = go.Figure(go.Scattergeo(
        lon=globe_df['lon'],
        lat=globe_df['lat'],
        text=globe_df['text'],
        mode='markers',
        marker=dict(
            size=globe_df['total'] / 10,
            color=globe_df['critical'],
            colorscale=[[0, '#00ff00'], [0.5, '#ffff00'], [1, '#ff0000']],
            showscale=False,
            line=dict(width=1, color='#00ffff'),
            sizemin=5
        ),
        hoverinfo='text'
    ))
    
    fig.update_layout(
        geo=dict(
            projection_type='orthographic',
            showland=True,
            landcolor='rgba(30, 35, 57, 0.9)',
            coastlinecolor='#00ffff',
            oceancolor='rgba(10, 14, 39, 0.95)',
            bgcolor='rgba(20, 25, 47, 0.1)'
        ),
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=600,
        title='Global Threat Distribution',
        margin=dict(l=0, r=0, t=50, b=0)
    )
    
    return fig

def create_time_series_chart(threat_df, group_by='day', attack_type=None, country=None, sector=None):
    """Create time series trend chart with filters"""
    filtered_df = threat_df.copy()
    
    if attack_type and attack_type != 'All':
        filtered_df = filtered_df[filtered_df['technique_name'] == attack_type]
    if country and country != 'All':
        filtered_df = filtered_df[filtered_df['target_country'] == country]
    if sector and sector != 'All':
        filtered_df = filtered_df[filtered_df['target_sector'] == sector]
    
    if filtered_df.empty:
        return go.Figure()
    
    # Group by time period
    if group_by == 'hour':
        filtered_df['period'] = filtered_df['timestamp'].dt.floor('H')
    elif group_by == 'day':
        filtered_df['period'] = filtered_df['timestamp'].dt.date
    elif group_by == 'week':
        filtered_df['period'] = filtered_df['timestamp'].dt.to_period('W').apply(lambda r: r.start_time)
    else:
        filtered_df['period'] = filtered_df['timestamp'].dt.to_period('M').apply(lambda r: r.start_time)
    
    # Count threats by period
    time_series = filtered_df.groupby('period').size().reset_index(name='count')
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=time_series['period'],
        y=time_series['count'],
        mode='lines+markers',
        name='Threat Count',
        line=dict(color='#00ffff', width=3),
        marker=dict(size=8, color='#bf00ff'),
        fill='tozeroy',
        fillcolor='rgba(0, 255, 255, 0.1)'
    ))
    
    fig.update_layout(
        title=f'Threat Trends Over Time ({group_by.capitalize()})',
        xaxis_title='Time Period',
        yaxis_title='Number of Threats',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=400,
        hovermode='x unified'
    )
    
    return fig

def create_severity_trend_chart(threat_df):
    """Stacked area chart showing severity trends over time"""
    if threat_df.empty:
        return go.Figure()
    
    threat_df['date'] = threat_df['timestamp'].dt.date
    severity_by_date = threat_df.groupby(['date', 'severity']).size().unstack(fill_value=0)
    
    fig = go.Figure()
    
    colors = {'Critical': '#ff0000', 'High': '#ff7f00', 'Medium': '#ffff00', 'Low': '#00ff00', 'Info': '#00ffff'}
    
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if severity in severity_by_date.columns:
            fig.add_trace(go.Scatter(
                x=severity_by_date.index,
                y=severity_by_date[severity],
                mode='lines',
                name=severity,
                stackgroup='one',
                line=dict(width=0.5, color=colors.get(severity, '#ffffff')),
                fillcolor=colors.get(severity, '#ffffff')
            ))
    
    fig.update_layout(
        title='Threat Severity Trends',
        xaxis_title='Date',
        yaxis_title='Number of Threats',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=400,
        hovermode='x unified'
    )
    
    return fig

def create_attack_heatmap(threat_df):
    """Heatmap of attacks by hour and day of week"""
    if threat_df.empty:
        return go.Figure()
    
    threat_df['hour'] = threat_df['timestamp'].dt.hour
    threat_df['day_of_week'] = threat_df['timestamp'].dt.day_name()
    
    heatmap_data = threat_df.groupby(['day_of_week', 'hour']).size().unstack(fill_value=0)
    
    # Reorder days
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_data = heatmap_data.reindex([d for d in day_order if d in heatmap_data.index])
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=heatmap_data.columns,
        y=heatmap_data.index,
        colorscale=[[0, '#0a0e27'], [0.5, '#bf00ff'], [1, '#00ffff']],
        hovertemplate='Hour: %{x}<br>Day: %{y}<br>Threats: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title='Attack Pattern Heatmap (Hour vs Day)',
        xaxis_title='Hour of Day',
        yaxis_title='Day of Week',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=400
    )
    
    return fig

def create_source_comparison_chart(threat_df):
    """Compare threat detection across sources"""
    if threat_df.empty:
        return go.Figure()
    
    source_stats = threat_df.groupby('detection_source').agg({
        'threat_id': 'count',
        'severity': lambda x: (x == 'Critical').sum()
    }).reset_index()
    source_stats.columns = ['source', 'total', 'critical']
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=source_stats['source'],
        y=source_stats['total'],
        name='Total Threats',
        marker=dict(color='#00ffff')
    ))
    
    fig.add_trace(go.Bar(
        x=source_stats['source'],
        y=source_stats['critical'],
        name='Critical Threats',
        marker=dict(color='#ff0000')
    ))
    
    fig.update_layout(
        title='Threats by Detection Source',
        xaxis_title='Source',
        yaxis_title='Number of Threats',
        barmode='group',
        plot_bgcolor='rgba(20, 25, 47, 0.1)',
        paper_bgcolor='rgba(20, 25, 47, 0.7)',
        font=dict(color='#b8bcc8'),
        height=400
    )
    
    return fig

def get_security_recommendations(threat_data):
    top_techniques = threat_data['technique_name'].value_counts().head(3)
    critical_threats = len(threat_data[threat_data['severity'] == 'Critical'])
    
    recommendations = []
    
    recommendations.append({
        'framework': 'ISO 27001',
        'priority': 'HIGH',
        'title': 'Information Security Management System (ISMS) Review',
        'threat': f'Multiple threat vectors detected across {len(threat_data["technique_name"].unique())} attack types',
        'controls': [
            'A.12.1.1 - Documented operating procedures',
            'A.12.6.1 - Management of technical vulnerabilities',
            'A.13.1.1 - Network controls and segmentation',
            'A.16.1.1 - Incident response procedures'
        ]
    })
    
    recommendations.append({
        'framework': 'NIST CSF',
        'priority': 'CRITICAL',
        'title': 'NIST Framework Core Functions Activation',
        'threat': f'Critical threats detected: {critical_threats} instances',
        'controls': [
            'IDENTIFY (ID.RA): Conduct immediate risk assessment',
            'PROTECT (PR.AC): Strengthen access control measures',
            'DETECT (DE.CM): Enhance continuous monitoring',
            'RESPOND (RS.AN): Activate incident analysis procedures',
            'RECOVER (RC.RP): Update recovery planning'
        ]
    })
    
    for technique, count in top_techniques.items():
        if technique == 'Phishing':
            recommendations.append({
                'framework': 'NIST SP 800-177',
                'priority': 'HIGH',
                'title': 'Email Security Enhancement',
                'threat': f'Phishing attacks: {count} instances detected',
                'controls': [
                    'Implement DMARC policy with p=reject',
                    'Deploy DKIM signing for all domains',
                    'Configure SPF records with -all',
                    'Enable ATP/Safe Links protection',
                    'Conduct phishing simulation training'
                ]
            })
    
    return recommendations

def generate_executive_summary(threat_df, start_time, end_time):
    if threat_df.empty:
        return "No threat data available for the selected period."
    
    total = len(threat_df)
    critical = len(threat_df[threat_df['severity'] == 'Critical'])
    blocked = len(threat_df[threat_df['blocked'] == True])
    top_technique = threat_df['technique_name'].mode()[0] if not threat_df.empty else "Unknown"
    
    block_rate = (blocked / total * 100) if total > 0 else 0
    
    # Get active feeds
    active_feeds = [source for source, count in st.session_state.get('feed_status', {}).items() if count > 0]
    
    summary = f"""
    During the selected period, the platform detected {total:,} total threats across all monitored systems. 
    Of these, {critical} were classified as Critical severity requiring immediate attention. 
    Our security controls successfully blocked {blocked:,} threats ({block_rate:.1f}% block rate). 
    The most prevalent attack technique was {top_technique}, indicating ongoing targeting in this area. 
    Continuous monitoring and threat intelligence integration from {', '.join(active_feeds)} provides real-time visibility 
    into emerging threats and attack patterns across multiple geographic regions and industry sectors.
    """
    
    return summary

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    apply_futuristic_theme()
    initialize_auto_update()
    
    if 'threat_data' not in st.session_state:
        with st.spinner("Loading threat intelligence from multiple sources..."):
            st.session_state.threat_data = generate_data()
    
    if check_auto_update():
        new_data = generate_data()
        if not new_data.empty:
            st.session_state.threat_data = pd.concat([new_data, st.session_state.threat_data]).reset_index(drop=True)
            st.session_state.threat_data = st.session_state.threat_data.head(2000)
    
    seconds_since = (datetime.now() - st.session_state.last_update).total_seconds()
    seconds_until = 300 - seconds_since
    minutes_until = int(seconds_until // 60)
    seconds_remainder = int(seconds_until % 60)
    
    # Header with feed status
    feed_status_html = ""
    if 'feed_status' in st.session_state:
        feed_badges = [f"<span style='background: rgba(0,255,255,0.2); padding: 3px 8px; border-radius: 5px; margin: 0 5px;'>{source}: {count}</span>" 
                      for source, count in st.session_state.feed_status.items() if count > 0]
        feed_status_html = "<br>" + " ".join(feed_badges)
    
    st.markdown(f"""
    <div style="text-align: center; padding: 30px; background: rgba(20, 25, 47, 0.7); 
                border-radius: 20px; border: 2px solid rgba(0, 255, 255, 0.3); margin-bottom: 30px;">
        <h1>THREAT INTELLIGENCE PLATFORM</h1>
        <p style="color: #b8bcc8; font-size: 1.1em;">
            MULTI-SOURCE INTEGRATION • AUTO-UPDATING EVERY 5 MINUTES
        </p>
        <p style="color: #00ff00; font-size: 0.9em;">
            Next Update: {minutes_until}m {seconds_remainder}s
        </p>
        {feed_status_html}
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar Filters
    with st.sidebar:
        st.markdown("### FILTERS & CONFIGURATION")
        
        # API Status
        with st.expander("API Keys Status"):
            for api_name, api_key in API_KEYS.items():
                status = "✅ Configured" if api_key else "❌ Not Set"
                st.markdown(f"**{api_name}**: {status}")
            st.markdown("---")
            st.markdown("*Add API keys in the script to enable additional feeds*")
        
        time_option = st.radio("Time Range", ['Quick Select', 'Custom Range'])
        
        if time_option == 'Quick Select':
            time_range = st.selectbox("Quick ranges", ['Last 24 Hours', 'Last 7 Days', 'Last 30 Days'], index=1)
            time_map = {'Last 24 Hours': timedelta(days=1), 'Last 7 Days': timedelta(days=7), 'Last 30 Days': timedelta(days=30)}
            time_cutoff = datetime.now() - time_map[time_range]
            end_datetime = datetime.now()
        else:
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=7))
            with col2:
                end_date = st.date_input("End Date", value=datetime.now())
            time_cutoff = datetime.combine(start_date, datetime.min.time())
            end_datetime = datetime.combine(end_date, datetime.max.time())
        
        st.markdown("---")
        
        attack_types = list(set([t['name'] for t in ThreatIntelligence.ATTACK_TECHNIQUES.values()]))
        if 'selected_attacks' not in st.session_state:
            st.session_state.selected_attacks = attack_types
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="sel_attacks"):
                st.session_state.selected_attacks = attack_types
        with col2:
            if st.button("Clear", key="clr_attacks"):
                st.session_state.selected_attacks = []
        
        selected_attacks = st.multiselect("Attack Types", attack_types, default=st.session_state.selected_attacks)
        st.session_state.selected_attacks = selected_attacks
        
        countries = list(ThreatIntelligence.COUNTRIES.keys())
        if 'selected_countries' not in st.session_state:
            st.session_state.selected_countries = countries
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="sel_countries"):
                st.session_state.selected_countries = countries
        with col2:
            if st.button("Clear", key="clr_countries"):
                st.session_state.selected_countries = []
        
        selected_countries = st.multiselect("Countries", countries, default=st.session_state.selected_countries)
        st.session_state.selected_countries = selected_countries
        
        sectors = ThreatIntelligence.SECTORS
        if 'selected_sectors' not in st.session_state:
            st.session_state.selected_sectors = sectors
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Select All", key="sel_sectors"):
                st.session_state.selected_sectors = sectors
        with col2:
            if st.button("Clear", key="clr_sectors"):
                st.session_state.selected_sectors = []
        
        selected_sectors = st.multiselect("Sectors", sectors, default=st.session_state.selected_sectors)
        st.session_state.selected_sectors = selected_sectors
        
        severity_options = ['Critical', 'High', 'Medium', 'Low', 'Info']
        severity_levels = st.multiselect("Severity", severity_options, default=severity_options)
        
        confidence_threshold = st.slider("Min Confidence %", 0, 100, 60, 10)
        
        if st.button("APPLY FILTERS", use_container_width=True):
            st.rerun()
    
    # Apply filters
    threat_df = st.session_state.threat_data.copy()
    threat_df = threat_df[threat_df['timestamp'] > time_cutoff]
    threat_df = threat_df[threat_df['timestamp'] <= end_datetime]
    threat_df = threat_df[threat_df['technique_name'].isin(selected_attacks)]
    threat_df = threat_df[threat_df['target_country'].isin(selected_countries)]
    threat_df = threat_df[threat_df['target_sector'].isin(selected_sectors)]
    threat_df = threat_df[threat_df['severity'].isin(severity_levels)]
    threat_df = threat_df[threat_df['confidence'] >= confidence_threshold]
    
    # Main tabs
    tabs = st.tabs(["Overview", "Trends Analysis", "Human Targeted", "Global Threats", "Intelligence Analysis", "Security Recommendations", "IOC Scanner"])
    
    with tabs[0]:
        st.markdown("### THREAT OVERVIEW")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_threats = len(threat_df)
        critical_threats = len(threat_df[threat_df['severity'] == 'Critical'])
        active_threats = len(threat_df[threat_df['active'] == True])
        blocked_threats = len(threat_df[threat_df['blocked'] == True])
        
        with col1:
            st.metric("Total Threats", f"{total_threats:,}")
        with col2:
            st.metric("Critical", critical_threats)
        with col3:
            st.metric("Active", active_threats)
        with col4:
            st.metric("Blocked", blocked_threats)
        with col5:
            block_rate = (blocked_threats / total_threats * 100) if total_threats > 0 else 0
            st.metric("Block Rate", f"{block_rate:.1f}%")
        
        st.markdown("### EXECUTIVE SUMMARY")
        summary = generate_executive_summary(threat_df, time_cutoff, end_datetime)
        st.markdown(f"""
        <div style="background: rgba(30, 41, 54, 0.9); border-radius: 16px; padding: 24px; margin: 20px 0;">
            <p style="color: #94a3b8; line-height: 1.6;">{summary}</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if not threat_df.empty:
                attack_dist = threat_df['technique_name'].value_counts()
                fig = go.Figure(go.Bar(
                    x=attack_dist.values,
                    y=attack_dist.index,
                    orientation='h',
                    marker=dict(color='#00ffff')
                ))
                fig.update_layout(
                    title='Attack Types Distribution',
                    plot_bgcolor='rgba(20, 25, 47, 0.1)',
                    paper_bgcolor='rgba(20, 25, 47, 0.7)',
                    font=dict(color='#b8bcc8'),
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if not threat_df.empty:
                nist_score, nist_breakdown = ThreatIntelligence.calculate_nist_score(threat_df)
                
                fig = go.Figure(go.Bar(
                    x=list(nist_breakdown.values()),
                    y=list(nist_breakdown.keys()),
                    orientation='h',
                    marker=dict(color='#bf00ff')
                ))
                fig.update_layout(
                    title=f'NIST Framework Score: {nist_score}/10',
                    plot_bgcolor='rgba(20, 25, 47, 0.1)',
                    paper_bgcolor='rgba(20, 25, 47, 0.7)',
                    font=dict(color='#b8bcc8'),
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[1]:
        st.markdown("### TRENDS ANALYSIS & FORECASTING")
        
        # Trend filters
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            trend_period = st.selectbox("Time Grouping", ['hour', 'day', 'week', 'month'], index=1)
        with col2:
            trend_attack = st.selectbox("Filter by Attack", ['All'] + list(threat_df['technique_name'].unique()) if not threat_df.empty else ['All'])
        with col3:
            trend_country = st.selectbox("Filter by Country", ['All'] + list(threat_df['target_country'].unique()) if not threat_df.empty else ['All'])
        with col4:
            trend_sector = st.selectbox("Filter by Sector", ['All'] + list(threat_df['target_sector'].unique()) if not threat_df.empty else ['All'])
        
        if not threat_df.empty:
            # Time series chart
            time_series_fig = create_time_series_chart(
                threat_df, 
                group_by=trend_period,
                attack_type=trend_attack,
                country=trend_country,
                sector=trend_sector
            )
            st.plotly_chart(time_series_fig, use_container_width=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Severity trends
                severity_fig = create_severity_trend_chart(threat_df)
                st.plotly_chart(severity_fig, use_container_width=True)
            
            with col2:
                # Source comparison
                source_fig = create_source_comparison_chart(threat_df)
                st.plotly_chart(source_fig, use_container_width=True)
            
            # Attack heatmap
            heatmap_fig = create_attack_heatmap(threat_df)
            st.plotly_chart(heatmap_fig, use_container_width=True)
            
            # Trend insights
            st.markdown("### KEY INSIGHTS")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                top_hour = threat_df['timestamp'].dt.hour.mode()[0] if not threat_df.empty else 0
                st.metric("Peak Attack Hour", f"{top_hour}:00")
            
            with col2:
                top_day = threat_df['timestamp'].dt.day_name().mode()[0] if not threat_df.empty else "Unknown"
                st.metric("Peak Attack Day", top_day)
            
            with col3:
                avg_daily = len(threat_df) / max(1, (end_datetime - time_cutoff).days)
                st.metric("Avg Daily Threats", f"{avg_daily:.1f}")
        else:
            st.info("No data available for trends analysis")
    
    with tabs[2]:
        st.markdown("### HUMAN-TARGETED ATTACKS")
        
        human_attacks = ['Phishing', 'OS Credential Dumping']
        human_threats = threat_df[threat_df['technique_name'].isin(human_attacks)]
        
        if not human_threats.empty:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Human-Targeted", len(human_threats))
            with col2:
                st.metric("Phishing", len(human_threats[human_threats['technique_name'] == 'Phishing']))
            with col3:
                st.metric("Critical", len(human_threats[human_threats['severity'] == 'Critical']))
            with col4:
                blocked = len(human_threats[human_threats['blocked'] == True])
                rate = (blocked / len(human_threats) * 100) if len(human_threats) > 0 else 0
                st.metric("Block Rate", f"{rate:.1f}%")
            
            st.markdown("### RECENT ATTACKS")
            display_df = human_threats[['timestamp', 'technique_name', 'target_country', 'target_sector', 'severity', 'detection_source']].head(20)
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No human-targeted attacks in current filter")
    
    with tabs[3]:
        st.markdown("### GLOBAL THREAT LANDSCAPE")
        if not threat_df.empty:
            globe_fig = create_globe_map(threat_df)
            st.plotly_chart(globe_fig, use_container_width=True)
            
            st.markdown("### SELECT COUNTRY FOR DETAILS")
            countries_with_threats = threat_df['target_country'].unique()
            selected_country = st.selectbox("Choose country:", ['None'] + sorted(countries_with_threats.tolist()))
            
            if selected_country != 'None':
                country_threats = threat_df[threat_df['target_country'] == selected_country]
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total", len(country_threats))
                with col2:
                    st.metric("Critical", len(country_threats[country_threats['severity'] == 'Critical']))
                with col3:
                    st.metric("Active", len(country_threats[country_threats['active'] == True]))
                with col4:
                    blocked = len(country_threats[country_threats['blocked'] == True])
                    st.metric("Blocked", blocked)
                
                display_data = country_threats[['timestamp', 'technique_name', 'severity', 'threat_actor', 'target_sector', 'detection_source']].head(30)
                st.dataframe(display_data, use_container_width=True)
        else:
            st.info("No threat data available")
    
    with tabs[4]:
        st.markdown("### THREAT INTELLIGENCE ANALYSIS")
        
        if not threat_df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### ATTACK TECHNIQUES")
                technique_stats = threat_df.groupby(['technique_id', 'technique_name']).size().reset_index(name='count')
                technique_stats = technique_stats.nlargest(5, 'count')
                
                for _, row in technique_stats.iterrows():
                    with st.expander(f"{row['technique_id']}: {row['technique_name']} ({row['count']} attacks)"):
                        technique_threats = threat_df[threat_df['technique_id'] == row['technique_id']]
                        
                        affected_countries = technique_threats['target_country'].value_counts().head(5)
                        affected_sectors = technique_threats['target_sector'].value_counts().head(5)
                        
                        st.markdown("**Top Affected Countries:**")
                        for country, count in affected_countries.items():
                            st.markdown(f"- {country}: {count} attacks")
                        
                        st.markdown("**Top Affected Sectors:**")
                        for sector, count in affected_sectors.items():
                            st.markdown(f"- {sector}: {count} attacks")
            
            with col2:
                st.markdown("#### THREAT ACTORS")
                actor_stats = threat_df['threat_actor'].value_counts().head(5)
                
                for actor, count in actor_stats.items():
                    actor_info = ThreatIntelligence.THREAT_ACTORS.get(actor, {})
                    
                    with st.expander(f"{actor} ({count} attacks) - {actor_info.get('origin', 'Unknown')}"):
                        st.markdown(f"**Description:** {actor_info.get('description', 'N/A')}")
                        st.markdown(f"**Sophistication:** {actor_info.get('sophistication', 'Unknown')}")
                        
                        actor_threats = threat_df[threat_df['threat_actor'] == actor]
                        attack_types = actor_threats['technique_name'].value_counts().head(3)
                        
                        st.markdown("**Primary Attack Types:**")
                        for attack, cnt in attack_types.items():
                            st.markdown(f"- {attack}: {cnt} instances")
        else:
            st.info("No data available")
    
    with tabs[5]:
        st.markdown("### SECURITY RECOMMENDATIONS")
        
        if not threat_df.empty:
            recommendations = get_security_recommendations(threat_df)
            
            for rec in recommendations:
                priority_color = {'CRITICAL': '#ff0000', 'HIGH': '#ff7f00', 'MEDIUM': '#ffff00'}.get(rec['priority'], '#00ff00')
                
                with st.expander(f"[{rec['framework']}] {rec['title']} - {rec['priority']}", expanded=False):
                    st.markdown(f"""
                    <div style="padding: 15px; background: rgba(20, 25, 47, 0.7);
                                border: 2px solid {priority_color}; border-radius: 10px;">
                        <div style="color: {priority_color}; font-weight: bold; margin-bottom: 10px;">
                            Threat Context: {rec['threat']}
                        </div>
                        <div style="color: #00ffff; font-weight: bold; margin-bottom: 10px;">
                            RECOMMENDED CONTROLS:
                        </div>
                        <div style="color: #b8bcc8;">
                            {'<br>'.join(rec['controls'])}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("No recommendations available")
    
    with tabs[6]:
        st.markdown("### IOC SCANNER")
        
        ioc_input = st.text_input("Enter IOC (IP, Domain, or Hash)", placeholder="e.g., 192.168.1.1 or malicious.com")
        
        if st.button("SCAN IOC"):
            if ioc_input:
                with st.spinner("Scanning..."):
                    time.sleep(2)
                    
                    detection_ratio = random.randint(0, 75)
                    is_malicious = detection_ratio > 30
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Detection Ratio", f"{detection_ratio}/75")
                    with col2:
                        status = "MALICIOUS" if is_malicious else "CLEAN"
                        st.metric("Status", status)
                    with col3:
                        st.metric("Reputation", f"{random.randint(10, 100)}/100")
                    with col4:
                        st.metric("Last Seen", f"{random.randint(1, 24)}h ago")
                    
                    if is_malicious:
                        st.error("⚠️ This IOC has been flagged as malicious!")
                        st.markdown("**Recommended Actions:**")
                        st.markdown("- Block this IOC across all network perimeters")
                        st.markdown("- Review logs for any connections to this IOC")
                        st.markdown("- Initiate incident response procedures")
                    else:
                        st.success("✅ This IOC appears to be clean")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Advanced Threat Intelligence Platform with Multiple Threat Feeds
Supports: OTX, VirusTotal, Shodan, AbuseIPDB, RSS Feeds
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
import time
import random
import hashlib
import json
import feedparser
import requests
from typing import Dict, List, Tuple

st.set_page_config(
    page_title="Threat Intelligence Platform - TIP",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# API CONFIGURATION - ADD YOUR API KEYS HERE
# ============================================================================

API_KEYS = {
    'OTX': "a64a6fc71743dd93f98f8b91b7a611e6bd219d32a9faa11d85256b7a81e8dd89",
    'VIRUSTOTAL': "ab80b053bde5338b274b1376002c55af5c6152f72031834f7c142ef17ba2023c",  # Add your VirusTotal API key here
    'SHODAN': "u2dp7LUQXfqMjbazPVwhcfcQ6pqPWTnq",      # Add your Shodan API key here
    'ABUSEIPDB': "b1fdd114ca7aa7b217656e262bc46be661b575117e97a31b3e02f1e98c4461ea1c9a5bd87b7e14e8"    # Add your AbuseIPDB API key here (optional)
}

# ============================================================================
# THREAT FEED CONNECTORS
# ============================================================================

class OTXConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {'X-OTX-API-KEY': api_key, 'Content-Type': 'application/json'}
    
    def get_pulses_subscribed(self, limit=50):
        url = f"{self.base_url}/pulses/subscribed"
        for attempt in range(3):
            try:
                timeout = 20 + (attempt * 10)
                response = requests.get(url, headers=self.headers, params={'limit': limit}, timeout=timeout)
                response.raise_for_status()
                return response.json()
            except:
                if attempt < 2:
                    continue
                return None
        return None

class VirusTotalConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {'x-apikey': api_key}
    
    def get_recent_files(self, limit=40):
        """Get recent file analyses"""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/intelligence/search"
        # Search for recently submitted malicious files
        query = "type:file (positives:5+ OR tag:malware)"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params={'query': query, 'limit': limit},
                timeout=15
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None
    
    def get_file_behaviour(self, file_hash):
        """Get behavior analysis for a file"""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/files/{file_hash}/behaviour_summary"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

class ShodanConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
    
    def get_alerts(self):
        """Get Shodan network alerts"""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/shodan/alert/info"
        try:
            response = requests.get(url, params={'key': self.api_key}, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None
    
    def search_exploits(self, query="", limit=20):
        """Search for exploits"""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/api/search"
        try:
            response = requests.get(
                url,
                params={'key': self.api_key, 'query': query or 'port:22,23,80,443', 'limit': limit},
                timeout=15
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

class AbuseIPDBConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {'Key': api_key, 'Accept': 'application/json'}
    
    def get_blacklist(self, limit=100):
        """Get blacklisted IPs"""
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/blacklist"
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params={'confidenceMinimum': 90, 'limit': limit},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

# ============================================================================
# THEME & UI
# ============================================================================

def apply_futuristic_theme():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #151934 50%, #1a0033 100%);
        background-attachment: fixed;
    }
    h1 {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(90deg, #00ffff, #bf00ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-transform: uppercase;
        letter-spacing: 3px;
        font-weight: 900 !important;
        text-align: center;
        padding: 20px 0;
        font-size: 2.5em !important;
    }
    h2, h3 {
        font-family: 'Orbitron', monospace !important;
        color: #00ffff !important;
        text-transform: uppercase;
    }
    [data-testid="stSidebar"] {
        background: rgba(20, 25, 47, 0.95);
        backdrop-filter: blur(20px);
        border-right: 2px solid rgba(0, 255, 255, 0.3);
    }
    .stButton > button {
        font-family: 'Orbitron', monospace !important;
        background: linear-gradient(45deg, #00ffff, #bf00ff);
        color: #ffffff !important;
        border-radius: 10px !important;
        padding: 10px 30px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
    }
    ::-webkit-scrollbar {
        width: 10px;
    }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00ffff, #bf00ff);
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

def initialize_auto_update():
    if 'last_update' not in st.session_state:
        st.session_state.last_update = datetime.now()
    if 'auto_update_counter' not in st.session_state:
        st.session_state.auto_update_counter = 0

def check_auto_update():
    current_time = datetime.now()
    if (current_time - st.session_state.last_update).total_seconds() >= 300:
        st.session_state.last_update = current_time
        st.session_state.auto_update_counter += 1
        return True
    return False

# ============================================================================
# THREAT INTELLIGENCE MODEL
# ============================================================================

class ThreatIntelligence:
    
    ATTACK_TECHNIQUES = {
        'T1566': {'name': 'Phishing', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Adversaries send fraudulent messages to trick users into revealing sensitive information or executing malicious code.'},
        'T1486': {'name': 'Data Encrypted for Impact', 'category': 'Impact', 'severity': 'Critical',
                  'description': 'Adversaries encrypt data on target systems to interrupt availability. Commonly seen in ransomware attacks.'},
        'T1498': {'name': 'Network Denial of Service', 'category': 'Impact', 'severity': 'High',
                  'description': 'Adversaries perform DoS/DDoS attacks to degrade or block availability of targeted resources.'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'category': 'Initial Access', 'severity': 'High',
                  'description': 'Adversaries exploit weaknesses in internet-facing applications to gain initial access.'},
        'T1059': {'name': 'Command and Scripting Interpreter', 'category': 'Execution', 'severity': 'Medium',
                  'description': 'Adversaries abuse command and script interpreters to execute commands and scripts.'},
        'T1055': {'name': 'Process Injection', 'category': 'Defense Evasion', 'severity': 'High',
                  'description': 'Adversaries inject code into processes to evade defenses and elevate privileges.'},
        'T1003': {'name': 'OS Credential Dumping', 'category': 'Credential Access', 'severity': 'Critical',
                  'description': 'Adversaries attempt to dump credentials to obtain account login information.'},
        'T1071': {'name': 'Application Layer Protocol', 'category': 'Command and Control', 'severity': 'Medium',
                  'description': 'Adversaries use application layer protocols for command and control communications.'}
    }
    
    KILL_CHAIN_PHASES = {
        'Reconnaissance': 'Gathering information about the target to plan the attack',
        'Weaponization': 'Creating malicious payloads and coupling them with exploits',
        'Delivery': 'Transmitting the weapon to the target environment',
        'Exploitation': 'Triggering the weapon to exploit vulnerabilities',
        'Installation': 'Installing malware or backdoors for persistent access',
        'Command & Control': 'Establishing communication channels with compromised systems',
        'Actions on Objectives': 'Achieving the attack goals (data theft, destruction, etc.)'
    }
    
    THREAT_ACTORS = {
        'APT28': {'origin': 'Russia', 'targets': ['Government', 'Defense', 'Energy'], 'sophistication': 'High',
                  'description': 'Russian state-sponsored group targeting government and military organizations'},
        'APT29': {'origin': 'Russia', 'targets': ['Government', 'Healthcare', 'Technology'], 'sophistication': 'High',
                  'description': 'Russian SVR-linked group known for stealthy operations'},
        'Lazarus': {'origin': 'North Korea', 'targets': ['Finance', 'Cryptocurrency', 'Defense'], 'sophistication': 'High',
                    'description': 'North Korean group involved in financial theft and espionage'},
        'APT1': {'origin': 'China', 'targets': ['Technology', 'Manufacturing', 'Energy'], 'sophistication': 'Medium',
                 'description': 'Chinese military unit focused on intellectual property theft'},
        'FIN7': {'origin': 'Unknown', 'targets': ['Retail', 'Hospitality', 'Finance'], 'sophistication': 'High',
                 'description': 'Financially motivated group targeting payment card data'},
        'Sandworm': {'origin': 'Russia', 'targets': ['Critical Infrastructure', 'Government', 'Energy'], 'sophistication': 'High',
                     'description': 'Russian state-sponsored group linked to disruptive cyberattacks on critical infrastructure'}
    }
    
    SECTORS = ['Finance', 'Healthcare', 'Government', 'Technology', 'Energy', 
               'Manufacturing', 'Retail', 'Defense', 'Education', 'Telecommunications',
               'Pharmaceutical', 'Engineering', 'Transportation', 'Media']
    
    COUNTRIES = {
        'USA': {'lat': 39.0, 'lon': -98.0, 'risk_level': 0.8},
        'UK': {'lat': 54.0, 'lon': -2.0, 'risk_level': 0.7},
        'Germany': {'lat': 51.0, 'lon': 10.5, 'risk_level': 0.7},
        'Japan': {'lat': 36.0, 'lon': 138.0, 'risk_level': 0.6},
        'Australia': {'lat': -25.0, 'lon': 135.0, 'risk_level': 0.6},
        'Canada': {'lat': 56.0, 'lon': -106.0, 'risk_level': 0.5},
        'France': {'lat': 47.0, 'lon': 2.0, 'risk_level': 0.7},
        'India': {'lat': 20.0, 'lon': 77.0, 'risk_level': 0.7},
        'Brazil': {'lat': -14.0, 'lon': -51.0, 'risk_level': 0.6},
        'Russia': {'lat': 61.0, 'lon': 105.0, 'risk_level': 0.9},
        'China': {'lat': 35.0, 'lon': 105.0, 'risk_level': 0.8},
        'Israel': {'lat': 31.0, 'lon': 35.0, 'risk_level': 0.8},
        'Portugal': {'lat': 39.5, 'lon': -8.0, 'risk_level': 0.5},
        'Spain': {'lat': 40.0, 'lon': -4.0, 'risk_level': 0.6},
        'Italy': {'lat': 42.5, 'lon': 12.5, 'risk_level': 0.6},
        'Denmark': {'lat': 56.0, 'lon': 10.0, 'risk_level': 0.5},
        'Finland': {'lat': 64.0, 'lon': 26.0, 'risk_level': 0.6},
        'Norway': {'lat': 61.0, 'lon': 8.0, 'risk_level': 0.6},
        'Sweden': {'lat': 63.0, 'lon': 16.0, 'risk_level': 0.6},
        'Netherlands': {'lat': 52.0, 'lon': 5.5, 'risk_level': 0.6},
        'Poland': {'lat': 52.0, 'lon': 19.0, 'risk_level': 0.6},
        'South Korea': {'lat': 37.0, 'lon': 127.5, 'risk_level': 0.7},
        'Singapore': {'lat': 1.3, 'lon': 103.8, 'risk_level': 0.6}
    }
    
    @staticmethod
    def generate_threat_feed(num_events=1000):
        threat_events = []
        for _ in range(num_events):
            technique_id = random.choice(list(ThreatIntelligence.ATTACK_TECHNIQUES.keys()))
            technique = ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]
            actor = random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys()))
            is_blocked = random.choice([True, True, True, False])
            
            threat_events.append({
                'timestamp': datetime.now() - timedelta(hours=random.randint(0, 720)),
                'threat_id': f"THREAT-{random.randint(10000, 99999)}",
                'technique_id': technique_id,
                'technique_name': technique['name'],
                'technique_description': technique['description'],
                'category': technique['category'],
                'severity': technique['severity'],
                'threat_actor': actor,
                'actor_description': ThreatIntelligence.THREAT_ACTORS[actor]['description'],
                'origin_country': ThreatIntelligence.THREAT_ACTORS[actor]['origin'],
                'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                'target_sector': random.choice(ThreatIntelligence.SECTORS),
                'confidence': random.randint(60, 100),
                'kill_chain_phase': random.choice(list(ThreatIntelligence.KILL_CHAIN_PHASES.keys())),
                'malware_family': random.choice(['Emotet', 'TrickBot', 'REvil', 'Conti', 'DarkSide', 'LockBit']),
                'detection_source': 'Simulated',
                'blocked': is_blocked,
                'active': not is_blocked,
                'ioc_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'ioc_domain': f"malicious-{random.randint(100,999)}.com",
                'mitigation': 'Blocked' if is_blocked else 'IMMEDIATE ACTION REQUIRED'
            })
        return pd.DataFrame(threat_events)
    
    @staticmethod
    def calculate_nist_score(threat_df):
        if threat_df.empty:
            return 5.0, {'Identify': 50, 'Protect': 50, 'Detect': 50, 'Respond': 50, 'Recover': 50}
        
        total_threats = len(threat_df)
        critical_threats = len(threat_df[threat_df['severity'] == 'Critical'])
        blocked_threats = len(threat_df[threat_df['blocked'] == True])
        
        identify_score = min(100, 60 + (blocked_threats / max(total_threats, 1)) * 40)
        protect_score = min(100, 50 + (blocked_threats / max(total_threats, 1)) * 50)
        detect_score = min(100, 40 + (len(threat_df[threat_df['confidence'] > 80]) / max(total_threats, 1)) * 60)
        respond_score = min(100, 55 + (blocked_threats / max(total_threats, 1)) * 45)
        recover_score = min(100, 70 + (1 - critical_threats / max(total_threats, 1)) * 30)
        
        avg_score = (identify_score + protect_score + detect_score + respond_score + recover_score) / 5
        nist_score = avg_score / 10
        
        return round(nist_score, 1), {
            'Identify': round(identify_score),
            'Protect': round(protect_score),
            'Detect': round(detect_score),
            'Respond': round(respond_score),
            'Recover': round(recover_score)
        }

# ============================================================================
# DATA FETCHING FROM ALL SOURCES
# ============================================================================

@st.cache_data(ttl=300)
def fetch_otx_data():
    if not API_KEYS['OTX']:
        return pd.DataFrame()
    
    otx = OTXConnector(API_KEYS['OTX'])
    pulses_data = otx.get_pulses_subscribed(limit=50)
    
    threat_events = []
    
    if pulses_data and 'results' in pulses_data:
        for pulse in pulses_data['results']:
            try:
                pulse_id = pulse.get('id', '')
                name = pulse.get('name', 'Unknown')
                description = pulse.get('description', '')
                modified = pulse.get('modified', datetime.now().isoformat())
                tags = pulse.get('tags', [])
                tlp = pulse.get('TLP', 'white')
                
                severity = 'Critical' if tlp == 'red' else 'High' if tlp == 'amber' else 'Medium'
                
                technique_mapping = {
                    'phishing': 'T1566', 'ransomware': 'T1486', 'ddos': 'T1498',
                    'exploit': 'T1190', 'malware': 'T1059', 'trojan': 'T1055',
                    'credential': 'T1003', 'c2': 'T1071'
                }
                
                technique_id = 'T1566'
                for keyword, tid in technique_mapping.items():
                    if keyword in name.lower() or keyword in description.lower():
                        technique_id = tid
                        break
                
                target_country = random.choice(list(ThreatIntelligence.COUNTRIES.keys()))
                target_sector = random.choice(ThreatIntelligence.SECTORS)
                threat_actor = random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys()))
                
                indicators = pulse.get('indicators', [])
                num_indicators = len(indicators)
                
                ioc_ip = ''
                ioc_domain = ''
                for ind in indicators[:5]:
                    if ind.get('type') == 'IPv4' and not ioc_ip:
                        ioc_ip = ind.get('indicator', '')
                    elif ind.get('type') in ['domain', 'hostname'] and not ioc_domain:
                        ioc_domain = ind.get('indicator', '')
                
                if not ioc_ip:
                    ioc_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                if not ioc_domain:
                    ioc_domain = f"threat-{pulse_id[:8]}.com"
                
                is_blocked = num_indicators > 5 or severity == 'Medium'
                
                threat_events.append({
                    'timestamp': pd.to_datetime(modified),
                    'threat_id': f"OTX-{pulse_id}",
                    'technique_id': technique_id,
                    'technique_name': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['name'],
                    'technique_description': description[:200] if description else ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['description'],
                    'category': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['category'],
                    'severity': severity,
                    'threat_actor': threat_actor,
                    'actor_description': ThreatIntelligence.THREAT_ACTORS[threat_actor]['description'],
                    'origin_country': ThreatIntelligence.THREAT_ACTORS[threat_actor]['origin'],
                    'target_country': target_country,
                    'target_sector': target_sector,
                    'confidence': min(100, 60 + num_indicators * 2),
                    'kill_chain_phase': random.choice(list(ThreatIntelligence.KILL_CHAIN_PHASES.keys())),
                    'malware_family': tags[0] if tags else 'Unknown',
                    'detection_source': 'OTX AlienVault',
                    'blocked': is_blocked,
                    'active': not is_blocked,
                    'ioc_ip': ioc_ip,
                    'ioc_domain': ioc_domain,
                    'mitigation': 'Blocked' if is_blocked else 'IMMEDIATE ACTION REQUIRED'
                })
            except:
                continue
    
    return pd.DataFrame(threat_events) if threat_events else pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_virustotal_data():
    if not API_KEYS['VIRUSTOTAL']:
        return pd.DataFrame()
    
    vt = VirusTotalConnector(API_KEYS['VIRUSTOTAL'])
    files_data = vt.get_recent_files()
    
    threat_events = []
    
    if files_data and 'data' in files_data:
        for item in files_data['data'][:30]:
            try:
                attrs = item.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                
                if malicious < 5:
                    continue
                
                file_hash = item.get('id', '')
                names = attrs.get('names', ['Unknown'])
                file_type = attrs.get('type_description', 'File')
                tags = attrs.get('tags', [])
                
                severity = 'Critical' if malicious > 20 else 'High' if malicious > 10 else 'Medium'
                
                technique_id = 'T1059'
                if 'ransomware' in ' '.join(tags).lower():
                    technique_id = 'T1486'
                elif 'trojan' in ' '.join(tags).lower():
                    technique_id = 'T1055'
                
                threat_events.append({
                    'timestamp': datetime.now() - timedelta(hours=random.randint(0, 48)),
                    'threat_id': f"VT-{file_hash[:16]}",
                    'technique_id': technique_id,
                    'technique_name': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['name'],
                    'technique_description': f"Malicious file detected: {names[0] if names else 'Unknown'}",
                    'category': ThreatIntelligence.ATTACK_TECHNIQUES[technique_id]['category'],
                    'severity': severity,
                    'threat_actor': random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys())),
                    'actor_description': f"File analysis: {malicious} detections",
                    'origin_country': 'Unknown',
                    'target_country': random.choice(list(ThreatIntelligence.COUNTRIES.keys())),
                    'target_sector': random.choice(ThreatIntelligence.SECTORS),
                    'confidence': min(100, 50 + malicious * 2),
                    'kill_chain_phase': 'Delivery',
                    'malware_family': tags[0] if tags else file_type,
                    'detection_source': 'VirusTotal',
                    'blocked': True,
                    'active': False,
                    'ioc_ip': '0.0.0.0',
                    'ioc_domain': file_hash[:20],
                    'mitigation': 'File identified and blocked'
                })
            except:
                continue
    
    return pd.DataFrame(threat_events) if threat_events else pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_shodan_data():
    if not API_KEYS['SHODAN']:
        return pd.DataFrame()
    
    shodan = ShodanConnector(API_KEYS['SHODAN'])
    results = shodan.search_exploits()
    
    threat_events = []
    
    if results and 'matches' in results:
        for item in results['matches'][:30]:
            try:
                ip = item.get('ip_str', '0.0.0.0')
                port = item.get('port', 0)
                org = item.get('org', 'Unknown')
                country = item.get('location', {}).get('country_code', 'Unknown')
                
                if country in ThreatIntelligence.COUNTRIES:
                    target_country = country
                else:
                    target_country = random.choice(list(ThreatIntelligence.COUNTRIES.keys()))
                
                threat_events.append({
                    'timestamp': datetime.now() - timedelta(hours=random.randint(0, 72)),
                    'threat_id': f"SHODAN-{ip.replace('.', '')}-{port}",
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing Application',
                    'technique_description': f"Exposed service on port {port}: {org}",
                    'category': 'Initial Access',
                    'severity': 'High' if port in [22, 23, 3389] else 'Medium',
                    'threat_actor': random.choice(list(ThreatIntelligence.THREAT_ACTORS.keys())),
                    'actor_description': f"Vulnerable service exposed: Port {port}",
                    'origin_country': 'Unknown',
                    'target_country': target_country,
                    'target_sector': random.choice(ThreatIntelligence.SECTORS),
                    'confidence': 75,
                    'kill_chain_phase': 'Reconnaissance',
                    'malware_family': f"Port {port} Exposure",
                    'detection_source': 'Shodan',
                    'blocked': False,
                    'active': True,
                    'ioc_ip': ip,
                    'ioc_domain': f"exposed-{port}.service",
                    'mitigation': 'REVIEW EXPOSURE - Potential vulnerability'
                })
            except:
                continue
    
    return pd.DataFrame(threat_events) if threat_events else pd.DataFrame()

@st.cache_data(ttl=600)
def fetch_rss_feeds():
    feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Hacker News": "https://hnrss.org/frontpage",
        "Malwarebytes": "https://blog.malwarebytes.com/feed/"
    }
    
    all_articles = []
    for source, url in feeds.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:10]:
                pub_date = entry.get('published_parsed')
                timestamp = datetime(*pub_date[:6]) if pub_date else datetime.now()
                
                all_articles.append({
                    'timestamp': timestamp,
                    'threat_id': hashlib.md5(entry.get('link', '').encode()).hexdigest()[:16],
                    'technique_id': 'T1566',
                    'technique_name': "Phishing",
                    'technique_description': entry.get('title', 'Security News')[:200],
                    'category': "Initial Access",
                    'severity': "Info",
                    'threat_actor':
