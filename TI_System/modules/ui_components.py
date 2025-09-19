<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/plotly.js/2.26.0/plotly.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/date-fns/2.30.0/index.min.js"></script>
    <style>
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
            --shadow-dark: 0 8px 32px rgba(0, 0, 0, 0.4);
            --shadow-glow: 0 0 20px rgba(0, 212, 255, 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, var(--primary-bg) 0%, #0f1419 100%);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }

        .dashboard-container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header */
        .header {
            background: rgba(26, 29, 35, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow-dark);
        }

        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-color), #00a8cc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .time-selector {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .refresh-btn {
            background: linear-gradient(135deg, var(--accent-color), #00a8cc);
            border: none;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }

        /* Executive Summary */
        .executive-summary {
            background: linear-gradient(135deg, var(--secondary-bg), var(--tertiary-bg));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-dark);
        }

        .summary-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--accent-color);
        }

        .summary-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }

        .metric-card {
            background: rgba(42, 45, 53, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-color), var(--success-color));
        }

        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-glow);
        }

        .metric-value {
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--accent-color);
            margin-bottom: 0.5rem;
        }

        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Filters */
        .filters-container {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-dark);
        }

        .filters-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--accent-color);
        }

        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .filter-label {
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .filter-select {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.75rem;
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .multi-select {
            min-height: 120px;
        }

        /* Charts Container */
        .charts-container {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .chart-section {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-dark);
        }

        .chart-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .chart-icon {
            width: 20px;
            height: 20px;
            background: var(--accent-color);
            border-radius: 4px;
        }

        /* Globe and Bar Charts */
        .charts-row {
            display: grid;
            grid-template-columns: 1fr 1.5fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }

        /* Trends Chart */
        .trends-container {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-dark);
        }

        /* Heatmap */
        .heatmap-container {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-dark);
        }

        /* Loading States */
        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 200px;
            color: var(--text-secondary);
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
            .header-content {
                flex-direction: column;
                gap: 1rem;
            }

            .main-content {
                padding: 1rem;
            }

            .charts-row {
                grid-template-columns: 1fr;
            }

            .filters-grid {
                grid-template-columns: 1fr;
            }

            .summary-content {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 480px) {
            .summary-content {
                grid-template-columns: 1fr;
            }

            .header {
                padding: 1rem;
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

        ::-webkit-scrollbar-thumb:hover {
            background: #00a8cc;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <header class="header">
            <div class="header-content">
                <div class="logo">🛡️ Threat Intelligence Dashboard</div>
                <div class="header-controls">
                    <select class="time-selector" id="timeRange">
                        <option value="7">Last 7 Days</option>
                        <option value="14">Last 14 Days</option>
                        <option value="30">Last 30 Days</option>
                        <option value="90">Last 90 Days</option>
                    </select>
                    <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
                </div>
            </div>
        </header>

        <main class="main-content">
            <!-- Executive Summary -->
            <section class="executive-summary">
                <h2 class="summary-title">📊 Executive Summary</h2>
                <p id="summaryText">Loading threat intelligence summary...</p>
                <div class="summary-content">
                    <div class="metric-card">
                        <div class="metric-value" id="totalThreats">0</div>
                        <div class="metric-label">Total Threats</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="uniqueCountries">0</div>
                        <div class="metric-label">Affected Countries</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="attackTechniques">0</div>
                        <div class="metric-label">Attack Techniques</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="humanTargeted">0</div>
                        <div class="metric-label">Human-Targeted</div>
                    </div>
                </div>
            </section>

            <!-- Filters -->
            <section class="filters-container">
                <h3 class="filters-title">🔍 Filters</h3>
                <div class="filters-grid">
                    <div class="filter-group">
                        <label class="filter-label">Countries</label>
                        <select class="filter-select multi-select" id="countryFilter" multiple>
                            <option value="">All Countries</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">Attack Techniques</label>
                        <select class="filter-select multi-select" id="techniqueFilter" multiple>
                            <option value="">All Techniques</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">Threat Type</label>
                        <select class="filter-select" id="threatTypeFilter">
                            <option value="all">All Threats</option>
                            <option value="human">Human-Targeted</option>
                            <option value="general">General Attacks</option>
                        </select>
                    </div>
                </div>
            </section>

            <!-- Charts Row -->
            <div class="charts-row">
                <section class="chart-section">
                    <h3 class="chart-title">
                        <div class="chart-icon"></div>
                        🌍 Global Threat Distribution
                    </h3>
                    <div id="globeChart"></div>
                </section>

                <section class="chart-section">
                    <h3 class="chart-title">
                        <div class="chart-icon"></div>
                        📊 Top Attack Techniques
                    </h3>
                    <div id="techniqueChart"></div>
                </section>
            </div>

            <!-- Trends Chart -->
            <section class="trends-container">
                <h3 class="chart-title">
                    <div class="chart-icon"></div>
                    📈 Threat Trends Over Time
                </h3>
                <div id="trendsChart"></div>
            </section>

            <!-- Countries Chart -->
            <section class="chart-section">
                <h3 class="chart-title">
                    <div class="chart-icon"></div>
                    🏳️ Countries by Threat Volume
                </h3>
                <div id="countryChart"></div>
            </section>

            <!-- Heatmap -->
            <section class="heatmap-container">
                <h3 class="chart-title">
                    <div class="chart-icon"></div>
                    🔥 Techniques vs Countries Heatmap
                </h3>
                <div id="heatmapChart"></div>
            </section>
        </main>
    </div>

    <script>
        // Global variables
        let currentData = null;
        let filteredData = null;
        let isLoading = false;

        // Sample data structure (replace with actual API calls)
        const sampleData = {
            threats: [
                {
                    id: 1,
                    title: "APT28 Phishing Campaign Targets Government Officials",
                    country: "United States",
                    technique: "Phishing (T1566.002)",
                    date: "2025-01-15",
                    severity: "high",
                    humanTargeted: true,
                    threatActor: "APT28"
                },
                {
                    id: 2,
                    title: "Ransomware Attack on Healthcare Infrastructure",
                    country: "Germany", 
                    technique: "Data Encrypted for Impact (T1486)",
                    date: "2025-01-14",
                    severity: "critical",
                    humanTargeted: false,
                    threatActor: "LockBit"
                },
                {
                    id: 3,
                    title: "Social Engineering Campaign Targets Financial Sector",
                    country: "United Kingdom",
                    technique: "Social Engineering (T1566)",
                    date: "2025-01-13",
                    severity: "medium",
                    humanTargeted: true,
                    threatActor: "Unknown"
                },
                {
                    id: 4,
                    title: "Supply Chain Compromise in Software Updates",
                    country: "Japan",
                    technique: "Supply Chain Compromise (T1195)",
                    date: "2025-01-12",
                    severity: "high",
                    humanTargeted: false,
                    threatActor: "APT41"
                },
                {
                    id: 5,
                    title: "Credential Dumping via Mimikatz",
                    country: "France",
                    technique: "Credential Dumping (T1003)",
                    date: "2025-01-11",
                    severity: "medium",
                    humanTargeted: true,
                    threatActor: "Lazarus Group"
                }
            ],
            countries: ["United States", "Germany", "United Kingdom", "Japan", "France", "China", "Russia", "Brazil"],
            techniques: [
                "Phishing (T1566.002)",
                "Data Encrypted for Impact (T1486)", 
                "Social Engineering (T1566)",
                "Supply Chain Compromise (T1195)",
                "Credential Dumping (T1003)",
                "Brute Force (T1110)",
                "Command Line Interface (T1059.003)"
            ]
        };

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeDashboard();
        });

        function initializeDashboard() {
            currentData = sampleData;
            filteredData = currentData;
            
            populateFilters();
            updateExecutiveSummary();
            createCharts();
            setupEventListeners();
        }

        function populateFilters() {
            // Populate country filter
            const countryFilter = document.getElementById('countryFilter');
            currentData.countries.forEach(country => {
                const option = document.createElement('option');
                option.value = country;
                option.textContent = country;
                countryFilter.appendChild(option);
            });

            // Populate technique filter
            const techniqueFilter = document.getElementById('techniqueFilter');
            currentData.techniques.forEach(technique => {
                const option = document.createElement('option');
                option.value = technique;
                option.textContent = technique;
                techniqueFilter.appendChild(option);
            });
        }

        function updateExecutiveSummary() {
            const data = filteredData.threats;
            
            // Calculate metrics
            const totalThreats = data.length;
            const uniqueCountries = [...new Set(data.map(t => t.country))].length;
            const attackTechniques = [...new Set(data.map(t => t.technique))].length;
            const humanTargeted = data.filter(t => t.humanTargeted).length;

            // Update DOM
            document.getElementById('totalThreats').textContent = totalThreats;
            document.getElementById('uniqueCountries').textContent = uniqueCountries;
            document.getElementById('attackTechniques').textContent = attackTechniques;
            document.getElementById('humanTargeted').textContent = humanTargeted;

            // Generate summary text
            const timeRange = document.getElementById('timeRange').value;
            const summaryText = `Over the past ${timeRange} days, our threat intelligence system detected ${totalThreats} security incidents across ${uniqueCountries} countries. ${humanTargeted} incidents (${Math.round(humanTargeted/totalThreats*100)}%) were specifically targeting human assets through social engineering and phishing campaigns. The most prevalent attack techniques included data encryption for impact and credential access methods.`;
            
            document.getElementById('summaryText').textContent = summaryText;
        }

        function createCharts() {
            createGlobeChart();
            createTechniqueChart();
            createTrendsChart();
            createCountryChart();
            createHeatmapChart();
        }

        function createGlobeChart() {
            const data = filteredData.threats;
            const countryCounts = {};
            
            data.forEach(threat => {
                countryCounts[threat.country] = (countryCounts[threat.country] || 0) + 1;
            });

            const countries = Object.keys(countryCounts);
            const values = Object.values(countryCounts);

            const trace = {
                type: 'choropleth',
                locations: countries,
                z: values,
                locationmode: 'country names',
                colorscale: [
                    [0, '#1a1d23'],
                    [0.2, '#2a2d35'],
                    [0.4, '#3a3d45'],
                    [0.6, '#00a8cc'],
                    [0.8, '#00d4ff'],
                    [1, '#00ff88']
                ],
                colorbar: {
                    title: 'Threat Count',
                    titlefont: { color: '#ffffff' },
                    tickfont: { color: '#b0b3b8' },
                    bgcolor: 'rgba(42, 45, 53, 0.8)',
                    bordercolor: '#3a3d45'
                },
                hovertemplate: '<b>%{locations}</b><br>Threats: %{z}<extra></extra>'
            };

            const layout = {
                title: {
                    text: '',
                    font: { color: '#ffffff' }
                },
                geo: {
                    projection: { type: 'orthographic' },
                    showcoastlines: true,
                    coastlinecolor: '#00d4ff',
                    showland: true,
                    landcolor: '#1a1d23',
                    showocean: true,
                    oceancolor: '#0a0b0f',
                    showframe: false,
                    bgcolor: '#0a0b0f'
                },
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: { color: '#ffffff' },
                margin: { t: 20, b: 20, l: 20, r: 20 },
                height: 400
            };

            Plotly.newPlot('globeChart', [trace], layout, { responsive: true, displayModeBar: false });
        }

        function createTechniqueChart() {
            const data = filteredData.threats;
            const techniqueCounts = {};
            
            data.forEach(threat => {
                techniqueCounts[threat.technique] = (techniqueCounts[threat.technique] || 0) + 1;
            });

            const techniques = Object.keys(techniqueCounts).slice(0, 10);
            const values = Object.values(techniqueCounts).slice(0, 10);

            const trace = {
                type: 'bar',
                y: techniques,
                x: values,
                orientation: 'h',
                marker: {
                    color: values.map((_, i) => `rgba(0, 212, 255, ${0.8 - i * 0.1})`),
                    line: { color: '#00d4ff', width: 1 }
                },
                hovertemplate: '<b>%{y}</b><br>Count: %{x}<extra></extra>'
            };

            const layout = {
                title: {
                    text: '',
                    font: { color: '#ffffff' }
                },
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: { color: '#ffffff' },
                margin: { t: 20, b: 40, l: 200, r: 20 },
                height: 400,
                xaxis: {
                    gridcolor: '#3a3d45',
                    zerolinecolor: '#3a3d45',
                    color: '#b0b3b8'
                },
                yaxis: {
                    gridcolor: '#3a3d45',
                    color: '#b0b3b8'
                }
            };

            Plotly.newPlot('techniqueChart', [trace], layout, { responsive: true, displayModeBar: false });
        }

        function createTrendsChart() {
            const data = filteredData.threats;
            const timeRange = parseInt(document.getElementById('timeRange').value);
            
            // Group data by date and technique
            const trendsData = {};
            const dates = [];
            
            for (let i = timeRange - 1; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                const dateStr = date.toISOString().split('T')[0];
                dates.push(dateStr);
                trendsData[dateStr] = {};
            }

            // Fill with sample data
            data.forEach(threat => {
                if (trendsData[threat.date]) {
                    if (!trendsData[threat.date][threat.technique]) {
                        trendsData[threat.date][threat.technique] = 0;
                    }
                    trendsData[threat.date][threat.technique]++;
                }
            });

            // Get top techniques
            const topTechniques = [...new Set(data.map(t => t.technique))].slice(0, 5);
            
            const traces = topTechniques.map((technique, index) => ({
                type: 'scatter',
                mode: 'lines+markers',
                name: technique.split('(')[0].trim(),
                x: dates,
                y: dates.map(date => trendsData[date][technique] || 0),
                line: {
                    color: `hsl(${index * 60}, 70%, 60%)`,
                    width: 3
                },
                marker: {
                    size: 6,
                    color: `hsl(${index * 60}, 70%, 60%)`
                }
            }));

            const layout = {
                title: {
                    text: '',
                    font: { color: '#ffffff' }
                },
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: { color: '#ffffff' },
                margin: { t: 20, b: 40, l: 40, r: 20 },
                height: 400,
                xaxis: {
                    gridcolor: '#3a3d45',
                    zerolinecolor: '#3a3d45',
                    color: '#b0b3b8'
                },
                yaxis: {
                    gridcolor: '#3a3d45',
                    zerolinecolor: '#3a3d45',
                    color: '#b0b3b8'
                },
                legend: {
                    font: { color: '#ffffff' },
                    bgcolor: 'rgba(42, 45, 53, 0.8)',
                    bordercolor: '#3a3d45'
                }
            };

            Plotly.newPlot('trendsChart', traces, layout, { responsive: true, displayModeBar: false });
        }

        function createCountryChart() {
            const data = filteredData.threats;
            const countryCounts = {};
            
            data.forEach(threat => {
                countryCounts[threat.country] = (countryCounts[threat.country] || 0) + 1;
            });

            const countries = Object.keys(countryCounts);
            const values = Object.values(countryCounts);

            const trace = {
                type: 'bar',
                x: countries,
                y: values,
                marker: {
                    color: values.map(v => `rgba(0, 212, 255, ${0.4 + (v / Math.max(...values)) * 0.6})`),
                    line: { color: '#00d4ff', width: 1 }
                },
                hovertemplate: '<b>%{x}</b><br>Threats: %{y}<extra></extra>'
            };

            const layout = {
                title: {
                    text: '',
                    font: { color: '#ffffff' }
                },
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(0,0,0,0)',
                font: { color: '#ffffff' },
                margin: { t: 20, b: 80, l: 40, r: 20 },
                height: 400,
                xaxis: {
                    gridcolor: '#3a3d45',
                    zerolinecolor: '#3a3d45',
                    color: '#b0b3b8',
                    tickangle: -45
                },
                yaxis: {
                    gridcolor: '#3a3d45',
                    zerolinecolor: '#3a3d45',
                    color: '#b0b3b8'
                }
            };

            Plotly.newPlot('countryChart', [trace], layout, { responsive: true, displayModeBar: false });
        }

        function createHeatmapChart() {
            const data = filteredData.threats;
            const countries = [...new Set(data.map(t => t.country))];
            const techniques = [...new Set(data.map(t => t.technique))];
            
            // Create matrix
            const matrix = techniques.map(technique => 
                countries.map(country => {
                    const count = data.filter(t => t.country === country && t.technique === technique).length;
                    return count;
                })
            );

            const trace = {
                type: 'heatmap',
                z: matrix,
                x: countries,
                y: techniques.map(t => t.split('(')[0].trim()),
                colorscale: [
                    [0, '#1a1d23'],
                    [0.2, '#2a2d35'],
                    [0.4, '#3a3d45'],
                    [0.6, '#00a8cc'],
                    [0.8, '#00d4ff'],
                    [1, '#00ff88']
