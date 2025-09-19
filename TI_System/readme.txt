# Threat Intelligence Dashboard System

A comprehensive, modularized threat intelligence collection and analysis system with automated data gathering from multiple sources, SQLite storage, and interactive dashboard visualization.

## 🚀 Features

### Core Capabilities
- **Multi-source Intelligence Collection**: RSS feeds, OTX AlienVault API integration
- **Automated MITRE ATT&CK Mapping**: Automatic TTP classification
- **Country Detection**: Advanced country identification using multiple methods
- **SQLite Database Storage**: Persistent storage with optimized queries
- **Interactive Dashboard**: Real-time visualization with Streamlit
- **Human vs General Attack Classification**: Automatic categorization
- **Trend Analysis**: Historical data comparison and trending

### Data Sources
- 30+ cybersecurity RSS feeds
- AlienVault OTX threat intelligence
- MaxMind GeoIP for IP geolocation
- Custom threat actor detection

## 📦 Installation

### Prerequisites
- Python 3.8+
- Git
- MaxMind GeoLite2 database (optional)
- OTX API key (optional)

### Quick Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/threat-intelligence-system.git
cd threat-intelligence-system
```

2. **Run automated setup**
```bash
python setup.py
```

3. **Configure API keys**
Edit `config.yaml`:
```yaml
otx:
  api_key: "YOUR_OTX_API_KEY_HERE"
```

4. **Download GeoIP Database**
- Register at [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Download GeoLite2-Country.mmdb
- Place in project root directory

## 🏗️ Project Structure

```
threat-intelligence-system/
│
├── modules/                    # Core modules
│   ├── __init__.py
│   ├── config.py               # Configuration management
│   ├── data_fetcher.py         # Data fetching from GitHub
│   ├── data_processor.py       # Data processing and transformation
│   ├── ui_components.py        # UI visualization components
│   ├── dashboard_page.py       # Main dashboard page
│   ├── trends_page.py          # Trends analysis page
│   ├── about_page.py           # About page
│   ├── country_detector.py     # Country detection logic
│   ├── ttp_classifier.py       # TTP classification
│   ├── feed_manager.py         # RSS feed management
│   ├── otx_client.py           # OTX API client
│   ├── database_manager.py     # SQLite database operations
│   └── report_generator.py     # Report generation
│
├── main.py                      # Dashboard entry point
├── threat_intel_enhanced.py     # Enhanced threat intel engine
├── setup.py                     # Setup and initialization
├── run_collection.py           # Manual collection script
├── scheduler.py                # Automated scheduling
├── utils.py                    # Utility functions
├── config.yaml                 # Configuration file
├── requirements.txt            # Python dependencies
├── threat_intel.db            # SQLite database
└── README.md                  # This file
```

## 🎯 Usage

### Running the Dashboard

```bash
# Start the Streamlit dashboard
streamlit run main.py
```

The dashboard will be available at `http://localhost:8501`

### Manual Data Collection

```bash
# Run threat intelligence collection
python run_collection.py
```

### Automated Scheduling

```bash
# Start the scheduler for automated weekly collection
python scheduler.py
```

### Command Line Interface

```bash
# Setup the system
python setup.py

# Run collection
python -c "from threat_intel_enhanced import ThreatIntelligenceEngine; engine = ThreatIntelligenceEngine(); engine.run_collection()"

# Query database
python -c "from modules.database_manager import DatabaseManager; db = DatabaseManager(); print(db.get_human_targeted_articles())"
```

## 📊 Dashboard Features

### Main Dashboard Page
- **Report Selection**: Choose specific weekly reports
- **Country Filtering**: Filter by affected countries
- **Metrics Display**: TTPs count, sources count
- **Interactive Globe**: Visual country representation
- **MITRE Techniques Chart**: Top techniques visualization
- **Country Impact Chart**: Occurrences per country
- **Heatmap**: TTPs vs Countries matrix
- **Search & Export**: Full-text search with Excel export

### Trends Analysis
- **Multi-week Comparison**: Select multiple reports
- **Country-specific Trends**: Track specific country threats
- **TTP Evolution**: Monitor technique changes over time
- **Time-series Visualization**: Interactive trend charts

## 🗄️ Database Schema

### Articles Table
```sql
CREATE TABLE articles (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    title TEXT,
    published_date DATETIME,
    source TEXT,
    threat_actor TEXT,
    is_human_targeted BOOLEAN,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

### TTPs Table
```sql
CREATE TABLE ttps (
    id INTEGER PRIMARY KEY,
    article_id INTEGER,
    ttp TEXT,
    FOREIGN KEY (article_id) REFERENCES articles (id)
)
```

### Countries Table
```sql
CREATE TABLE countries (
    id INTEGER PRIMARY KEY,
    article_id INTEGER,
    country TEXT,
    FOREIGN KEY (article_id) REFERENCES articles (id)
)
```

## 🔧 Configuration

### config.yaml Structure

```yaml
database:
  path: "threat_intel.db"
  backup_enabled: true

otx:
  api_key: "YOUR_KEY"
  enabled: true
  pulse_limit: 100

collection:
  days_back: 7
  auto_run: false

feeds:
  rss_feeds:
    - "feed_url_1"
    - "feed_url_2"
```

### Environment Variables

```bash
export OTX_API_KEY="your_api_key"
export TI_DB_PATH="custom_db_path.db"
```

## 📈 API Usage

### Python API

```python
from threat_intel_enhanced import ThreatIntelligenceEngine

# Initialize engine
engine = ThreatIntelligenceEngine(
    otx_api_key="YOUR_KEY",
    db_path="threat_intel.db"
)

# Run collection
engine.run_collection(days_back=7)

# Query database
df = engine.query_database({
    'country': 'United States',
    'is_human_targeted': True,
    'start_date': datetime(2024, 1, 1)
})
```

### Database Queries

```python
from modules.database_manager import DatabaseManager

db = DatabaseManager()

# Get human-targeted attacks
human_attacks = db.get_human_targeted_articles()

# Get general attacks
general_attacks = db.get_general_articles()

# Custom query
results = db.query_articles(
    country="China",
    ttp="Phishing",
    start_date=datetime(2024, 1, 1)
)
```

## 🛠️ Advanced Features

### Custom Feed Sources

Add new RSS feeds to `config.yaml`:

```yaml
feeds:
  rss_feeds:
    - "https://your-feed-url.com/rss"
```

### Custom TTP Patterns

Modify `modules/ttp_classifier.py`:

```python
self.mappings = {
    r"\byour_pattern\b": ["Your TTP (T####)"],
    # Add more patterns
}
```

### Custom Country Detection

Update `modules/country_detector.py`:

```python
self.aliases = {
    "your_alias": "Country Name",
    # Add more aliases
}
```

## 🐛 Troubleshooting

### Common Issues

1. **Database Lock Error**
   ```bash
   # Close all connections and restart
   pkill -f streamlit
   python main.py
   ```

2. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **OTX API Errors**
   - Verify API key in config.yaml
   - Check API rate limits

4. **GeoIP Database Missing**
   - Download from MaxMind
   - Place in project root

## 📝 Development

### Running Tests

```bash
pytest tests/
pytest --cov=modules tests/
```

### Code Formatting

```bash
black modules/ *.py
flake8 modules/
```

### Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📊 Performance Optimization

### Database Optimization
- Indexes on frequently queried columns
- Batch inserts for large datasets
- Connection pooling for concurrent access

### Memory Management
- Chunk processing for large feeds
- Lazy loading of article content
- Efficient pandas operations

## 🔒 Security

### Best Practices
- Store API keys in environment variables
- Use HTTPS for all external requests
- Validate and sanitize user inputs
- Regular database backups
- Rate limiting for API calls

### Data Privacy
- No PII collection
- Local database storage
- Optional content truncation
- Configurable data retention

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [MaxMind GeoIP](https://www.maxmind.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)

## 📄 License

MIT License - See LICENSE file for details

## 👥 Credits

Created by Ricardo Mendes Pinto

## 🆘 Support

For issues, questions, or suggestions:
- Create an issue on GitHub
- Contact: [LinkedIn Profile](https://www.linkedin.com/in/ricardopinto110993/)

## 🚦 Status

- ✅ Core functionality
- ✅ Database integration
- ✅ OTX integration
- ✅ Dashboard visualization
- ✅ Automated scheduling
- 🔄 Machine learning enhancements (planned)
- 🔄 API endpoint development (planned)