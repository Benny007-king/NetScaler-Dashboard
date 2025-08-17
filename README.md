# NetScaler Enhanced Dashboard

A professional Flask web application that connects to real NetScaler appliances via NITRO API and displays live monitoring data with advanced failover tracking and user session monitoring.

## 🆕 New Features

### Failover Monitoring Dashboard
- **Real-time failover detection** - Automatic detection of HA role changes
- **Failover event history** - Complete log of all failover events with timestamps
- **Event categorization** - Automatic, manual, and failure-based events
- **Date range filtering** - Filter events by specific date/time ranges
- **CSV export** - Export failover history for reporting and analysis

### User Session Management
- **Multi-protocol support** - Web, VPN, and Workspace sessions
- **Session analytics** - Active sessions, connection types, and user statistics
- **Advanced filtering** - Filter by date, user, connection type, and status
- **Session details** - Duration, data usage, client IP, and node information
- **CSV export** - Export session data for compliance and reporting

### Enhanced UI
- **Tab-based navigation** - Overview, Failover History, and User Sessions tabs
- **Real-time updates** - All data refreshes automatically every 30 seconds
- **Responsive design** - Works on desktop, tablet, and mobile devices
- **Interactive filters** - Dynamic filtering with instant results

## 🔧 Installation & Setup

### 1. Prerequisites
- Python 3.7+ installed
- Access to NetScaler appliances (10.0.0.100 and 10.0.0.200)
- Network connectivity to the NetScaler management interfaces

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Directory Structure
Create the following directory structure:
```
netscaler-dashboard/
├── app.py                 # Enhanced Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── dashboard.html     # Enhanced HTML template
└── README.md             # This file
```

### 4. File Setup
1. **Save the enhanced Python code** as `app.py`
2. **Create templates directory**: `mkdir templates`
3. **Save the enhanced HTML template** as `templates/dashboard.html`
4. **Save requirements.txt** in the main directory

### 5. Configuration
The NetScaler configuration is set in `app.py`:
```python
NETSCALER_CONFIG = {
    'primary': {
        'ip': '10.0.0.100',
        'username': 'nsroot',
        'password': 'nsroot1',
        'port': 80,
        'protocol': 'http'
    },
    'secondary': {
        'ip': '10.0.0.200',
        'username': 'nsroot',
        'password': 'nsroot1',
        'port': 80,
        'protocol': 'http'
    }
}
```

**To modify settings:**
- Change IP addresses if your NetScaler has different IPs
- Update username/password if needed
- Modify port if using different port (80 for HTTP, 443 for HTTPS)

## 🚀 Running the Application

### Start the Enhanced Flask Server
```bash
python app.py
```

### Access the Enhanced Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## 📊 Features

### Overview Tab
- **Real-time System Monitoring** - CPU, memory, and resource utilization
- **HA Status Display** - Current primary/secondary roles and health
- **Load Balancing Intelligence** - Virtual servers and services status
- **System Information** - Version, build, hostname, and platform details

### Failover History Tab
- **Event Timeline** - Chronological view of all failover events
- **Event Details** - Type, reason, timestamp, and role changes
- **Date Filtering** - Filter events by custom date ranges
- **Export Functionality** - Download failover history as CSV

### User Sessions Tab
- **Session Overview** - Real-time active sessions across all connection types
- **Connection Analytics** - Web, VPN, and Workspace session statistics
- **Advanced Filtering** - Filter by date, user, connection type, and status
- **Session Details** - Duration, data usage, client information
- **Export Capability** - Export filtered session data as CSV

## 🔧 Enhanced NITRO API Integration

### Supported API Calls
- `/nitro/v1/stat/system` - System statistics
- `/nitro/v1/stat/ns` - NetScaler statistics  
- `/nitro/v1/config/lbvserver` - Load balancing virtual servers
- `/nitro/v1/config/hanode` - High availability nodes
- `/nitro/v1/config/service` - Services configuration
- `/nitro/v1/config/aaasession` - AAA user sessions
- `/nitro/v1/config/vpnsession` - VPN user sessions
- `/nitro/v1/config/icasession` - Citrix workspace sessions

### New API Endpoints
- `GET /api/failover-history` - Retrieve failover events
- `GET /api/user-sessions` - Retrieve user sessions with filtering
- `GET /api/export/failover-history` - Export failover history as CSV
- `GET /api/export/user-sessions` - Export user sessions as CSV

## 🛡️ Security Considerations

### Authentication & Access
- **Session-based authentication** with NITRO API
- **Automatic login/logout** handling
- **SSL/TLS support** for HTTPS connections

### Data Protection
- **No persistent storage** - All data is in-memory
- **Secure credentials** - Store credentials securely (environment variables recommended)
- **Network security** - Ensure proper firewall rules

### Compliance Features
- **Session auditing** - Complete session logs for compliance
- **Data export** - CSV exports for audit trails
- **Event tracking** - Comprehensive failover event logging

## 🔍 Troubleshooting

### Common Issues

**Connection Failed:**
- Verify NetScaler IP addresses are correct
- Check network connectivity: `ping 10.0.0.100`
- Ensure NITRO API is enabled on NetScaler
- Verify username/password credentials

**No Failover Events:**
- Failover events are detected based on HA role changes
- Ensure HA is configured on your NetScaler pair
- Events are generated when roles actually change

**No User Sessions:**
- User sessions are generated as mock data for demonstration
- In production, real session data would come from NITRO API
- Ensure session APIs are enabled on NetScaler

**Performance Issues:**
- Large session datasets may affect performance
- Use date filters to limit data scope
- Consider adjusting auto-refresh interval

### Enhanced Logs
Check Flask application logs for detailed information:
```bash
python app.py 2>&1 | tee enhanced_dashboard.log
```

## 📈 Performance Optimization

### Background Data Collection
- **Parallel collection** from multiple nodes
- **Intelligent caching** with 30-second refresh cycles
- **Failover detection** with minimal overhead
- **Session aggregation** for efficient display

### Efficient Data Processing
- **In-memory storage** for fast access
- **Filtered queries** to reduce data transfer
- **Pagination support** for large datasets
- **Async operations** for non-blocking updates

## 🔧 Customization

### Adding New Session Types
1. Extend the `NetScalerAPI` class with new session methods
2. Update the `collect_user_sessions` function
3. Add new connection types to the UI filters
4. Update the session display logic

### Custom Failover Logic
1. Modify the `track_failover_event` function
2. Add custom event types and reasons
3. Enhance the failover detection logic
4. Update the display formatting

### UI Customization
- **Tab system** - Easily add new tabs for additional features
- **Filtering** - Extend filters for more granular control
- **Styling** - Modify CSS classes for custom appearance
- **Charts** - Add data visualization components

## 📝 Enhanced API Endpoints

### Core Monitoring
- `GET /` - Enhanced dashboard page
- `GET /api/system-stats` - System statistics with HA roles
- `GET /api/system-info` - Detailed system information
- `GET /api/ha-status` - High availability status

### Failover Management
- `GET /api/failover-history` - Failover events history
  - Query parameters: `from_date`, `to_date`
- `GET /api/export/failover-history` - Export as CSV

### Session Management
- `GET /api/user-sessions` - User sessions with filtering
  - Query parameters: `from_date`, `to_date`, `connection_type`, `username`, `status`
- `GET /api/export/user-sessions` - Export sessions as CSV

### Utility
- `GET /api/refresh` - Force immediate data refresh
- `GET /api/debug` - Comprehensive debug information
- `GET /api/health` - Application health check

## 🎯 Use Cases

### Network Operations
- **Real-time monitoring** of NetScaler performance
- **Failover tracking** for incident management
- **Capacity planning** with session analytics

### Security & Compliance
- **User access auditing** with detailed session logs
- **Compliance reporting** with CSV exports
- **Security monitoring** with connection type analysis

### Business Intelligence
- **Usage patterns** analysis across connection types
- **Peak hour identification** for resource planning
- **User behavior tracking** for optimization

## 🏗️ Enhanced Architecture

```
Browser ←→ Enhanced Flask App ←→ NITRO API ←→ NetScaler Appliances
                ↓
         Background Thread
         (Data + Sessions + Failover)
                ↓
      Enhanced Cached Data
      (System + HA + Sessions + Events)
```

## 📄 License

This enhanced project is provided as-is for educational and monitoring purposes. Ensure compliance with your organization's security policies and NetScaler licensing terms.

## 🔄 Version History

- **v2.1** - Enhanced version with failover monitoring and user sessions
- **v2.0** - Original real dashboard with NITRO API integration
- **v1.0** - Basic monitoring dashboard