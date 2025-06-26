# Network Digital Twin System

## Overview
A real-time network topology visualization system that monitors and visualizes SDN network infrastructure. This system provides real-time topology discovery, traffic monitoring, and web-based network visualization with a clean and efficient architecture.

## System Architecture

### 1. Physical Network Layer
- **Tools**: Mininet
- **Features**:
  - SDN network environment creation
  - Network topology simulation
  - Dynamic topology modification
  - Traffic generation and management

### 2. Control Layer
- **Tools**: Ryu SDN Controller
- **Components**:
  - `ryu_app.py`: Main SDN controller with topology discovery
  - `topology_rest.py`: REST API for external communication
- **Features**:
  - LLDP-based topology discovery
  - Real-time link and host monitoring  
  - OpenFlow flow statistics collection
  - Port statistics and traffic monitoring
  - RESTful API endpoints
  - WebSocket notifications

### 3. Presentation Layer
- **Tools**: Flask + D3.js, WebSocket
- **Components**:
  - `app.py`: Flask web server with SocketIO
  - `static/js/topology.js`: D3.js-based network visualization
  - `templates/index.html`: Single-page web interface
- **Features**:
  - Interactive network topology visualization
  - Real-time topology updates via WebSocket
  - Traffic flow overlay display
  - Traffic statistics dashboard
  - Responsive and modern UI design

## Project Structure
```
.
├── controller/          # Ryu SDN controller applications
│   ├── __init__.py     # Package initialization
│   ├── ryu_app.py      # Main SDN controller application
│   └── topology_rest.py # REST API controller
├── physical_network/    # Mininet topology configuration
│   └── topo.py         # Network topology definition
├── web_interface/       # Web-based visualization interface
│   ├── app.py          # Flask web application
│   ├── static/         # Static web assets
│   │   ├── css/        # Stylesheets
│   │   └── js/         # JavaScript modules
│   └── templates/      # HTML templates
├── utils/              # Utility functions and configuration
│   ├── config.py       # Configuration management
│   └── traffic_monitor.py  # Traffic data formatting utilities
└── setup.py            # Project installation and dependencies
```

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd Network_Digital_Twin
```

2. Install the package and its dependencies:
```bash
pip install -e .
```
This will install the following dependencies:
- Flask (Web framework for visualization interface)
- Flask-SocketIO (WebSocket support for real-time updates)
- Requests (HTTP client for API communication)
- Ryu (SDN controller framework with OpenFlow support)

3. Install Mininet:
```bash
# Follow the official Mininet installation guide:
# http://mininet.org/download/
```
Note: Make sure you have Python 3.7+ installed before proceeding with the installation.

## Usage

### Starting the System

1. Start the Ryu controller:
```bash
ryu-manager controller/ryu_app.py
```

2. Start the Mininet topology:
```bash
sudo python physical_network/topo.py
```

3. Start the web interface:
```bash
python web_interface/app.py
```

### Testing Network Changes

The system supports various network topology changes:

1. Link Operations:
```bash
mininet> link s1 s2 down  # Disconnect link between s1 and s2
mininet> link s1 s2 up    # Restore link between s1 and s2
```

2. Host Operations:
```bash
mininet> py net.delHost(h4)  # Remove host h4
```

3. Port Status Changes:
```bash
mininet> link s2 h2 down  # Disconnect h2 from s2
mininet> link s2 h2 up    # Restore connection
```

4. Switch Operations:
```bash
mininet> py net.delSwitch(s3)  # Remove switch s3
```

5. IP Address Changes:
```bash
mininet> h1 ifconfig h1-eth0 10.0.0.100/24  # Change h1's IP
mininet> h1 ping h2  # Trigger IP update
```

6. Traffic Generation for Testing:
```bash
# Generate traffic between hosts to test traffic monitoring
mininet> h1 iperf3 -s &                              # Start iperf3 server on h1
mininet> h2 iperf3 -c h1 -t 10 -b 500K        # Generate 500K traffic from h2 to h1
mininet> h2 iperf3 -c h1 -t 10 -b 1M          # Generate 1M traffic from h2 to h1
```

## Features

- **Real-time Network Monitoring**:
  - Dynamic topology visualization
  - Link state tracking
  - Port status monitoring
  
- **Traffic Analysis**:
  - Real-time traffic flow visualization
  - Traffic statistics dashboard
  - Port throughput monitoring
  
- **Interactive Interface**:
  - Web-based topology visualization
  - Traffic overlay display
  - Real-time statistics dashboard
  - Interactive network manipulation

### Traffic Monitoring Features

The system provides two main traffic monitoring capabilities:

1. **Real-time Traffic Visualization**:
   - Click "Show Traffic" / "Hide Traffic" button to toggle traffic overlay
   - Traffic flows are displayed as colored links with varying thickness

2. **Traffic Statistics Dashboard**:
   - Click "Traffic Stats" button to view detailed statistics
   - Shows throughput, packet counts, and byte transfer data

### API Endpoints

The system provides the following REST API endpoints:

- `GET /topology` - Get current network topology
- `GET /traffic` - Get traffic statistics
- `GET /traffic/summary` - Get traffic summary

## Key Features Implemented

- **Streamlined Architecture**: Focused on core SDN monitoring without unnecessary complexity
- **Optimized Performance**: Efficient topology discovery and traffic monitoring
- **Clean Code**: Reduced from 1884 to 1519 lines (19.4% reduction) while maintaining all functionality
- **Minimal Dependencies**: Only essential packages required for core functionality

## Acknowledgments

- Mininet for network emulation and testing
- Ryu for SDN controller framework and OpenFlow support
- D3.js for interactive network visualization
- Flask and SocketIO for real-time web interface
