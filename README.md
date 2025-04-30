# Network Digital Twin System

## Overview
A real-time network topology visualization system that creates a digital twin of physical network infrastructure. This system enables real-time monitoring and visualization of network topology changes.

## System Architecture

### 1. Physical Network Layer
- **Tools**: Mininet
- **Features**:
  - SDN network environment creation
  - Network topology simulation
  - Dynamic topology modification

### 2. Control Layer
- **Tools**: Ryu Controller
- **Features**:
  - Network topology discovery
  - Link state monitoring
  - REST API endpoints
  - Real-time event handling

### 3. Digital Twin Layer
- **Tools**: Python (NetworkX, Matplotlib)
- **Features**:
  - Topology data processing
  - Network graph construction
  - Data visualization
  - State synchronization

### 4. Presentation Layer
- **Tools**: Flask, WebSocket
- **Features**:
  - Web-based visualization interface
  - Real-time data updates
  - Interactive topology manipulation
  - Responsive design

## Project Structure
```
.
├── physical_network/     # Mininet topology configuration
├── controller/          # Ryu controller applications
├── digital_twin/        # Network modeling and visualization
├── web_interface/       # Web application
├── utils/              # Utility functions
└── setup.py            # Project installation
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
- Flask (Web framework)
- Flask-SocketIO (WebSocket support)
- NetworkX (Graph operations)
- Matplotlib (Data visualization)
- Requests (HTTP client)
- Ryu (SDN controller)

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

## Features

- Real-time network topology visualization
- Dynamic topology change detection
- Interactive web interface
- RESTful API for system control
- WebSocket-based real-time updates

## Acknowledgments

- Mininet for network emulation
- Ryu for SDN controller
- NetworkX for graph operations
- Flask for web interface
