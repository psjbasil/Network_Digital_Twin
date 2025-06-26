"""
Configuration constants for Network Digital Twin System
"""

class Config:
    """Configuration class with system constants"""
    
    # Ryu controller configuration
    RYU_CONTROLLER_HOST = "127.0.0.1"
    RYU_CONTROLLER_PORT = 6653
    RYU_REST_API_PORT = 8080
    
    # Web interface configuration
    WEB_HOST = "0.0.0.0"
    WEB_PORT = 5000
    
    # Update intervals (seconds)
    TOPOLOGY_UPDATE_INTERVAL = 1
    TRAFFIC_UPDATE_INTERVAL = 2 