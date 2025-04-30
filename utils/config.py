class Config:
    # Ryu controller configuration
    RYU_CONTROLLER_HOST = "127.0.0.1"
    RYU_CONTROLLER_PORT = 6653
    RYU_REST_API_PORT = 8080
    
    # Web interface configuration
    WEB_HOST = "0.0.0.0"
    WEB_PORT = 5000
    
    # Update interval (seconds)
    UPDATE_INTERVAL = 10
    
    # Static file path
    TOPOLOGY_IMAGE_PATH = "web_interface/static/topology.png" 