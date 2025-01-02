class Config:
    # Ryu控制器配置
    RYU_CONTROLLER_HOST = "127.0.0.1"
    RYU_CONTROLLER_PORT = 6653
    RYU_REST_API_PORT = 8080
    
    # Web界面配置
    WEB_HOST = "0.0.0.0"
    WEB_PORT = 5000
    
    # 更新间隔（秒）
    UPDATE_INTERVAL = 10
    
    # 静态文件路径
    TOPOLOGY_IMAGE_PATH = "web_interface/static/topology.png" 