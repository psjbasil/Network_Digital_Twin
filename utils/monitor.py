import time
from digital_twin.network_model import NetworkModel
from digital_twin.visualizer import NetworkVisualizer
from utils.config import Config

class TopologyMonitor:
    def __init__(self):
        self.network_model = NetworkModel()
        self.visualizer = NetworkVisualizer()
        self.config = Config()
        
    def start_monitoring(self):
        while True:
            try:
                if self.network_model.update_topology():
                    self.visualizer.visualize(
                        self.network_model.graph,
                        self.config.TOPOLOGY_IMAGE_PATH
                    )
                    print("拓扑更新成功")
                else:
                    print("拓扑更新失败")
            except Exception as e:
                print(f"监控错误: {str(e)}")
                
            time.sleep(self.config.UPDATE_INTERVAL)

if __name__ == "__main__":
    monitor = TopologyMonitor()
    monitor.start_monitoring() 