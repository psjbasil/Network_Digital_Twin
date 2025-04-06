import os
import sys
import requests
import json
import threading
import time
import logging

# 添加项目根目录到 Python 路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO, emit
from digital_twin.network_model import NetworkModel
from digital_twin.visualizer import NetworkVisualizer

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
network_model = NetworkModel()
visualizer = NetworkVisualizer()

# 确保static目录存在
os.makedirs('web_interface/static', exist_ok=True)

class TopologyUpdater:
    _instance = None  # 单例模式
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, interval=5):
        if not hasattr(self, 'initialized'):
            self.interval = interval
            self.controller_url = "http://localhost:8080/topology"
            self.last_topology = None
            self.retry_count = 0
            self.max_retries = 3
            self.retry_interval = 1  # 重试间隔（秒）
            self.thread = threading.Thread(target=self._update_loop, daemon=True)
            self.thread.start()
            self.initialized = True
            self.last_update_time = time.time()
            self.update_count = 0
            self.error_count = 0

    def _get_topology(self):
        """获取拓扑数据"""
        try:
            response = requests.get(self.controller_url, timeout=5)  # 添加超时
            if response.status_code == 200:
                topology = response.json()
                self.retry_count = 0
                self.error_count = 0
                self.last_topology = topology
                self.last_update_time = time.time()
                self.update_count += 1
                return topology
            elif response.status_code == 204 and self.last_topology:
                logger.debug("Using cached topology data")
                return self.last_topology
            else:
                # 强制获取拓扑数据
                response = requests.get(self.controller_url + "?force=true", timeout=5)
                if response.status_code == 200:
                    topology = response.json()
                    self.last_topology = topology
                    self.last_update_time = time.time()
                    self.update_count += 1
                    return topology
                logger.error(f"Failed to get topology: HTTP {response.status_code}")
                self.error_count += 1
                return None
        except requests.Timeout:
            logger.error("Timeout while getting topology")
            self.error_count += 1
            return None
        except Exception as e:
            logger.error(f"Error getting topology: {str(e)}")
            self.error_count += 1
            return None

    def _update_loop(self):
        while True:
            try:
                # 动态调整更新间隔
                current_interval = self._calculate_update_interval()
                
                topology = self._get_topology()
                if topology:
                    if topology != self.last_topology:
                        logger.info("检测到拓扑变化")
                        logger.debug(f"新拓扑数据: {json.dumps(topology, indent=2)}")
                        # 发送带有变化类型的拓扑更新
                        changes = self._detect_topology_changes(self.last_topology, topology)
                        socketio.emit('topology_update', {
                            'topology': topology,
                            'changes': changes,
                            'timestamp': time.time()
                        })
                        logger.info("拓扑数据已发送到前端")
                        self.last_topology = topology
                        self.retry_count = 0
                    else:
                        logger.debug("拓扑数据未变化")
                else:
                    self.retry_count += 1
                    if self.retry_count >= self.max_retries:
                        logger.warning("达到最大重试次数，等待更长时间后重试")
                        time.sleep(self.retry_interval * 2)
                        self.retry_count = 0
            except Exception as e:
                logger.error(f"Update loop error: {str(e)}")
                self.error_count += 1
            
            time.sleep(current_interval)

    def _calculate_update_interval(self):
        """动态计算更新间隔"""
        base_interval = self.interval
        
        # 根据错误率调整间隔
        if self.error_count > 10:
            return base_interval * 2
        elif self.error_count > 5:
            return base_interval * 1.5
        
        # 根据更新频率调整间隔
        time_since_last_update = time.time() - self.last_update_time
        if time_since_last_update > 300:  # 5分钟没有更新
            return base_interval * 0.5  # 更频繁地检查
        
        return base_interval

    def _detect_topology_changes(self, old_topology, new_topology):
        """检测拓扑变化的具体内容"""
        if not old_topology:
            return {'type': 'initial'}
        
        changes = {
            'added': {'switches': [], 'hosts': [], 'links': []},
            'removed': {'switches': [], 'hosts': [], 'links': []},
            'modified': {'switches': [], 'hosts': [], 'links': []}
        }
        
        # 检测交换机变化
        old_switches = {f"s{sw['dpid']}" for sw in old_topology.get('switches', [])}
        new_switches = {f"s{sw['dpid']}" for sw in new_topology.get('switches', [])}
        changes['added']['switches'] = list(new_switches - old_switches)
        changes['removed']['switches'] = list(old_switches - new_switches)
        
        # 检测主机变化
        old_hosts = {h['mac'] for h in old_topology.get('hosts', [])}
        new_hosts = {h['mac'] for h in new_topology.get('hosts', [])}
        changes['added']['hosts'] = list(new_hosts - old_hosts)
        changes['removed']['hosts'] = list(old_hosts - new_hosts)
        
        # 检测链路变化
        old_links = {(l['src']['dpid'], l['dst']['dpid']) for l in old_topology.get('links', [])}
        new_links = {(l['src']['dpid'], l['dst']['dpid']) for l in new_topology.get('links', [])}
        changes['added']['links'] = list(new_links - old_links)
        changes['removed']['links'] = list(old_links - new_links)
        
        return changes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@socketio.on('connect')
def handle_connect():
    """处理客户端连接"""
    logger.info("Client connected")
    try:
        updater = TopologyUpdater()
        topology = updater._get_topology()
        if topology:
            # 发送初始拓扑数据
            socketio.emit('topology_update', {
                'topology': topology,
                'changes': {'type': 'initial'}
            })
            logger.info("Initial topology sent to client")
        else:
            # 尝试强制获取拓扑
            response = requests.get(updater.controller_url + "?force=true")
            if response.status_code == 200:
                topology = response.json()
                socketio.emit('topology_update', {
                    'topology': topology,
                    'changes': {'type': 'initial'}
                })
                updater.last_topology = topology
                logger.info("Initial topology sent to client (forced)")
            else:
                logger.error("Failed to get initial topology")
    except Exception as e:
        logger.error(f"Error sending initial topology: {str(e)}")

if __name__ == '__main__':
    updater = TopologyUpdater()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 