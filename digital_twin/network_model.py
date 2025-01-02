import networkx as nx
import json
import requests
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class NetworkModel:
    def __init__(self):
        self.graph = nx.Graph()
        self.controller_url = "http://localhost:8080"

    def update_topology(self):
        try:
            response = requests.get(f"{self.controller_url}/topology")
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response content: {response.text}")
            
            if response.status_code != 200:
                logger.error(f"Failed to get topology: HTTP {response.status_code}")
                return False
                
            topology_data = json.loads(response.text)
            
            self.graph.clear()
            
            # 添加交换机
            for switch in topology_data['switches']:
                self.graph.add_node(switch['dpid'], type='switch')
                
            # 添加链路
            for link in topology_data['links']:
                src = link['src']['dpid']
                dst = link['dst']['dpid']
                self.graph.add_edge(src, dst)
                
            return True
        except requests.exceptions.ConnectionError as e:
            logger.error(f"连接到控制器失败: {str(e)}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"解析拓扑数据失败: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"更新拓扑失败: {str(e)}")
            return False

    def get_topology(self):
        return {
            'nodes': list(self.graph.nodes()),
            'edges': list(self.graph.edges())
        } 