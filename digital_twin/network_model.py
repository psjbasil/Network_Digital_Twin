import networkx as nx
import json
import requests

class NetworkModel:
    def __init__(self):
        self.graph = nx.Graph()
        self.controller_url = "http://localhost:8080"

    def update_topology(self):
        try:
            response = requests.get(f"{self.controller_url}/topology")
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
        except Exception as e:
            print(f"更新拓扑失败: {str(e)}")
            return False

    def get_topology(self):
        return {
            'nodes': list(self.graph.nodes()),
            'edges': list(self.graph.edges())
        } 