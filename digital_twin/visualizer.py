"""
网络可视化模块
"""
import logging
from typing import Dict, List, Optional

class NetworkVisualizer:
    """网络可视化类"""
    
    def __init__(self):
        """初始化可视化器"""
        self.logger = logging.getLogger(__name__)
        self.layout_data = {}  # 存储节点布局数据
        
    def update_layout(self, topology_data: Dict) -> Dict:
        """
        更新网络布局
        
        Args:
            topology_data: 拓扑数据
            
        Returns:
            Dict: 更新后的布局数据
        """
        try:
            # 保持现有节点的位置
            for node_id, pos in self.layout_data.items():
                if node_id in topology_data.get('nodes', {}):
                    topology_data['nodes'][node_id]['position'] = pos
            
            # 为新节点分配位置
            for node_id, node in topology_data.get('nodes', {}).items():
                if node_id not in self.layout_data:
                    # 简单网格布局
                    x = len(self.layout_data) % 10 * 100
                    y = len(self.layout_data) // 10 * 100
                    self.layout_data[node_id] = {'x': x, 'y': y}
                    node['position'] = self.layout_data[node_id]
            
            return topology_data
            
        except Exception as e:
            self.logger.error(f"更新布局失败: {str(e)}")
            return topology_data
            
    def get_visualization_data(self, topology_data: Dict) -> Dict:
        """
        获取可视化数据
        
        Args:
            topology_data: 拓扑数据
            
        Returns:
            Dict: 可视化数据
        """
        try:
            # 转换拓扑数据为可视化格式
            vis_data = {
                'nodes': [],
                'edges': []
            }
            
            # 添加交换机节点
            for dpid, switch in topology_data.get('switches', {}).items():
                vis_data['nodes'].append({
                    'id': dpid,
                    'label': f'Switch {dpid}',
                    'type': 'switch',
                    'position': self.layout_data.get(dpid, {'x': 0, 'y': 0})
                })
            
            # 添加主机节点
            for mac, host in topology_data.get('hosts', {}).items():
                vis_data['nodes'].append({
                    'id': mac,
                    'label': f'Host {mac}',
                    'type': 'host',
                    'position': self.layout_data.get(mac, {'x': 0, 'y': 0})
                })
            
            # 添加链路
            for link in topology_data.get('links', []):
                vis_data['edges'].append({
                    'from': link['source'],
                    'to': link['target'],
                    'source_port': link.get('source_port'),
                    'target_port': link.get('target_port')
                })
            
            return vis_data
            
        except Exception as e:
            self.logger.error(f"获取可视化数据失败: {str(e)}")
            return {'nodes': [], 'edges': []} 