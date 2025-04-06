"""
网络拓扑模型
"""
import logging
from typing import Dict, List, Set, Optional

class NetworkModel:
    """网络拓扑模型类"""
    
    def __init__(self):
        """初始化网络模型"""
        self.switches: Dict[str, Dict] = {}  # 交换机信息
        self.hosts: Dict[str, Dict] = {}     # 主机信息
        self.links: List[Dict] = []          # 链路信息
        self.port_states: Dict[str, Dict] = {}  # 端口状态
        self.logger = logging.getLogger(__name__)
    
    def update_from_topology(self, topology_data: Dict) -> bool:
        """
        从拓扑数据更新模型
        
        Args:
            topology_data: 拓扑数据
            
        Returns:
            bool: 是否发生拓扑变化
        """
        try:
            # 保存旧拓扑用于比较
            old_switches = self.switches.copy()
            old_hosts = self.hosts.copy()
            old_links = self.links.copy()
            
            # 更新交换机信息
            self.switches = {}
            for switch in topology_data.get('switches', []):
                self.switches[switch['dpid']] = {
                    'dpid': switch['dpid'],
                    'ports': switch.get('ports', []),
                    'features': switch.get('features', {})
                }
            
            # 更新主机信息
            self.hosts = {}
            for host in topology_data.get('hosts', []):
                self.hosts[host['mac']] = {
                    'mac': host['mac'],
                    'ip': host.get('ip', ''),
                    'location': host.get('location', {})
                }
            
            # 更新链路信息
            self.links = []
            for link in topology_data.get('links', []):
                self.links.append({
                    'source': link['source'],
                    'target': link['target'],
                    'source_port': link.get('source_port'),
                    'target_port': link.get('target_port')
                })
            
            # 更新端口状态
            self.port_states = {}
            for switch in topology_data.get('switches', []):
                dpid = switch['dpid']
                self.port_states[dpid] = {}
                for port in switch.get('ports', []):
                    self.port_states[dpid][port['port_no']] = {
                        'state': port.get('state', 'down'),
                        'features': port.get('features', {})
                    }
            
            # 检查拓扑是否发生变化
            topology_changed = (
                old_switches != self.switches or
                old_hosts != self.hosts or
                old_links != self.links
            )
            
            if topology_changed:
                self.logger.info("检测到拓扑变化")
            
            return topology_changed
            
        except Exception as e:
            self.logger.error(f"更新拓扑模型失败: {str(e)}")
            return False
    
    def get_topology_data(self) -> Dict:
        """
        获取当前拓扑数据
        
        Returns:
            Dict: 拓扑数据
        """
        return {
            'switches': [
                {
                    'dpid': dpid,
                    'ports': data['ports'],
                    'features': data['features']
                }
                for dpid, data in self.switches.items()
            ],
            'hosts': [
                {
                    'mac': mac,
                    'ip': data['ip'],
                    'location': data['location']
                }
                for mac, data in self.hosts.items()
            ],
            'links': self.links.copy()
        }
    
    def is_topology_changed(self, new_topology: Dict) -> bool:
        """
        检查拓扑是否发生变化
        
        Args:
            new_topology: 新的拓扑数据
            
        Returns:
            bool: 是否发生变化
        """
        try:
            # 比较交换机
            new_switches = {
                switch['dpid']: switch
                for switch in new_topology.get('switches', [])
            }
            if new_switches != self.switches:
                return True
            
            # 比较主机
            new_hosts = {
                host['mac']: host
                for host in new_topology.get('hosts', [])
            }
            if new_hosts != self.hosts:
                return True
            
            # 比较链路
            new_links = set(
                (link['source'], link['target'])
                for link in new_topology.get('links', [])
            )
            current_links = set(
                (link['source'], link['target'])
                for link in self.links
            )
            if new_links != current_links:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"检查拓扑变化失败: {str(e)}")
            return False 