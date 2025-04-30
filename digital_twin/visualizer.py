"""
Network Topology Visualization
"""
import logging
from typing import Dict, List, Set, Optional
import json

class NetworkVisualizer:
    """Network Topology Visualization Class"""
    
    def __init__(self):
        """Initialize visualizer"""
        self.layout_data = {}  # Store node position information
        self.logger = logging.getLogger(__name__)
        self.node_styles = {
            'switch': {
                'color': '#2196F3',
                'size': 30,
                'label': 'Switch'
            },
            'host': {
                'color': '#4CAF50',
                'size': 20,
                'label': 'Host'
            }
        }
        self.edge_styles = {
            'normal': {
                'color': '#666',
                'width': 2
            },
            'down': {
                'color': '#FF5252',
                'width': 2,
                'dashes': True
            }
        }
    
    def get_visualization_data(self, topology_data: Dict) -> Dict:
        """
        Get visualization data
        
        Args:
            topology_data: Topology data
            
        Returns:
            Dict: Visualization data
        """
        try:
            # Convert topology data to visualization format
            vis_data = {
                'nodes': [],
                'edges': []
            }
            
            # Add switch nodes
            for switch in topology_data.get('switches', []):
                dpid = switch['dpid']
                vis_data['nodes'].append({
                    'id': f's{dpid}',
                    'label': f'Switch {dpid}',
                    'type': 'switch',
                    'position': self.layout_data.get(f's{dpid}', {'x': 0, 'y': 0}),
                    'style': self.node_styles['switch'],
                    'ports': switch.get('ports', [])
                })
            
            # Add host nodes
            for host in topology_data.get('hosts', []):
                mac = host['mac']
                vis_data['nodes'].append({
                    'id': mac,
                    'label': f'Host {host.get("ip", mac)}',
                    'type': 'host',
                    'position': self.layout_data.get(mac, {'x': 0, 'y': 0}),
                    'style': self.node_styles['host'],
                    'dpid': host.get('dpid'),
                    'port': host.get('port'),
                    'is_active': host.get('is_active', True)
                })
            
            # Add links
            for link in topology_data.get('links', []):
                src = f's{link["src"]["dpid"]}'
                dst = f's{link["dst"]["dpid"]}'
                
                # Check link state
                src_port_key = (link['src']['dpid'], link['src']['port_no'])
                dst_port_key = (link['dst']['dpid'], link['dst']['port_no'])
                
                is_live = True  # Default state
                if 'port_states' in topology_data:
                    is_live = (topology_data['port_states'].get(src_port_key, False) and
                             topology_data['port_states'].get(dst_port_key, False))
                
                vis_data['edges'].append({
                    'from': src,
                    'to': dst,
                    'source_port': link['src']['port_no'],
                    'target_port': link['dst']['port_no'],
                    'style': self.edge_styles['down' if not is_live else 'normal']
                })
            
            return vis_data
            
        except Exception as e:
            self.logger.error(f"Failed to get visualization data: {str(e)}")
            return {'nodes': [], 'edges': []}
    
    def update_layout(self, node_id: str, position: Dict):
        """
        Update node position
        
        Args:
            node_id: Node ID
            position: Position information {'x': x, 'y': y}
        """
        self.layout_data[node_id] = position
    
    def save_layout(self, file_path: str):
        """
        Save layout data
        
        Args:
            file_path: File path
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.layout_data, f)
            self.logger.info(f"Layout data saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save layout data: {str(e)}")
    
    def load_layout(self, file_path: str):
        """
        Load layout data
        
        Args:
            file_path: File path
        """
        try:
            with open(file_path, 'r') as f:
                self.layout_data = json.load(f)
            self.logger.info(f"Layout data loaded from {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to load layout data: {str(e)}")
    
    def get_node_style(self, node_type: str) -> Dict:
        """
        Get node style
        
        Args:
            node_type: Node type ('switch' or 'host')
            
        Returns:
            Dict: Node style
        """
        return self.node_styles.get(node_type, {})
    
    def get_edge_style(self, is_live: bool) -> Dict:
        """
        Get edge style
        
        Args:
            is_live: Whether the link is active
            
        Returns:
            Dict: Edge style
        """
        return self.edge_styles['normal' if is_live else 'down'] 