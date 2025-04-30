"""
Network Topology Model
"""
import logging
from typing import Dict, List, Set, Optional

class NetworkModel:
    """Network Topology Model Class"""
    
    def __init__(self):
        """Initialize network model"""
        self.switches: Dict[str, Dict] = {}  # Switch information
        self.hosts: Dict[str, Dict] = {}     # Host information
        self.links: List[Dict] = []          # Link information
        self.port_states: Dict[str, Dict] = {}  # Port state
        self.logger = logging.getLogger(__name__)
    
    def update_from_topology(self, topology_data: Dict) -> bool:
        """
        Update model from topology data
        
        Args:
            topology_data: Topology data
            
        Returns:
            bool: Whether topology has changed
        """
        try:
            # Save old topology for comparison
            old_switches = self.switches.copy()
            old_hosts = self.hosts.copy()
            old_links = self.links.copy()
            
            # Update switch information
            self.switches = {}
            for switch in topology_data.get('switches', []):
                self.switches[switch['dpid']] = {
                    'dpid': switch['dpid'],
                    'ports': switch.get('ports', []),
                    'features': switch.get('features', {})
                }
            
            # Update host information
            self.hosts = {}
            for host in topology_data.get('hosts', []):
                self.hosts[host['mac']] = {
                    'mac': host['mac'],
                    'ip': host.get('ip', ''),
                    'location': host.get('location', {})
                }
            
            # Update link information
            self.links = []
            for link in topology_data.get('links', []):
                self.links.append({
                    'source': link['source'],
                    'target': link['target'],
                    'source_port': link.get('source_port'),
                    'target_port': link.get('target_port')
                })
            
            # Update port state
            self.port_states = {}
            for switch in topology_data.get('switches', []):
                dpid = switch['dpid']
                self.port_states[dpid] = {}
                for port in switch.get('ports', []):
                    self.port_states[dpid][port['port_no']] = {
                        'state': port.get('state', 'down'),
                        'features': port.get('features', {})
                    }
            
            # Check if topology has changed
            topology_changed = (
                old_switches != self.switches or
                old_hosts != self.hosts or
                old_links != self.links
            )
            
            if topology_changed:
                self.logger.info("Topology change detected")
            
            return topology_changed
            
        except Exception as e:
            self.logger.error(f"Failed to update topology model: {str(e)}")
            return False
    
    def get_topology_data(self) -> Dict:
        """
        Get current topology data
        
        Returns:
            Dict: Topology data
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
        Check if topology has changed
        
        Args:
            new_topology: New topology data
            
        Returns:
            bool: Whether topology has changed
        """
        try:
            # Compare switches
            new_switches = {
                switch['dpid']: switch
                for switch in new_topology.get('switches', [])
            }
            if new_switches != self.switches:
                return True
            
            # Compare hosts
            new_hosts = {
                host['mac']: host
                for host in new_topology.get('hosts', [])
            }
            if new_hosts != self.hosts:
                return True
            
            # Compare links
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
            self.logger.error(f"Failed to check topology changes: {str(e)}")
            return False 