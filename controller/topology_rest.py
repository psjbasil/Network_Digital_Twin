from ryu.app.wsgi import ControllerBase, Response, route
import json
import logging

logger = logging.getLogger(__name__)

class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.network_monitor = data['network_monitor']

    @route('topology', '/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        """Get complete topology information"""
        try:
            topology_data = self.network_monitor.get_topology_data()
            return Response(content_type='application/json', 
                          body=json.dumps(topology_data))
        except Exception as e:
            logger.error(f"Failed to get topology: {str(e)}")
            return Response(status=500, body=str(e))

    @route('switches', '/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        """Get switch list"""
        try:
            switches = []
            for switch in self.network_monitor.switches.values():
                switches.append({
                    'dpid': switch.dp.id,
                    'ports': [{
                        'port_no': port.port_no,
                        'hw_addr': str(port.hw_addr),
                        'is_live': self.network_monitor.port_states.get(
                            (switch.dp.id, port.port_no), True)
                    } for port in switch.ports]
                })
            return Response(content_type='application/json',
                          body=json.dumps({'switches': switches}))
        except Exception as e:
            logger.error(f"Failed to get switches: {str(e)}")
            return Response(status=500, body=str(e))

    @route('hosts', '/hosts', methods=['GET'])
    def get_hosts(self, req, **kwargs):
        """Get host list"""
        try:
            hosts = []
            for mac, host in self.network_monitor.hosts.items():
                hosts.append({
                    'mac': mac,
                    'ip': host.get('ip'),
                    'dpid': host.get('dpid'),
                    'port': host.get('port'),
                    'is_active': host.get('is_active', True)
                })
            return Response(content_type='application/json',
                          body=json.dumps({'hosts': hosts}))
        except Exception as e:
            logger.error(f"Failed to get hosts: {str(e)}")
            return Response(status=500, body=str(e))

    @route('links', '/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        """Get link list"""
        try:
            links = []
            for link in self.network_monitor.links:
                links.append({
                    'src': {
                        'dpid': link.src.dpid,
                        'port_no': link.src.port_no
                    },
                    'dst': {
                        'dpid': link.dst.dpid,
                        'port_no': link.dst.port_no
                    }
                })
            return Response(content_type='application/json',
                          body=json.dumps({'links': links}))
        except Exception as e:
            logger.error(f"Failed to get links: {str(e)}")
            return Response(status=500, body=str(e))

    @route('port_state', '/port_state/{dpid}/{port_no}', methods=['GET'])
    def get_port_state(self, req, **kwargs):
        """Get port state"""
        try:
            dpid = int(kwargs['dpid'])
            port_no = int(kwargs['port_no'])
            
            port_key = (dpid, port_no)
            is_live = self.network_monitor.port_states.get(port_key, False)
            
            return Response(content_type='application/json',
                          body=json.dumps({
                              'dpid': dpid,
                              'port_no': port_no,
                              'is_live': is_live
                          }))
        except Exception as e:
            logger.error(f"Failed to get port state: {str(e)}")
            return Response(status=500, body=str(e))

    @route('host_connectivity', '/host_connectivity/{mac}', methods=['GET'])
    def get_host_connectivity(self, req, **kwargs):
        """Get host connectivity status"""
        try:
            mac = kwargs['mac']
            is_connected = self.network_monitor._check_host_connectivity(mac)
            
            return Response(content_type='application/json',
                          body=json.dumps({
                              'mac': mac,
                              'is_connected': is_connected
                          }))
        except Exception as e:
            logger.error(f"Failed to get host connectivity: {str(e)}")
            return Response(status=500, body=str(e))

    @route('topology', '/topology/link', methods=['POST'])
    def update_link(self, req, **kwargs):
        """REST API endpoint for updating link state
        
        Request body format:
        {
            "src_dpid": "Source switch ID",
            "dst_dpid": "Destination switch ID",
            "src_port_no": "Source port number",
            "dst_port_no": "Destination port number",
            "is_up": true/false
        }
        """
        try:
            body = json.loads(req.body)
            required_fields = ['src_dpid', 'dst_dpid', 'src_port_no', 'dst_port_no', 'is_up']
            
            # Validate required fields in request body
            for field in required_fields:
                if field not in body:
                    return Response(status=400, body=json.dumps({
                        'error': f'Missing required field: {field}'
                    }))
            
            # Get TopologyMonitor instance
            topology_monitor = self.topology_api_app.topology_monitor
            
            # Call update_link_state method
            result = topology_monitor.update_link_state(
                int(body['src_dpid']),
                int(body['dst_dpid']),
                int(body['src_port_no']),
                int(body['dst_port_no']),
                bool(body['is_up'])
            )
            
            if result:
                return Response(status=200, body=json.dumps({
                    'message': 'Link state updated successfully'
                }))
            else:
                return Response(status=400, body=json.dumps({
                    'error': 'Failed to update link state'
                }))
                
        except ValueError as e:
            return Response(status=400, body=json.dumps({
                'error': f'Invalid parameter value: {str(e)}'
            }))
        except Exception as e:
            return Response(status=500, body=json.dumps({
                'error': f'Internal server error: {str(e)}'
            })) 