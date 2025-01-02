from ryu.app.wsgi import ControllerBase, Response, route
import json

class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.network_monitor = data['network_monitor']

    @route('topology', '/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        switches = []
        links = []
        
        try:
            for switch in self.network_monitor.switches:
                switches.append({
                    'dpid': switch.dp.id,
                    'ports': [{'port_no': port.port_no} for port in switch.ports]
                })
                
            for link in self.network_monitor.links:
                links.append({
                    'src': {'dpid': link.src.dpid, 'port_no': link.src.port_no},
                    'dst': {'dpid': link.dst.dpid, 'port_no': link.dst.port_no}
                })
                
            body = json.dumps({
                'switches': switches,
                'links': links
            })
            
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500, body=str(e)) 