from ryu.app.rest_topology import TopologyController
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import WSGIApplication

class NetworkMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.switches = []
        self.links = []
        self.monitor_thread = hub.spawn(self._monitor)
        wsgi = kwargs['wsgi']
        wsgi.register(TopologyController, {'network_monitor': self})

    def _monitor(self):
        while True:
            self.switches = get_switch(self.topology_api_app, None)
            self.links = get_link(self.topology_api_app, None)
            self._request_stats()
            hub.sleep(10)

    def _request_stats(self):
        for switch in self.switches:
            datapath = switch.dp
            parser = datapath.ofproto_parser
            req = parser.OFPPortStatsRequest(datapath, 0)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # 处理端口统计信息 