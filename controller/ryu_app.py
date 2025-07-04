from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import WSGIApplication, ControllerBase, Response, route
from ryu.lib.packet import packet, ethernet, ether_types, lldp, arp, ipv4
import json
import logging
import time
import os

# Import the external REST API controller
try:
    # Try relative import first (when run as part of a package)
    from .topology_rest import TopologyController
except ImportError:
    # Fall back to absolute import (when run directly)
    try:
        from topology_rest import TopologyController
    except ImportError:
        # If both fail, try importing from controller package
        import sys
        import os
        
        # Add the controller directory to Python path
        controller_dir = os.path.dirname(os.path.abspath(__file__))
        if controller_dir not in sys.path:
            sys.path.insert(0, controller_dir)
        
        from topology_rest import TopologyController

# Configure logging - keep it simple
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Simply set log levels to suppress frequent access logs
logging.getLogger('werkzeug').setLevel(logging.WARNING)  # Only show warnings/errors
logging.getLogger('socketio').setLevel(logging.WARNING)
logging.getLogger('engineio').setLevel(logging.WARNING) 
logging.getLogger('gevent').setLevel(logging.WARNING)

# Suppress Ryu's WSGI server access logs
logging.getLogger('ryu.app.wsgi').setLevel(logging.WARNING)
logging.getLogger('ryu.lib.hub').setLevel(logging.WARNING)
logging.getLogger('ryu').setLevel(logging.INFO)  # Keep general Ryu logs at INFO level

# Additional WSGI server loggers that might produce access logs
import wsgiref.simple_server
wsgiref.simple_server.ServerHandler.log_message = lambda self, format, *args: None

# Suppress more potential log sources
logging.getLogger('eventlet.wsgi.server').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

# Override potential access logging methods
try:
    from ryu.app.wsgi import WSGIApplication
    # Monkey patch to disable access logging if possible
    original_log_request = getattr(WSGIApplication, 'log_request', None)
    if original_log_request:
        WSGIApplication.log_request = lambda self, *args, **kwargs: None
except:
    pass

logger = logging.getLogger(__name__)

class TopologyMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)
        logger.info("Topology monitoring application started")
        self.topology_api_app = self
        self.switches = {}      # dpid -> Switch object
        self.links = []         # Store all link information
        self.hosts = {}         # mac -> host information
        self.datapaths = {}     # dpid -> datapath
        self.port_states = {}   # (dpid, port_no) -> is_live
        self.gateway_macs = set()  # Store gateway MAC addresses
        self.ws_clients = set()  # Store WebSocket client connections
        self.lldp_timestamps = {}  # Store last LLDP timestamp for each link
        
        # Register REST API
        wsgi = kwargs['wsgi']
        
        # Try to disable WSGI access logging
        try:
            # Set WSGI logger to WARNING level
            if hasattr(wsgi, 'logger'):
                wsgi.logger.setLevel(logging.WARNING)
            # Override log_request method if it exists
            if hasattr(wsgi, 'log_request'):
                wsgi.log_request = lambda *args, **kwargs: None
        except:
            pass
            
        wsgi.register(TopologyController, {'topology_monitor': self})
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.discovery_thread = hub.spawn(self._active_scan)
        self.lldp_thread = hub.spawn(self._send_lldp_packets)
        self.stats_thread = hub.spawn(self._collect_statistics)

        self.host_timeout = 300  # Increase host timeout to 5 minutes
        self.discovery_interval = 120  # Active discovery interval is 2 minutes (reduced frequency)
        self.lldp_interval = 10  # LLDP sending interval is 10 seconds (reduced frequency)
        self.link_timeout = 30  # Link timeout is 30 seconds (increased tolerance)

        self.ip_to_mac = {}     # Add IP to MAC mapping
        self.pending_hosts = {} # Store hosts waiting for IP
        self.mac_to_port = {}  # Add MAC to port mapping

        # Add new attribute to track topology changes
        self.last_topology = None  # Store last topology information
        self.topology_changed = False  # Flag whether topology has changed
        
        # Add traffic monitoring attributes
        self.flow_stats = {}    # Store flow statistics
        self.port_stats = {}    # Store port statistics
        self.flow_stats_reply_pending = set()  # Track pending flow stats requests
        self.port_stats_reply_pending = set()  # Track pending port stats requests
        self.last_stats_request = 0  # Last statistics request timestamp
        self.stats_request_interval = 3  # Statistics request interval (seconds)
        
        logger.info("Topology monitoring initialization completed")

    def _is_topology_changed(self, new_topology):
        """Compare if topology has changed"""
        if self.last_topology is None:
            logger.info("First topology data")
            return True
            
        # Removed verbose topology comparison debug log
        
        # Compare number of switches and port states
        if len(new_topology['switches']) != len(self.last_topology['switches']):
            logger.info("Switch number changed")
            return True

        # Sort switches by dpid and compare
        new_switches = sorted(new_topology['switches'], key=lambda x: x['dpid'])
        old_switches = sorted(self.last_topology['switches'], key=lambda x: x['dpid'])
        
        for new_sw, old_sw in zip(new_switches, old_switches):
            if new_sw['dpid'] != old_sw['dpid']:
                logger.info(f"Switch DPID changed: {new_sw['dpid']} != {old_sw['dpid']}")
                return True
                
            # Sort ports by port_no and compare
            new_ports = sorted(new_sw['ports'], key=lambda x: x['port_no'])
            old_ports = sorted(old_sw['ports'], key=lambda x: x['port_no'])
            
            if len(new_ports) != len(old_ports):
                logger.info(f"Port number changed for switch {new_sw['dpid']}")
                return True
                
            for new_port, old_port in zip(new_ports, old_ports):
                if (new_port['port_no'] != old_port['port_no'] or
                    new_port['is_live'] != old_port['is_live']):
                    logger.info(f"Port state changed for switch {new_sw['dpid']}, port {new_port['port_no']}")
                    return True

        # Compare number and state of links
        if len(new_topology['links']) != len(self.last_topology['links']):
            logger.info("Link number changed")
            return True

        # Normalize and sort links before comparison
        def normalize_and_sort_links(links):
            normalized_links = []
            for link in links:
                src = link['src']
                dst = link['dst']
                if (src['dpid'] > dst['dpid'] or 
                    (src['dpid'] == dst['dpid'] and src['port_no'] > dst['port_no'])):
                    src, dst = dst, src
                normalized_links.append({
                    'src': src,
                    'dst': dst
                })
            return sorted(normalized_links, 
                        key=lambda x: (x['src']['dpid'], x['src']['port_no'], 
                                     x['dst']['dpid'], x['dst']['port_no']))

        new_links = normalize_and_sort_links(new_topology['links'])
        old_links = normalize_and_sort_links(self.last_topology['links'])

        for new_link, old_link in zip(new_links, old_links):
            if (new_link['src']['dpid'] != old_link['src']['dpid'] or
                new_link['dst']['dpid'] != old_link['dst']['dpid'] or
                new_link['src']['port_no'] != old_link['src']['port_no'] or
                new_link['dst']['port_no'] != old_link['dst']['port_no']):
                logger.info("Link configuration changed")
                return True

        # Compare host information
        if len(new_topology['hosts']) != len(self.last_topology['hosts']):
            logger.info("Host number changed")
            return True

        # Sort hosts by MAC address and compare
        new_hosts = sorted(new_topology['hosts'], key=lambda x: x['mac'])
        old_hosts = sorted(self.last_topology['hosts'], key=lambda x: x['mac'])

        for new_host, old_host in zip(new_hosts, old_hosts):
            if (new_host['mac'] != old_host['mac'] or
                new_host['dpid'] != old_host['dpid'] or
                new_host['port'] != old_host['port'] or
                new_host['ip'] != old_host['ip']):
                logger.info(f"Host information changed: {new_host['mac']}")
                return True

        return False

    def _monitor(self):
        """Periodically monitor topology changes"""
        while True:
            try:
                current_time = time.time()
                
                # Update switch and link information
                switches = get_switch(self.topology_api_app, None)
                self.switches = {sw.dp.id: sw for sw in switches}
                
                # Check link timeout
                links_to_remove = []
                for link in self.links:
                    src_dpid = link.src.dpid
                    dst_dpid = link.dst.dpid
                    src_port = link.src.port_no
                    dst_port = link.dst.port_no
                    
                    # Standardize link direction
                    if src_dpid > dst_dpid:
                        src_dpid, dst_dpid = dst_dpid, src_dpid
                        src_port, dst_port = dst_port, src_port
                    
                    link_key = (src_dpid, src_port, dst_dpid, dst_port)
                    last_seen = self.lldp_timestamps.get(link_key, 0)
                    
                    # If link times out, mark for removal
                    if current_time - last_seen > self.link_timeout:
                        links_to_remove.append((src_dpid, dst_dpid, src_port, dst_port))
                        logger.info(f"Link timeout: {src_dpid}:{src_port} -> {dst_dpid}:{dst_port}")
                
                # Remove timed-out links
                for link in links_to_remove:
                    src_dpid, dst_dpid, src_port, dst_port = link
                    self.update_link_state(src_dpid, dst_dpid, src_port, dst_port, False)
                    link_key = (src_dpid, src_port, dst_dpid, dst_port)
                    if link_key in self.lldp_timestamps:
                        del self.lldp_timestamps[link_key]
                
                # Clean up invalid host information
                self._cleanup_hosts()
                
                # Get current topology information
                current_topology = self.get_topology_data()
                
                # Check if topology has changed
                if self._is_topology_changed(current_topology):
                    self._log_topology_changes(self.last_topology, current_topology)
                    self.last_topology = current_topology
                    self.topology_changed = True
                    self._notify_topology_change()
                elif self.topology_changed:
                    # If topology_changed flag is set by other events, still notify
                    logger.info("Topology changed by external event, sending update")
                    self.last_topology = current_topology
                    self.topology_changed = False
                    self._notify_topology_change()
                
            except Exception as e:
                logger.error(f"Monitoring error: {str(e)}")
            
            hub.sleep(5)  # Check every 5 seconds

    def _active_scan(self):
        """Actively scan for hosts"""
        while True:
            try:
                current_time = time.time()
                
                # Check and mark inactive hosts
                for mac, host in list(self.hosts.items()):
                    if current_time - host['last_seen'] > self.host_timeout:
                        if host.get('is_active', True):
                            host['is_active'] = False
                            logger.info(f"Host {mac} marked as inactive")
                    elif not host.get('is_active', True):
                        host['is_active'] = True
                        logger.info(f"Host {mac} is active again")

                # Send ARP requests to each port of each switch
                for dpid, switch in self.switches.items():
                    if dpid not in self.datapaths:
                        continue
                    datapath = self.datapaths[dpid]
                    
                    # Get known active host IPs
                    known_ips = set()
                    for host in self.hosts.values():
                        if host.get('is_active') and host.get('ip'):
                            known_ips.add(host['ip'])
                    
                    # Send ARP requests to each port (limited scanning)
                    for port in switch.ports:
                        if port.port_no != datapath.ofproto.OFPP_LOCAL:
                            # Only scan a limited range for active discovery
                            for i in range(1, 11):  # Only scan first 10 IPs
                                target_ip = f'10.0.0.{i}'
                                if target_ip not in known_ips:
                                    self._send_arp_request(datapath, port.port_no, port.hw_addr, target_ip)
                                    hub.sleep(0.2)  # Slower scanning to avoid flooding
                
            except Exception as e:
                logger.error(f"Active scan error: {str(e)}")
            
            hub.sleep(self.discovery_interval)

    def _log_topology_changes(self, old_topology, new_topology):
        """Log specific content of topology changes"""
        if not old_topology:
            logger.info("First topology data obtained")
            return

        # Compare switch changes
        old_switches = {sw['dpid'] for sw in old_topology['switches']}
        new_switches = {sw['dpid'] for sw in new_topology['switches']}
        added_switches = new_switches - old_switches
        removed_switches = old_switches - new_switches
        if added_switches:
            logger.info(f"Topology change - Added switches: {sorted(list(added_switches))}")
        if removed_switches:
            logger.info(f"Topology change - Removed switches: {sorted(list(removed_switches))}")

        # Compare link changes
        old_links = {(link['src']['dpid'], link['src']['port_no'], 
                     link['dst']['dpid'], link['dst']['port_no']) 
                    for link in old_topology['links']}
        new_links = {(link['src']['dpid'], link['src']['port_no'], 
                     link['dst']['dpid'], link['dst']['port_no']) 
                    for link in new_topology['links']}
        added_links = new_links - old_links
        removed_links = old_links - new_links
        if added_links:
            for link in sorted(list(added_links)):
                logger.info(f"Topology change - Added link: {link[0]}:{link[1]} -> {link[2]}:{link[3]}")
        if removed_links:
            for link in sorted(list(removed_links)):
                logger.info(f"Topology change - Removed link: {link[0]}:{link[1]} -> {link[2]}:{link[3]}")

        # Compare host changes
        old_hosts = {(host['mac'], host['ip']) for host in old_topology['hosts']}
        new_hosts = {(host['mac'], host['ip']) for host in new_topology['hosts']}
        added_hosts = new_hosts - old_hosts
        removed_hosts = old_hosts - new_hosts
        if added_hosts:
            for host in sorted(list(added_hosts)):
                logger.info(f"Topology change - Added host: MAC={host[0]}, IP={host[1]}")
        if removed_hosts:
            for host in sorted(list(removed_hosts)):
                logger.info(f"Topology change - Removed host: MAC={host[0]}, IP={host[1]}")

    def _cleanup_hosts(self):
        """Clean up invalid host information"""
        current_time = time.time()
        hosts_to_remove = []
        
        for mac, host in self.hosts.items():
            port_key = (host['dpid'], host['port'])
            # Check port state
            port_down = not self.port_states.get(port_key, True)
            
            # Check if host has been inactive for too long
            last_seen = host.get('last_seen', current_time)
            inactive_too_long = (current_time - last_seen) > self.host_timeout
            
            # Check if the port exists in any active links (this indicates it's an inter-switch link)
            port_in_link = False
            for link in self.links:
                if ((link.src.dpid == host['dpid'] and link.src.port_no == host['port']) or
                    (link.dst.dpid == host['dpid'] and link.dst.port_no == host['port'])):
                    port_in_link = True
                    break
            
            # Remove host only if:
            # 1. Port is down AND it's not in a link (to avoid removing hosts on inter-switch ports)
            # 2. OR host has been inactive for too long
            if (port_down and not port_in_link) or inactive_too_long:
                hosts_to_remove.append(mac)
                reason = "inactive timeout" if inactive_too_long else "port down"
                logger.info(f"Removed host due to {reason}: {mac}")
        
        for mac in hosts_to_remove:
            del self.hosts[mac]
            # Clean up related IP mappings
            for ip, known_mac in list(self.ip_to_mac.items()):
                if known_mac == mac:
                    del self.ip_to_mac[ip]

    def _send_lldp_packets(self):
        """Thread for periodically sending LLDP packets"""
        while True:
            try:
                self._send_lldp_probes()
            except Exception as e:
                logger.error(f"Error sending LLDP packets: {e}")
            hub.sleep(self.lldp_interval)

    def _collect_statistics(self):
        """Collect traffic statistics from all switches"""
        while True:
            try:
                current_time = time.time()
                if current_time - self.last_stats_request >= self.stats_request_interval:
                    self._request_flow_stats()
                    self._request_port_stats()
                    self.last_stats_request = current_time
                hub.sleep(1)
            except Exception as e:
                logger.error(f"Error in statistics collection: {str(e)}")
                hub.sleep(5)

    def _request_flow_stats(self):
        """Request flow statistics from all connected switches"""
        for dpid, datapath in self.datapaths.items():
            if dpid not in self.flow_stats_reply_pending:
                try:
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    
                    req = parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(req)
                    self.flow_stats_reply_pending.add(dpid)
                    # Removed frequent flow stats request log
                except Exception as e:
                    logger.error(f"Failed to request flow stats from switch {dpid}: {str(e)}")

    def _request_port_stats(self):
        """Request port statistics from all connected switches"""
        for dpid, datapath in self.datapaths.items():
            if dpid not in self.port_stats_reply_pending:
                try:
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    
                    req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
                    datapath.send_msg(req)
                    self.port_stats_reply_pending.add(dpid)
                    # Removed frequent port stats request log
                except Exception as e:
                    logger.error(f"Failed to request port stats from switch {dpid}: {str(e)}")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        try:
            # Remove from pending set
            self.flow_stats_reply_pending.discard(dpid)
            
            # Initialize flow stats for this switch
            if dpid not in self.flow_stats:
                self.flow_stats[dpid] = {}
            
            # Process each flow entry
            for stat in msg.body:
                match = stat.match
                priority = stat.priority
                
                # Create flow key for identification
                flow_key = f"{priority}_{hash(str(match))}"
                
                # Store flow statistics
                self.flow_stats[dpid][flow_key] = {
                    'match': str(match),
                    'priority': priority,
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration_sec': stat.duration_sec,
                    'duration_nsec': stat.duration_nsec,
                    'idle_timeout': stat.idle_timeout,
                    'hard_timeout': stat.hard_timeout,
                    'timestamp': time.time()
                }
            
            # Removed frequent flow stats update log
            
        except Exception as e:
            logger.error(f"Error processing flow stats reply from switch {dpid}: {str(e)}")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        try:
            # Remove from pending set
            self.port_stats_reply_pending.discard(dpid)
            
            # Initialize port stats for this switch
            if dpid not in self.port_stats:
                self.port_stats[dpid] = {}
            
            # Process each port statistics
            for stat in msg.body:
                port_no = stat.port_no
                
                # Skip local and controller ports
                if port_no >= 0xffffff00:
                    continue
                
                # Calculate throughput if we have previous data
                prev_stats = self.port_stats[dpid].get(port_no, {})
                current_time = time.time()
                
                rx_throughput = 0
                tx_throughput = 0
                
                if prev_stats and 'timestamp' in prev_stats:
                    time_diff = current_time - prev_stats['timestamp']
                    if time_diff > 0:
                        rx_bytes_diff = stat.rx_bytes - prev_stats.get('rx_bytes', 0)
                        tx_bytes_diff = stat.tx_bytes - prev_stats.get('tx_bytes', 0)
                        
                        rx_throughput = max(0, rx_bytes_diff / time_diff) * 8  # Convert to bits per second
                        tx_throughput = max(0, tx_bytes_diff / time_diff) * 8  # Convert to bits per second
                
                # Store port statistics
                self.port_stats[dpid][port_no] = {
                    'port_no': port_no,
                    'rx_packets': stat.rx_packets,
                    'tx_packets': stat.tx_packets,
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'rx_dropped': stat.rx_dropped,
                    'tx_dropped': stat.tx_dropped,
                    'rx_errors': stat.rx_errors,
                    'tx_errors': stat.tx_errors,
                    'rx_frame_err': stat.rx_frame_err,
                    'rx_over_err': stat.rx_over_err,
                    'rx_crc_err': stat.rx_crc_err,
                    'collisions': stat.collisions,
                    'rx_throughput': rx_throughput,
                    'tx_throughput': tx_throughput,
                    'timestamp': current_time
                }
            
            # Removed frequent port stats update log
            
        except Exception as e:
            logger.error(f"Error processing port stats reply from switch {dpid}: {str(e)}")

    def _send_lldp_probes(self):
        """Send LLDP probe packets"""
        for dpid, switch in self.switches.items():
            if dpid not in self.datapaths:
                continue
            datapath = self.datapaths[dpid]
            for port in switch.ports:
                if port.port_no != datapath.ofproto.OFPP_LOCAL:
                    try:
                        # Check port state
                        if self.port_states.get((dpid, port.port_no), True):
                            self._send_lldp_packet(datapath, port.port_no, port.hw_addr)
                    except Exception as e:
                        logger.error(f"Error sending LLDP probe on switch {dpid} port {port.port_no}: {e}")
            
        # Removed frequent LLDP probe cycle log

    def _send_lldp_packet(self, datapath, port_no, hw_addr):
        """Send LLDP packet to specified port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct LLDP packet
        pkt = packet.Packet()
        
        # Add Ethernet header
        pkt.add_protocol(ethernet.ethernet(
            dst='01:80:c2:00:00:0e',
            src=hw_addr,
            ethertype=ether_types.ETH_TYPE_LLDP))

        # Construct LLDP TLV
        tlvs = []
        
        # Chassis ID - Use LOCALLY_ASSIGNED subtype
        chassis_id = str(datapath.id).encode('utf-8')
        tlvs.append(lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=chassis_id))
        
        # Port ID - Use PORT_COMPONENT subtype
        port_id = str(port_no).encode('utf-8')
        tlvs.append(lldp.PortID(
            subtype=lldp.PortID.SUB_PORT_COMPONENT,
            port_id=port_id))
        
        # TTL
        tlvs.append(lldp.TTL(ttl=120))
        
        # System Name (optional)
        sys_name = f"switch-{datapath.id}".encode('utf-8')
        tlvs.append(lldp.SystemName(system_name=sys_name))
        
        # End
        tlvs.append(lldp.End())

        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()

        data = pkt.data
        actions = [parser.OFPActionOutput(port_no)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data)
        
        datapath.send_msg(out)
        # Remove debug log for LLDP packet sending
        # logger.debug(f"Sent LLDP packet: switch={datapath.id}, port={port_no}")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        """Handle switch join event"""
        switch = ev.switch
        dpid = switch.dp.id
        
        # Update switch information
        self.switches[dpid] = switch
        self.datapaths[dpid] = switch.dp
        
        # Initialize port states
        for port in switch.ports:
            self.port_states[(dpid, port.port_no)] = True
        
        # Log event
        logger.info(f"Switch entered: dpid={dpid}")
        
        # Update topology state
        self.topology_changed = True
        
        # Install default flow table
        self.install_default_flows(switch.dp)
        
        # Send LLDP probes
        self._send_lldp_probes()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        """Handle switch leave event"""
        dpid = ev.switch.dp.id
        
        # Clean up switch-related information
        if dpid in self.switches:
            del self.switches[dpid]
        if dpid in self.datapaths:
            del self.datapaths[dpid]
            
        # Clean up related port states
        for port_key in list(self.port_states.keys()):
            if port_key[0] == dpid:
                del self.port_states[port_key]
        
        # Clean up related links
        self.links = [link for link in self.links 
                     if link.src.dpid != dpid and link.dst.dpid != dpid]
        
        # Log event
        logger.info(f"Switch left: dpid={dpid}")
        
        # Update topology state
        self.topology_changed = True

    def update_link_state(self, src_dpid, dst_dpid, src_port_no, dst_port_no, is_up):
        """Update link state"""
        try:
            # Standardize link representation (ensure source DPID is smaller than destination DPID)
            if src_dpid > dst_dpid:
                src_dpid, dst_dpid = dst_dpid, src_dpid
                src_port_no, dst_port_no = dst_port_no, src_port_no
            
            # Removed frequent link state update debug log
            
            # Ensure self.links is a list
            if not isinstance(self.links, list):
                logger.warning("self.links is not a list, resetting")
                self.links = []
            
            if is_up:
                # Validate if link is valid
                if not self._validate_link(src_dpid, dst_dpid, src_port_no, dst_port_no):
                    logger.warning(f"Link validation failed: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
                    return False

                # Check if link already exists
                link_exists = any(
                    (link.src.dpid == src_dpid and link.src.port_no == src_port_no and
                     link.dst.dpid == dst_dpid and link.dst.port_no == dst_port_no)
                    for link in self.links
                )

                if not link_exists:
                    # Create new link object
                    class LinkPort:
                        def __init__(self, dpid, port_no):
                            self.dpid = dpid
                            self.port_no = port_no

                    class Link:
                        def __init__(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
                            self.src = LinkPort(src_dpid, src_port_no)
                            self.dst = LinkPort(dst_dpid, dst_port_no)

                    # Add link
                    new_link = Link(src_dpid, src_port_no, dst_dpid, dst_port_no)
                    self.links.append(new_link)
                    
                    # Update port states
                    self.port_states[(src_dpid, src_port_no)] = True
                    self.port_states[(dst_dpid, dst_port_no)] = True
                    
                    logger.info(f"Successfully added new link: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
                    self.topology_changed = True
                    self._notify_topology_change()
            else:
                # Remove link
                links_to_remove = []
                for link in self.links:
                    # Standardize link comparison
                    link_src_dpid = link.src.dpid
                    link_dst_dpid = link.dst.dpid
                    link_src_port = link.src.port_no
                    link_dst_port = link.dst.port_no
                    
                    if link_src_dpid > link_dst_dpid:
                        link_src_dpid, link_dst_dpid = link_dst_dpid, link_src_dpid
                        link_src_port, link_dst_port = link_dst_port, link_src_port
                    
                    if (link_src_dpid == src_dpid and link_src_port == src_port_no and
                        link_dst_dpid == dst_dpid and link_dst_port == dst_port_no):
                        links_to_remove.append(link)
                
                if links_to_remove:
                    for link in links_to_remove:
                        if link in self.links:
                            self.links.remove(link)
                            logger.info(f"Successfully removed link: {link.src.dpid}:{link.src.port_no} -> {link.dst.dpid}:{link.dst.port_no}")
                    
                    # Update port states
                    self.port_states[(src_dpid, src_port_no)] = False
                    self.port_states[(dst_dpid, dst_port_no)] = False
                    
                    self.topology_changed = True
                    self._notify_topology_change()
                else:
                    # Removed frequent link removal debug log
                    pass

            return True
            
        except Exception as e:
            logger.error(f"Error updating link state: {str(e)}")
            return False

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        """Handle link add event"""
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port_no = link.src.port_no
        dst_port_no = link.dst.port_no
        
        logger.info(f"Detected link add event: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
        
        # Update port states directly (OpenFlow handles port configuration automatically)
        self.port_states[(src_dpid, src_port_no)] = True
        self.port_states[(dst_dpid, dst_port_no)] = True
            
        # 2. Update link state
        if self.update_link_state(src_dpid, dst_dpid, src_port_no, dst_port_no, True):
            logger.info(f"Link added successfully: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
            
            # 3. Send LLDP probes to confirm link state
            if src_dpid in self.datapaths and dst_dpid in self.datapaths:
                src_dp = self.datapaths[src_dpid]
                dst_dp = self.datapaths[dst_dpid]
                src_hw_addr = self._get_port_hw_addr(src_dpid, src_port_no)
                dst_hw_addr = self._get_port_hw_addr(dst_dpid, dst_port_no)
                
                if src_hw_addr and dst_hw_addr:
                    self._send_lldp_packet(src_dp, src_port_no, src_hw_addr)
                    self._send_lldp_packet(dst_dp, dst_port_no, dst_hw_addr)
                    # Removed frequent LLDP probe confirmation log
        else:
            logger.error(f"Failed to add link: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")

    # Removed complex path management methods - using simple learning switch is sufficient
    # The packet_in_handler already implements MAC learning which provides adequate forwarding

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        """Handle link delete event"""
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port_no = link.src.port_no
        dst_port_no = link.dst.port_no
        
        logger.info(f"Detected link delete event: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
        
        # Update port states directly
        self.port_states[(src_dpid, src_port_no)] = False
        self.port_states[(dst_dpid, dst_port_no)] = False
        
        # 2. Update link state
        if self.update_link_state(src_dpid, dst_dpid, src_port_no, dst_port_no, False):
            logger.info(f"Link deleted successfully: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
            
            # 3. Delete related flow tables
            self._remove_flow_tables(src_dpid, dst_dpid, src_port_no, dst_port_no)
        else:
            logger.error(f"Failed to delete link: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")

    def _configure_port(self, dpid, port_no, is_up):
        """Simplified port state management - just update local cache"""
        if dpid not in self.datapaths:
            logger.error(f"Switch {dpid} not connected to controller")
            return False
        
        # Update port state cache
        self.port_states[(dpid, port_no)] = is_up
        # Removed frequent port state cache update log
        
        # If port is enabled, install necessary flow tables
        if is_up and dpid in self.datapaths:
            self._install_port_flows(self.datapaths[dpid], port_no)
        
        return True

    def _get_port_hw_addr(self, dpid, port_no):
        """Get port MAC address"""
        if dpid in self.switches:
            switch = self.switches[dpid]
            for port in switch.ports:
                if port.port_no == port_no:
                    return port.hw_addr
        return None

    # Removed unused method _update_flow_tables - functionality replaced by _install_path_flows

    def _remove_flow_tables(self, src_dpid, dst_dpid, src_port_no, dst_port_no):
        """Delete flow tables related to the link"""
        # Delete source switch flow table
        if src_dpid in self.datapaths:
            self._remove_flow_entry(self.datapaths[src_dpid], src_port_no)
            
        # Delete destination switch flow table
        if dst_dpid in self.datapaths:
            self._remove_flow_entry(self.datapaths[dst_dpid], dst_port_no)

    def _add_flow_entry(self, datapath, in_port, out_port):
        """Add flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match incoming port
        match = parser.OFPMatch(in_port=in_port)
        
        # Set action to forward to output port
        actions = [parser.OFPActionOutput(out_port)]
        
        # Add flow entry
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD)
            
        datapath.send_msg(mod)
        logger.info(f"Flow entry added: dpid={datapath.id}, in_port={in_port}, out_port={out_port}")

    def _remove_flow_entry(self, datapath, port):
        """Remove flow entries related to specified port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match incoming or outgoing port
        match = parser.OFPMatch(in_port=port)
        
        # Remove flow entries
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match)
            
        datapath.send_msg(mod)
        logger.info(f"Flow entries removed for port: dpid={datapath.id}, port={port}")

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        """Handle host addition event"""
        host = ev.host
        mac = host.mac
        dpid = host.port.dpid
        port_no = host.port.port_no
        
        # Update host information
        self.hosts[mac] = {
            'mac': mac,
            'dpid': dpid,
            'port': port_no,
            'ip': None,  # IP will be updated when packet is received
            'last_seen': time.time()
        }
        
        # Update port state
        self.port_states[(dpid, port_no)] = True
        
        # Log event
        logger.info(f"Host added: mac={mac}, dpid={dpid}, port={port_no}")
        
        # Mark topology change
        self.topology_changed = True
        
        # Send ARP request to get IP address
        if dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            # Get port MAC address
            port_mac = None
            if dpid in self.switches:
                switch = self.switches[dpid]
                for port in switch.ports:
                    if port.port_no == port_no:
                        port_mac = port.hw_addr
                        break
            
            if port_mac:
                self._send_arp_request(datapath, port_no, port_mac, None)  # Broadcast ARP request
            else:
                logger.warning(f"Could not find MAC address for port {port_no} on switch {dpid}")

    @set_ev_cls(event.EventHostDelete)
    def host_delete_handler(self, ev):
        """Handle host removal event"""
        host = ev.host
        mac = host.mac
        dpid = host.port.dpid
        port_no = host.port.port_no
        
        # Log event
        logger.info(f"Host removed: mac={mac}, dpid={dpid}, port={port_no}")
        
        # Remove host information
        if mac in self.hosts:
            del self.hosts[mac]
            
            # Clean related IP mappings
            for ip, known_mac in list(self.ip_to_mac.items()):
                if known_mac == mac:
                    del self.ip_to_mac[ip]
            
            # Update port state
            self.port_states[(dpid, port_no)] = False
            
            # Mark topology change
            self.topology_changed = True
            
            # Notify topology change
            self._notify_topology_change()
            
            logger.info(f"Successfully removed host {mac} from topology")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection initialization"""
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        
        # Install basic flow table rules
        self.install_default_flows(datapath)

    def install_default_flows(self, datapath):
        """Install default flow table rules"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install LLDP packet handling rule
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        # Install ARP packet handling rule
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """Helper method to add flow entry"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                               match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Handle LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            try:
                self._handle_lldp(datapath, in_port, pkt)
            except Exception as e:
                logger.error(f"Error handling LLDP packet: {e}")
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn source MAC address and corresponding port
        self.mac_to_port[dpid][src] = in_port

        # Update host information
        if not self._is_multicast(src):
            # Get IP address
            ip_addr = None
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                ip_addr = pkt_ipv4.src
            else:
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp:
                    ip_addr = pkt_arp.src_ip

            # Update host information
            if src not in self.hosts:
                self.hosts[src] = {
                    'dpid': dpid,
                    'port': in_port,
                    'mac': src,
                    'ip': ip_addr,
                    'last_seen': time.time(),
                    'is_active': True
                }
            else:
                self.hosts[src]['last_seen'] = time.time()
                self.hosts[src]['is_active'] = True
                if ip_addr:
                    self.hosts[src]['ip'] = ip_addr
                    self.ip_to_mac[ip_addr] = src

        # If destination MAC is known, add flow entry
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If not broadcast and destination port is known, add flow entry
        if dst != 'ff:ff:ff:ff:ff:ff' and out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_lldp(self, datapath, in_port, pkt):
        """Handle received LLDP packet"""
        try:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            if not lldp_pkt:
                return
                
            tlvs = lldp_pkt.tlvs
            chassis_id = port_id = None
            
            for tlv in tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    chassis_id = str(tlv.chassis_id.decode('utf-8'))
                elif isinstance(tlv, lldp.PortID):
                    port_id = str(tlv.port_id.decode('utf-8'))

            if chassis_id and port_id:
                try:
                    src_dpid = int(chassis_id)
                    src_port_no = int(port_id)
                    dst_dpid = datapath.id
                    dst_port_no = in_port
                    
                    # Standardize link direction (use smaller DPID as source)
                    if src_dpid > dst_dpid:
                        src_dpid, dst_dpid = dst_dpid, src_dpid
                        src_port_no, dst_port_no = dst_port_no, src_port_no
                    
                    # Update LLDP timestamp for the link
                    link_key = (src_dpid, src_port_no, dst_dpid, dst_port_no)
                    self.lldp_timestamps[link_key] = time.time()
                    
                    # Check if link already exists
                    link_exists = any(
                        (link.src.dpid == src_dpid and link.src.port_no == src_port_no and
                         link.dst.dpid == dst_dpid and link.dst.port_no == dst_port_no)
                        for link in self.links
                    )
                    
                    if not link_exists:
                        logger.info(f"LLDP discovered new link: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
                        self.update_link_state(src_dpid, dst_dpid, src_port_no, dst_port_no, True)
                    
                except ValueError as e:
                    logger.error(f"Failed to parse LLDP values: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing LLDP packet: {e}")

    # Removed unused method _handle_lldp_link - functionality integrated into _handle_lldp

    # Removed unused method _update_host_info - functionality integrated into _packet_in_handler

    def _get_ip_from_packet(self, pkt):
        """Extract IP address from packet"""
        # Try to get from IPv4 packet
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            return pkt_ipv4.src
            
        # Try to get from ARP packet
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            return pkt_arp.src_ip
            
        return None

    def _is_multicast(self, mac):
        """Check if MAC address is multicast"""
        return (mac.startswith('01:00:5e') or  # IPv4 multicast
                mac.startswith('33:33') or     # IPv6 multicast
                mac.startswith('01:80:c2') or  # IEEE 802.1D/Q
                mac == 'ff:ff:ff:ff:ff:ff')    # Broadcast

    def _send_arp_request(self, datapath, port_no, port_mac, target_ip):
        """Send ARP request to discover hosts"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct ARP request packet
        pkt = packet.Packet()
        eth = ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',  # Broadcast
            src=port_mac,             # Use port's MAC address
            ethertype=ether_types.ETH_TYPE_ARP)
        
        # If target_ip is None, use broadcast address
        dst_ip = target_ip if target_ip is not None else '255.255.255.255'
        
        arp_req = arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=port_mac,         # Use port's MAC address
            src_ip='10.0.0.254',      # Use a fixed source IP
            dst_mac='00:00:00:00:00:00',
            dst_ip=dst_ip)
        
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        # Send ARP request
        actions = [parser.OFPActionOutput(port_no)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        
        datapath.send_msg(out)

    # Removed unused method _discover_hosts - functionality integrated into _active_scan

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """Handle port status change event"""
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        
        if msg.reason == ofp.OFPPR_ADD:
            reason = "ADD"
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = "DELETE"
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = "MODIFY"
        else:
            reason = "UNKNOWN"
            
        port_no = msg.desc.port_no
        port_state = msg.desc.state
        is_live = port_state & ofp.OFPPS_LINK_DOWN == 0
        hw_addr = msg.desc.hw_addr
        
        logger.info(f"Port status changed: dpid={dp.id}, port={port_no}, reason={reason}, state={port_state}, is_live={is_live}")
        
        # Update port state
        self.port_states[(dp.id, port_no)] = is_live
        
        # If port is deleted, check for connected hosts
        if msg.reason == ofp.OFPPR_DELETE:
            # Find hosts connected to this port
            hosts_to_remove = []
            for mac, host in self.hosts.items():
                if host['dpid'] == dp.id and host['port'] == port_no:
                    hosts_to_remove.append(mac)
            
            # Remove these hosts
            for mac in hosts_to_remove:
                self._handle_host_removal(mac)
                logger.info(f"Host removed due to port deletion: mac={mac}")
        
        # If new port is added, configure it and send LLDP probe
        if msg.reason == ofp.OFPPR_ADD and is_live:
            # Configure port
            self._configure_port(dp.id, port_no, True)
            
            # Install default flows
            self._install_port_flows(dp, port_no)
            
            # Send LLDP probe (delayed to avoid startup flood)
            if hw_addr:
                def delayed_lldp():
                    hub.sleep(1)  # Wait before sending LLDP
                    self._send_lldp_packet(dp, port_no, hw_addr)
                    logger.info(f"Sent LLDP probe to new port: dpid={dp.id}, port={port_no}")
                hub.spawn(delayed_lldp)
        
        # Handle link state changes
        self._handle_port_status_change(dp.id, port_no, is_live)
        
        # Trigger topology update
        self.topology_changed = True

    def _install_port_flows(self, datapath, port_no):
        """Install necessary flows for new port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install LLDP handling rule
        match = parser.OFPMatch(in_port=port_no, eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        # Install ARP handling rule
        match = parser.OFPMatch(in_port=port_no, eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        # Install default forwarding rule (low priority)
        match = parser.OFPMatch(in_port=port_no)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        logger.info(f"Installed flows for port: dpid={datapath.id}, port={port_no}")

    def _handle_port_status_change(self, dpid, port_no, is_live):
        """Handle link changes due to port status change"""
        # Find all links related to this port
        affected_links = []
        for link in self.links:
            if ((link.src.dpid == dpid and link.src.port_no == port_no) or
                (link.dst.dpid == dpid and link.dst.port_no == port_no)):
                affected_links.append(link)
        
        if not is_live:  # Port down
            for link in affected_links:
                src_dpid = link.src.dpid
                dst_dpid = link.dst.dpid
                src_port = link.src.port_no
                dst_port = link.dst.port_no
                logger.info(f"Link removed due to port down: {src_dpid}:{src_port} -> {dst_dpid}:{dst_port}")
                self.update_link_state(src_dpid, dst_dpid, src_port, dst_port, False)
        else:  # Port up
            # Resend LLDP probes
            if dpid in self.datapaths:
                datapath = self.datapaths[dpid]
                hw_addr = self._get_port_hw_addr(dpid, port_no)
                if hw_addr:
                    logger.info(f"Port restored, sending LLDP probe: dpid={dpid}, port={port_no}")
                    self._send_lldp_packet(datapath, port_no, hw_addr)
                    # Install necessary flows
                    self._install_port_flows(datapath, port_no)
                    
                    # Schedule lighter host rediscovery on this port (only for known subnet)
                    logger.info(f"Scheduling host discovery for restored port: dpid={dpid}, port={port_no}")
                    # Only send ARP requests for a limited range and with delay
                    def delayed_host_discovery():
                        hub.sleep(2)  # Wait for port to stabilize
                        for i in range(1, 11):  # Only scan first 10 IPs
                            target_ip = f'10.0.0.{i}'
                            self._send_arp_request(datapath, port_no, hw_addr, target_ip)
                            hub.sleep(0.1)  # Slower ARP requests
                    
                    # Start discovery in background
                    hub.spawn(delayed_host_discovery)

    def get_port_speed(self, dpid, port_no):
        """Get port speed information
        
        Args:
            dpid: Switch ID
            port_no: Port number
            
        Returns:
            int: Port speed in bps, or None if unavailable
        """
        try:
            if dpid not in self.switches:
                return None
                
            switch = self.switches[dpid]
            for port in switch.ports:
                if port.port_no == port_no:
                    # Try to get port speed information
                    if hasattr(port, 'curr'):  # OpenFlow 1.3 uses curr attribute
                        return port.curr
                    elif hasattr(port, 'curr_speed'):  # Some versions may use curr_speed
                        return port.curr_speed
                    elif hasattr(port, 'max_speed'):  # Fallback to max speed
                        return port.max_speed
            return None
            
        except Exception as e:
            logger.error(f"Error getting port speed for switch {dpid} port {port_no}: {e}")
            return None

    def get_topology_data(self):
        """Generate standardized topology data"""
        # If no switch information, return empty topology
        if not self.switches:
            logger.warning("No switch information, returning empty topology")
            return {
                'switches': [],
                'links': [],
                'hosts': []
            }

        # Get switch information with traffic statistics
        switches = []
        for dpid, switch in self.switches.items():
            ports = []
            for port in switch.ports:
                if port.port_no != ofproto_v1_3.OFPP_LOCAL:
                    # Get port traffic statistics
                    port_traffic = {}
                    if dpid in self.port_stats and port.port_no in self.port_stats[dpid]:
                        port_stats = self.port_stats[dpid][port.port_no]
                        port_traffic = {
                            'rx_packets': port_stats.get('rx_packets', 0),
                            'tx_packets': port_stats.get('tx_packets', 0),
                            'rx_bytes': port_stats.get('rx_bytes', 0),
                            'tx_bytes': port_stats.get('tx_bytes', 0),
                            'rx_throughput': port_stats.get('rx_throughput', 0),
                            'tx_throughput': port_stats.get('tx_throughput', 0),
                            'rx_dropped': port_stats.get('rx_dropped', 0),
                            'tx_dropped': port_stats.get('tx_dropped', 0),
                            'rx_errors': port_stats.get('rx_errors', 0),
                            'tx_errors': port_stats.get('tx_errors', 0)
                        }
                    
                    port_data = {
                        'port_no': port.port_no,
                        'hw_addr': str(port.hw_addr),
                        'is_live': self.port_states.get((dpid, port.port_no), True),
                        'traffic': port_traffic
                    }
                    ports.append(port_data)
            switches.append({
                'dpid': dpid,
                'ports': ports
            })

        # Sort switch list
        switches = sorted(switches, key=lambda x: x['dpid'])

        # Only process links related to existing switches
        valid_links = []
        for link in self.links:
            if (link.src.dpid in self.switches and 
                link.dst.dpid in self.switches):
                valid_links.append(link)

        # Get link information
        links = []
        seen_links = set()  # For deduplication

        for link in valid_links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            # Get traffic statistics for both directions of the link
            src_traffic = {}
            if src_dpid in self.port_stats and src_port in self.port_stats[src_dpid]:
                src_stats = self.port_stats[src_dpid][src_port]
                src_traffic = {
                    'rx_throughput': src_stats.get('rx_throughput', 0),
                    'tx_throughput': src_stats.get('tx_throughput', 0),
                    'rx_bytes': src_stats.get('rx_bytes', 0),
                    'tx_bytes': src_stats.get('tx_bytes', 0)
                }

            dst_traffic = {}
            if dst_dpid in self.port_stats and dst_port in self.port_stats[dst_dpid]:
                dst_stats = self.port_stats[dst_dpid][dst_port]
                dst_traffic = {
                    'rx_throughput': dst_stats.get('rx_throughput', 0),
                    'tx_throughput': dst_stats.get('tx_throughput', 0),
                    'rx_bytes': dst_stats.get('rx_bytes', 0),
                    'tx_bytes': dst_stats.get('tx_bytes', 0)
                }

            # Calculate total link throughput (bidirectional)
            total_throughput = src_traffic.get('tx_throughput', 0) + dst_traffic.get('tx_throughput', 0)

            # Only add link in one direction, using smaller dpid as source
            if src_dpid <= dst_dpid:
                link_key = (src_dpid, dst_dpid, src_port, dst_port)
                if link_key not in seen_links:
                    links.append({
                        'src': {'dpid': src_dpid, 'port_no': src_port, 'traffic': src_traffic},
                        'dst': {'dpid': dst_dpid, 'port_no': dst_port, 'traffic': dst_traffic},
                        'total_throughput': total_throughput
                    })
                    seen_links.add(link_key)
            else:
                link_key = (dst_dpid, src_dpid, dst_port, src_port)
                if link_key not in seen_links:
                    links.append({
                        'src': {'dpid': dst_dpid, 'port_no': dst_port, 'traffic': dst_traffic},
                        'dst': {'dpid': src_dpid, 'port_no': src_port, 'traffic': src_traffic},
                        'total_throughput': total_throughput
                    })
                    seen_links.add(link_key)

        # Sort links
        links.sort(key=lambda x: (x['src']['dpid'], x['dst']['dpid'], x['src']['port_no']))
        
        # Get host information (with filtering logic)
        valid_hosts = []
        current_time = time.time()
        
        for mac, host in self.hosts.items():
            if host['dpid'] in self.switches:
                # Validate IP address
                ip = host.get('ip', '')
                if (ip and 
                    ip != 'unknown' and 
                    ip != '10.0.0.254' and  # Exclude ARP probe source IP
                    self._is_valid_ipv4(ip)):  # Validate IP format
                    
                    last_seen_time = host.get('last_seen', current_time)
                    is_active = (current_time - last_seen_time) < self.host_timeout
                    port_status = self.port_states.get((host['dpid'], host['port']), True)
                    port_speed = self.get_port_speed(host['dpid'], host['port'])
                    
                    # Get host traffic statistics from connected switch port
                    host_traffic = {}
                    if host['dpid'] in self.port_stats and host['port'] in self.port_stats[host['dpid']]:
                        port_stats = self.port_stats[host['dpid']][host['port']]
                        host_traffic = {
                            'rx_throughput': port_stats.get('rx_throughput', 0),
                            'tx_throughput': port_stats.get('tx_throughput', 0),
                            'rx_bytes': port_stats.get('rx_bytes', 0),
                            'tx_bytes': port_stats.get('tx_bytes', 0),
                            'rx_packets': port_stats.get('rx_packets', 0),
                            'tx_packets': port_stats.get('tx_packets', 0)
                        }
                    
                    host_data = {
                        'mac': mac,
                        'dpid': host['dpid'],
                        'port': host['port'],
                        'ip': ip,
                        'last_seen': last_seen_time,
                        'is_active': is_active,
                        'port_status': port_status,
                        'port_speed': port_speed,
                        'traffic': host_traffic
                    }
                    valid_hosts.append(host_data)

        # Sort host list by MAC address
        valid_hosts.sort(key=lambda x: x['mac'])

        topology_data = {
            'switches': switches,
            'links': links,
            'hosts': valid_hosts,
            'traffic_stats': {
                'flow_stats': self.flow_stats.copy(),
                'port_stats': self.port_stats.copy(),
                'timestamp': time.time()
            }
        }
        
        # Removed frequent topology data generation log
        return topology_data

    def _is_valid_ipv4(self, ip):
        """Validate IPv4 address format
        
        Args:
            ip: IP address string
            
        Returns:
            bool: Whether the IP is valid IPv4
        """
        try:
            # Split IP address
            parts = ip.split('.')
            # Check if there are 4 parts
            if len(parts) != 4:
                return False
            # Check each part is a number between 0-255
            return all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def _validate_link(self, src_dpid, dst_dpid, src_port_no, dst_port_no):
        """Validate if link is valid"""
        # Check if switches exist
        if src_dpid not in self.switches:
            logger.warning(f"Source switch not found: dpid={src_dpid}")
            return False
        if dst_dpid not in self.switches:
            logger.warning(f"Destination switch not found: dpid={dst_dpid}")
            return False
            
        # Check if ports exist
        src_switch = self.switches[src_dpid]
        dst_switch = self.switches[dst_dpid]
        
        src_port_exists = any(port.port_no == src_port_no for port in src_switch.ports)
        if not src_port_exists:
            logger.warning(f"Source port not found: dpid={src_dpid}, port={src_port_no}")
            return False
            
        dst_port_exists = any(port.port_no == dst_port_no for port in dst_switch.ports)
        if not dst_port_exists:
            logger.warning(f"Destination port not found: dpid={dst_dpid}, port={dst_port_no}")
            return False
                
        return True

    def _handle_host_removal(self, mac):
        """Handle host removal"""
        if mac in self.hosts:
            host_info = self.hosts[mac]
            logger.info(f"Host removed: mac={mac}, ip={host_info.get('ip')}")
            
            # Remove host information
            del self.hosts[mac]
            
            # Clean related IP mappings
            for ip, known_mac in list(self.ip_to_mac.items()):
                if known_mac == mac:
                    del self.ip_to_mac[ip]
            
            # Mark topology change
            self.topology_changed = True
            
            # Notify topology change
            self._notify_topology_change()
            
            logger.info(f"Successfully removed host {mac} from topology")

    def _check_host_connectivity(self, mac):
        """Check host connectivity"""
        if mac not in self.hosts:
            return False
            
        host = self.hosts[mac]
        if not host.get('is_active'):
            return False
            
        # Check port state
        port_key = (host['dpid'], host['port'])
        if port_key not in self.port_states or not self.port_states[port_key]:
            return False
            
        return True

    # Removed unused validation methods _validate_switch_config and _validate_port_config

    # Removed unused method _notify_port_state_change - functionality integrated into port_status_handler

    def _handle_port_up(self, dpid, port_no):
        """Handle port restoration event"""
        # Resend LLDP probes
        if dpid in self.datapaths:
            switch = self.switches[dpid]
            for port in switch.ports:
                if port.port_no == port_no:
                    self._send_lldp_packet(self.datapaths[dpid], port_no, port.hw_addr)
                    break

    def _notify_topology_change(self):
        """Notify topology changes to all WebSocket clients"""
        if not self.ws_clients:
            # Removed frequent WebSocket client connection log
            return
            
        try:
            # Get latest topology data
            topology_data = self.get_topology_data()
            
            # Construct notification message
            message = {
                'type': 'topology_update',
                'data': topology_data
            }
            
            # Send to all WebSocket clients
            active_clients = 0
            for ws_client in list(self.ws_clients):
                try:
                    ws_client.send_message(json.dumps(message))
                    active_clients += 1
                except Exception as e:
                    logger.error(f"Failed to send topology update to client: {str(e)}")
                    self.ws_clients.discard(ws_client)
                    
            if active_clients > 0:
                # Only log if there are multiple clients connected
                if active_clients > 1:
                    logger.debug(f"Sent topology update to {active_clients} clients")
            
        except Exception as e:
            logger.error(f"Failed to notify topology change: {str(e)}")