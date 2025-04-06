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

logger = logging.getLogger(__name__)

class TopologyMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.switches = {}      # dpid -> Switch 对象
        self.links = []         # 存储所有链路信息
        self.hosts = {}         # mac -> 主机信息
        self.datapaths = {}     # dpid -> datapath
        self.port_states = {}   # (dpid, port_no) -> is_live
        self.gateway_macs = set()  # 存储网关MAC地址
        
        # 注册REST API
        wsgi = kwargs['wsgi']
        wsgi.register(TopologyController, {'topology_monitor': self})
        
        # 启动监控线程
        self.monitor_thread = hub.spawn(self._monitor)
        self.discovery_thread = hub.spawn(self._active_scan)

        self.host_timeout = 300  # 增加主机超时时间到5分钟
        self.discovery_interval = 60  # 主动发现间隔为1分钟

        self.ip_to_mac = {}     # 添加 IP 到 MAC 的映射
        self.pending_hosts = {} # 存储等待 IP 的主机

        self.mac_to_port = {}  # 添加 MAC 到端口的映射

        # 添加新的属性来跟踪拓扑变化
        self.last_topology = None  # 存储上一次的拓扑信息
        self.topology_changed = False  # 标记拓扑是否发生变化

    def _is_topology_changed(self, new_topology):
        """比较拓扑是否发生变化"""
        if self.last_topology is None:
            logger.info("First topology data")
            return True
            
        logger.debug(f"Comparing topology:\nOld: {json.dumps(self.last_topology, indent=2)}\nNew: {json.dumps(new_topology, indent=2)}")
        
        # 比较交换机数量和端口状态
        if len(new_topology['switches']) != len(self.last_topology['switches']):
            logger.info("Switch number changed")
            return True

        # 将交换机按dpid排序后比较
        new_switches = sorted(new_topology['switches'], key=lambda x: x['dpid'])
        old_switches = sorted(self.last_topology['switches'], key=lambda x: x['dpid'])
        
        for new_sw, old_sw in zip(new_switches, old_switches):
            if new_sw['dpid'] != old_sw['dpid']:
                logger.info(f"Switch DPID changed: {new_sw['dpid']} != {old_sw['dpid']}")
                return True
                
            # 将端口按port_no排序后比较
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

        # 比较链路数量和状态
        if len(new_topology['links']) != len(self.last_topology['links']):
            logger.info("Link number changed")
            return True

        # 将链路标准化并排序后比较
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

        # 比较主机信息
        if len(new_topology['hosts']) != len(self.last_topology['hosts']):
            logger.info("Host number changed")
            return True

        # 将主机按MAC地址排序后比较
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
        """定期监控拓扑变化"""
        while True:
            try:
                # 首先更新交换机信息
                switch_list = get_switch(self.topology_api_app, None)
                if not switch_list:
                    logger.warning("No switches found")
                    hub.sleep(1)  # 如果没有交换机，短暂等待后重试
                    continue
                
                self.switches = {sw.dp.id: sw for sw in switch_list}
                
                # 然后更新链路信息
                links = get_link(self.topology_api_app, None)
                self.links = links
                
                # 清理无效的主机信息
                self._cleanup_hosts()
                
                # 获取当前拓扑信息
                current_topology = self.get_topology_data()
                
                # 检查拓扑是否发生变化
                if self._is_topology_changed(current_topology):
                    self.last_topology = current_topology
                    self.topology_changed = True
                    logger.info("Network topology changed detected")
                
            except Exception as e:
                logger.error(f"Monitor error: {str(e)}")
            
            hub.sleep(10)  # 每10秒检查一次

    def _active_scan(self):
        """主动扫描主机"""
        while True:
            try:
                self._discover_hosts()
            except Exception as e:
                logger.error(f"Active scan error: {str(e)}")
            hub.sleep(10)

    def _cleanup_hosts(self):
        """清理无效的主机信息"""
        hosts_to_remove = []
        for mac, host in self.hosts.items():
            port_key = (host['dpid'], host['port'])
            # 只有当端口down时才移除主机信息
            if not self.port_states.get(port_key, True):  # 端口down
                hosts_to_remove.append(mac)
                logger.info(f"Host {mac} removed due to port down")
        
        for mac in hosts_to_remove:
            del self.hosts[mac]
            # 清理相关的IP映射
            for ip, known_mac in list(self.ip_to_mac.items()):
                if known_mac == mac:
                    del self.ip_to_mac[ip]

    def _send_lldp_probes(self):
        """发送 LLDP 探测包"""
        for dpid, switch in self.switches.items():
            if dpid not in self.datapaths:
                continue
            datapath = self.datapaths[dpid]
            for port in switch.ports:
                port_key = (dpid, port.port_no)
                if (port.port_no != datapath.ofproto.OFPP_LOCAL and
                    self.port_states.get(port_key, True)):
                    self._send_lldp_packet(datapath, port.port_no, port.hw_addr)

    def _send_lldp_packet(self, datapath, port_no, hw_addr):
        """发送 LLDP 包到指定端口"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet()
        
        # 添加以太网头
        pkt.add_protocol(ethernet.ethernet(
            dst='01:80:c2:00:00:0e',
            src=hw_addr,
            ethertype=ether_types.ETH_TYPE_LLDP))

        # 添加 LLDP 包，使用字符串格式
        chassis_id = str(datapath.id).encode()
        port_id = str(port_no).encode()
        
        pkt.add_protocol(lldp.lldp(
            tlvs=[
                lldp.ChassisID(
                    subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                    chassis_id=chassis_id),
                lldp.PortID(
                    subtype=lldp.PortID.SUB_PORT_COMPONENT,
                    port_id=port_id),
                lldp.TTL(ttl=120),
                lldp.End()
            ]
        ))

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

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        """处理交换机加入事件"""
        switch = ev.switch
        dpid = switch.dp.id
        
        # 更新交换机信息
        self.switches[dpid] = switch
        self.datapaths[dpid] = switch.dp
        
        # 初始化端口状态
        for port in switch.ports:
            self.port_states[(dpid, port.port_no)] = True
        
        # 记录日志
        logger.info(f"Switch entered: dpid={dpid}")
        
        # 更新拓扑状态
        self.topology_changed = True
        
        # 安装默认流表
        self.install_default_flows(switch.dp)
        
        # 发送LLDP探测包
        self._send_lldp_probes()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        """处理交换机离开事件"""
        dpid = ev.switch.dp.id
        
        # 清理交换机相关信息
        if dpid in self.switches:
            del self.switches[dpid]
        if dpid in self.datapaths:
            del self.datapaths[dpid]
            
        # 清理相关的端口状态
        for port_key in list(self.port_states.keys()):
            if port_key[0] == dpid:
                del self.port_states[port_key]
        
        # 清理相关的链路
        self.links = [link for link in self.links 
                     if link.src.dpid != dpid and link.dst.dpid != dpid]
        
        # 记录日志
        logger.info(f"Switch left: dpid={dpid}")
        
        # 更新拓扑状态
        self.topology_changed = True

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        """处理链路添加事件"""
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port_no = link.src.port_no
        dst_port_no = link.dst.port_no
        
        # 更新端口状态
        self.port_states[(src_dpid, src_port_no)] = True
        self.port_states[(dst_dpid, dst_port_no)] = True
        
        # 记录日志
        logger.info(f"Link added: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")
        
        # 更新拓扑状态
        self.topology_changed = True
        
        # 发送LLDP探测包以确认链路状态
        self._send_lldp_probes()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        """处理链路删除事件"""
        link = ev.link
        logger.info(f"Link deleted: {link.src.dpid}:{link.src.port_no} -> {link.dst.dpid}:{link.dst.port_no}")
        # 从 self.links 中移除链路
        self.links = [l for l in self.links if (
            l.src.dpid != link.src.dpid or
            l.src.port_no != link.src.port_no or
            l.dst.dpid != link.dst.dpid or
            l.dst.port_no != link.dst.port_no
        )]

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        """处理主机添加事件"""
        host = ev.host
        mac = host.mac
        dpid = host.port.dpid
        port_no = host.port.port_no
        
        # 更新主机信息
        self.hosts[mac] = {
            'mac': mac,
            'dpid': dpid,
            'port': port_no,
            'ip': None,  # IP地址将在收到数据包时更新
            'last_seen': time.time()
        }
        
        # 更新端口状态
        self.port_states[(dpid, port_no)] = True
        
        # 记录日志
        logger.info(f"Host added: mac={mac}, dpid={dpid}, port={port_no}")
        
        # 更新拓扑状态
        self.topology_changed = True
        
        # 发送ARP请求以获取IP地址
        if dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            self._send_arp_request(datapath, port_no, None)  # 广播ARP请求

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """交换机连接初始化"""
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        
        # 安装基本流表规则
        self.install_default_flows(datapath)

    def install_default_flows(self, datapath):
        """安装默认流表规则"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 安装 table-miss 流表项
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # 安装 LLDP 包处理规则
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        # 安装 ARP 包处理规则
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """添加流表项的辅助方法"""
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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # 学习源MAC地址和对应端口
        self.mac_to_port[dpid][src] = in_port

        # 更新主机信息
        if not self._is_multicast(src):
            # 获取IP地址
            ip_addr = None
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                ip_addr = pkt_ipv4.src
            else:
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp:
                    ip_addr = pkt_arp.src_ip

            # 更新主机信息
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

        # 如果目的MAC地址已知，添加流表项
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # 如果不是广播包且目的端口已知，则添加流表项
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

    def _update_host_info(self, mac, dpid, port, pkt):
        """更新主机信息"""
        # 检查是否是新的主机
        is_new_host = mac not in self.hosts
        
        # 获取IP地址
        ip = self._get_ip_from_packet(pkt)
        
        # 更新主机信息
        if is_new_host:
            self.hosts[mac] = {
                'mac': mac,
                'dpid': dpid,
                'port': port,
                'ip': ip,
                'last_seen': time.time()
            }
            logger.info(f"New host detected: mac={mac}, ip={ip}, dpid={dpid}, port={port}")
        else:
            # 检查IP是否发生变化
            old_ip = self.hosts[mac].get('ip')
            if ip and ip != old_ip:
                logger.info(f"Host IP changed: mac={mac}, old_ip={old_ip}, new_ip={ip}")
                self.hosts[mac]['ip'] = ip
            
            # 更新最后发现时间
            self.hosts[mac]['last_seen'] = time.time()
            
            # 如果端口发生变化，更新端口信息
            if self.hosts[mac]['port'] != port:
                logger.info(f"Host port changed: mac={mac}, old_port={self.hosts[mac]['port']}, new_port={port}")
                self.hosts[mac]['port'] = port
        
        # 更新IP到MAC的映射
        if ip:
            self.ip_to_mac[ip] = mac
        
        # 更新拓扑状态
        self.topology_changed = True

    def _get_ip_from_packet(self, pkt):
        """从数据包中提取IP地址"""
        # 尝试从 IPv4 包获取
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            return pkt_ipv4.src
            
        # 尝试从 ARP 包获取
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            return pkt_arp.src_ip
            
        return None

    def _handle_lldp_link(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
        """处理 LLDP 发现的链路"""
        # 只处理 dpid 1-3 的交换机
        if not (1 <= src_dpid <= 3 and 1 <= dst_dpid <= 3):
            return

        # 检查是否已存在相同的链路
        for link in self.links:
            if ((link.src.dpid == src_dpid and link.src.port_no == src_port_no and
                 link.dst.dpid == dst_dpid and link.dst.port_no == dst_port_no) or
                (link.src.dpid == dst_dpid and link.src.port_no == dst_port_no and
                 link.dst.dpid == src_dpid and link.dst.port_no == src_port_no)):
                return

        # 创建新的链路对象
        class Link:
            def __init__(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
                self.src = type('LinkPort', (), {'dpid': src_dpid, 'port_no': src_port_no})
                self.dst = type('LinkPort', (), {'dpid': dst_dpid, 'port_no': dst_port_no})

        # 添加新链路
        link = Link(src_dpid, src_port_no, dst_dpid, dst_port_no)
        self.links.append(link)
        logger.info(f"New link added: {src_dpid}:{src_port_no} -> {dst_dpid}:{dst_port_no}")

    def _is_multicast(self, mac):
        """检查是否是多播地址"""
        return (mac.startswith('01:00:5e') or  # IPv4 多播
                mac.startswith('33:33') or     # IPv6 多播
                mac.startswith('01:80:c2') or  # IEEE 802.1D/Q
                mac == 'ff:ff:ff:ff:ff:ff')    # 广播

    def _send_arp_request(self, datapath, port, target_ip):
        """发送 ARP 请求以发现主机"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 构造 ARP 请求包
        pkt = packet.Packet()
        eth = ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',  # 广播
            src=port.hw_addr,         # 使用端口的 MAC 地址
            ethertype=ether_types.ETH_TYPE_ARP)
        arp_req = arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=port.hw_addr,     # 使用端口的 MAC 地址
            src_ip='10.0.0.254',      # 使用一个固定的源 IP
            dst_mac='00:00:00:00:00:00',
            dst_ip=target_ip)
        
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_req)
        pkt.serialize()

        # 发送 ARP 请求
        actions = [parser.OFPActionOutput(port.port_no)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        
        datapath.send_msg(out)

    def _discover_hosts(self):
        """主动发现主机"""
        current_time = time.time()
        
        # 检查并标记不活跃的主机
        for mac, host in self.hosts.items():
            if current_time - host['last_seen'] > self.host_timeout:
                if host.get('is_active', True):
                    host['is_active'] = False
                    logger.info(f"Host {mac} marked as inactive")
            elif not host.get('is_active', True):
                host['is_active'] = True
                logger.info(f"Host {mac} is active again")

        # 对每个交换机的每个端口发送 ARP 请求
        for dpid, switch in self.switches.items():
            if dpid not in self.datapaths:
                continue
            datapath = self.datapaths[dpid]
            
            # 获取已知的活跃主机 IP
            known_ips = set()
            for host in self.hosts.values():
                if host.get('is_active') and host.get('ip'):
                    known_ips.add(host['ip'])
            
            # 对每个端口发送 ARP 请求
            for port in switch.ports:
                if port.port_no != datapath.ofproto.OFPP_LOCAL:
                    # 发送 ARP 请求到可能的主机 IP
                    for i in range(1, 255):  # 扫描整个子网
                        target_ip = f'10.0.0.{i}'
                        if target_ip not in known_ips:
                            self._send_arp_request(datapath, port, target_ip)
                            hub.sleep(0.1)  # 添加短暂延迟避免发送太快

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """处理端口状态变化事件"""
        dpid = ev.msg.datapath.id
        ports = ev.msg.body
        
        for port in ports:
            port_no = port.port_no
            port_key = (dpid, port_no)
            is_live = port.state == 0  # 0表示端口UP
            
            # 检查端口状态是否发生变化
            if port_key in self.port_states and self.port_states[port_key] != is_live:
                if is_live:
                    logger.info(f"Port {port_no} on switch {dpid} is up")
                    # 端口恢复，重新发送LLDP探测
                    if dpid in self.datapaths:
                        self._send_lldp_packet(self.datapaths[dpid], port_no, port.hw_addr)
                else:
                    logger.info(f"Port {port_no} on switch {dpid} is down")
                    self._handle_port_down(dpid, port_no)
            
            # 更新端口状态
            self.port_states[port_key] = is_live
            
        # 更新拓扑状态
        self.topology_changed = True

    def _handle_port_down(self, dpid, port_no):
        """处理端口断开事件"""
        # 移除连接到该端口的主机
        hosts_to_remove = []
        for mac, host in self.hosts.items():
            if host['dpid'] == dpid and host['port'] == port_no:
                hosts_to_remove.append(mac)
        
        for mac in hosts_to_remove:
            del self.hosts[mac]
            logger.info(f"Removed host with MAC {mac} due to port down")

        # 移除涉及该端口的链路
        links_to_remove = []
        for link in self.links:
            if ((link.src.dpid == dpid and link.src.port_no == port_no) or
                (link.dst.dpid == dpid and link.dst.port_no == port_no)):
                links_to_remove.append(link)
        
        for link in links_to_remove:
            if link in self.links:
                self.links.remove(link)
                logger.info(f"Removed link {link.src.dpid}:{link.src.port_no} -> "
                          f"{link.dst.dpid}:{link.dst.port_no} due to port down")

    def get_topology_data(self):
        """生成标准化拓扑数据"""
        # 如果没有交换机信息，返回空拓扑
        if not self.switches:
            logger.warning("No switches found, returning empty topology")
            return {
                'switches': [],
                'links': [],
                'hosts': []
            }

        # 获取所有交换机端口的 MAC 地址
        switch_port_macs = set()
        for switch in self.switches.values():
            for port in switch.ports:
                switch_port_macs.add(str(port.hw_addr))

        # 获取交换机信息
        switches = []
        for dpid, switch in self.switches.items():
            ports = []
            for port in switch.ports:
                if port.port_no != ofproto_v1_3.OFPP_LOCAL:
                    port_data = {
                        'port_no': port.port_no,
                        'hw_addr': str(port.hw_addr),
                        'is_live': self.port_states.get((dpid, port.port_no), True)
                    }
                    ports.append(port_data)
            switches.append({
                'dpid': dpid,
                'ports': ports
            })

        # 对交换机列表排序
        switches = sorted(switches, key=lambda x: x['dpid'])
        for switch in switches:
            # 对每个交换机的端口列表排序
            switch['ports'] = sorted(switch['ports'], key=lambda x: x['port_no'])

        # 只处理与现有交换机相关的链路
        valid_links = []
        for link in self.links:
            if (link.src.dpid in self.switches and 
                link.dst.dpid in self.switches):
                valid_links.append(link)

        # 获取链路信息
        links = []
        seen_links = set()  # 用于去重
        seen_ports = set()  # 用于检查端口是否已被使用

        for link in valid_links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            # 检查端口是否已被使用
            src_port_key = (src_dpid, src_port)
            dst_port_key = (dst_dpid, dst_port)

            # 如果端口已被使用，跳过这个链路
            if src_port_key in seen_ports or dst_port_key in seen_ports:
                continue

            # 记录已使用的端口
            seen_ports.add(src_port_key)
            seen_ports.add(dst_port_key)

            # 标准化链路方向（小ID指向大ID）
            if src_dpid > dst_dpid:
                src_dpid, dst_dpid = dst_dpid, src_dpid
                src_port, dst_port = dst_port, src_port

            link_key = (src_dpid, dst_dpid)
            if link_key not in seen_links:
                link_data = {
                    'src': {'dpid': src_dpid, 'port_no': src_port},
                    'dst': {'dpid': dst_dpid, 'port_no': dst_port}
                }
                links.append(link_data)
                seen_links.add(link_key)
                logger.debug(f"Added link: {src_dpid}:{src_port} -> {dst_dpid}:{dst_port}")

        # 对链路进行排序
        links.sort(key=lambda x: (x['src']['dpid'], x['src']['port_no']))

        # 只包含连接到现有交换机的主机
        valid_hosts = []
        for mac, host in self.hosts.items():
            if (host['dpid'] in self.switches and
                mac not in self.gateway_macs and 
                mac not in switch_port_macs and
                not any(mac.startswith(prefix) for prefix in ['01:', '33:', 'ff:']) and
                host.get('is_active', True) and
                host.get('ip') != '10.0.0.254'):
                
                host_data = {
                    'mac': mac,
                    'dpid': host['dpid'],
                    'port': host['port'],
                    'ip': host.get('ip', 'unknown'),
                    'last_seen': float(host['last_seen'])
                }
                valid_hosts.append(host_data)

        topology_data = {
            'switches': switches,
            'links': links,
            'hosts': valid_hosts
        }
        
        logger.debug(f"Generated topology data: {json.dumps(topology_data, indent=2)}")
        return topology_data

class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.topology_monitor = data['topology_monitor']

    @route('topology', '/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        """REST API：返回完整拓扑数据"""
        try:
            # 获取当前拓扑数据
            current_topology = self.topology_monitor.get_topology_data()
            
            # 检查是否强制获取
            force = req.GET.get('force', 'false').lower() == 'true'
            
            if force or self.topology_monitor.topology_changed:
                self.topology_monitor.topology_changed = False
                logger.info("Sending topology data (forced or changed)")
            elif not current_topology['switches']:
                logger.warning("No switches found")
                return Response(status=204)
            
            # 返回拓扑数据
            return Response(
                content_type='application/json',
                body=json.dumps(current_topology, indent=2).encode('utf-8')
            )
                
        except Exception as e:
            logger.error(f"API Error: {str(e)}", exc_info=True)
            return Response(status=500, 
                          body=json.dumps({'error': str(e)}).encode('utf-8'))