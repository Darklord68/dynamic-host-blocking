import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib import hub

WHITELIST = {'10.0.0.1', '10.0.0.4', '10.0.0.254'}
SERVER_PORT = 9000
BLOCK_PRIO = 100
FLOW_PRIO = 10
BLOCK_SECS = 30


class BlockingSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked = {}
        self.conn_times = {}
        self.detector = None   # Member 3 plugs detector here later
        self.logf = open('events.log', 'a')
        hub.spawn(self._stats_loop)

    # ---------- logging ----------
    def log_event(self, kind, **fields):
        extra = ' '.join(f'{k}={v}' for k, v in fields.items())
        line = f"[{time.strftime('%H:%M:%S')}] EVENT={kind} {extra}"
        print(line, flush=True)
        self.logf.write(line + '\n')
        self.logf.flush()

    # ---------- flow helpers ----------
    def add_flow(self, dp, prio, match, actions, idle=0, hard=0, flags=0):
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                 instructions=inst, idle_timeout=idle,
                                 hard_timeout=hard, flags=flags))

    def packet_out(self, dp, msg, in_port, out_port):
        p = dp.ofproto_parser
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port,
                                   actions=[p.OFPActionOutput(out_port)],
                                   data=msg.data))

    # ---------- block / unblock ----------
    def block_host(self, dp, ip, secs=BLOCK_SECS):
        if ip in WHITELIST:
            self.log_event('BLOCK', host=ip, reason='whitelisted-skipped')
            return
        ofp, p = dp.ofproto, dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        self.add_flow(dp, BLOCK_PRIO, match, [], hard=secs,
                      flags=ofp.OFPFF_SEND_FLOW_REM)
        self.blocked[ip] = time.time() + secs
        self.log_event('BLOCK', host=ip, reason=f'drop-rule-{secs}s')

    def unblock_host(self, dp, ip):
        ofp, p = dp.ofproto, dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        dp.send_msg(p.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                                 priority=BLOCK_PRIO, match=match,
                                 out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
        self.blocked.pop(ip, None)
        self.log_event('UNBLOCK', host=ip, reason='manual')

    # ---------- switch setup ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.add_flow(dp, 0, p.OFPMatch(),
                      [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

    # ---------- packet-in ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == 0x86dd:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)

        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        if ip and t:
            # count only new connections to the server (SYN without ACK)
            if (t.dst_port == SERVER_PORT and (t.bits & tcp.TCP_SYN)
                    and not (t.bits & tcp.TCP_ACK)):
                self.on_connection(dp, ip.src)
            if out_port != ofp.OFPP_FLOOD:
                match = p.OFPMatch(eth_type=0x0800, ipv4_src=ip.src,
                                   ipv4_dst=ip.dst, ip_proto=6,
                                   tcp_src=t.src_port, tcp_dst=t.dst_port)
                self.add_flow(dp, FLOW_PRIO, match,
                              [p.OFPActionOutput(out_port)], idle=10)
        self.packet_out(dp, msg, in_port, out_port)

    def on_connection(self, dp, ip):
        now = time.time()
        if ip in WHITELIST or ip in self.blocked:
            return
        if self.detector:
            self.detector.on_connection(ip, now)
            return
        q = self.conn_times.setdefault(ip, [])
        q.append(now)
        q[:] = [x for x in q if now - x <= 5]
        if len(q) >= 15:
            self.log_event('DETECT', host=ip, reason='15 conns in 5s')
            self.block_host(dp, ip, BLOCK_SECS)
            q.clear()

    # ---------- expiry ----------
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        if msg.priority != BLOCK_PRIO:
            return
        ip = msg.match.get('ipv4_src')
        self.blocked.pop(ip, None)
        if msg.reason == msg.datapath.ofproto.OFPRR_HARD_TIMEOUT:
            self.log_event('EXPIRE', host=ip, reason='hard_timeout')

    # ---------- stats every 2 s ----------
    def _stats_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(2)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        per = {}
        for st in ev.msg.body:
            ip = st.match.get('ipv4_src')
            if ip and st.priority == FLOW_PRIO:
                per[ip] = per.get(ip, 0) + st.packet_count
        for ip, pk in per.items():
            self.log_event('STATS', host=ip, packets=pk)

