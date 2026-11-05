
                # Reverse-direction flow: send the reply back
                # through the port on which the original packet arrived.
                rmatch = p.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip.dst,
                    ipv4_dst=ip.src,
                    ip_proto=6,
                    tcp_src=t.dst_port,
                    tcp_dst=t.src_port
                )

                self.add_flow(
                    dp,
                    FLOW_PRIO,
                    rmatch,
                    [p.OFPActionOutput(in_port)],
                    idle=10
                )

        self.packet_out(
            dp,
            msg,
            in_port,
            out_port
        )

    # ---------- connection detection ----------
    def on_connection(self, dp, ip):

        # Disable detection when mode is none
        if self.mode == 'none':
            return

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

            self.log_event(
                'DETECT',
                host=ip,
                reason='15 conns in 5s'
            )

            self.block_host(dp, ip, BLOCK_SECS)
            q.clear()

    # ---------- expiry ----------
    @set_ev_cls(
        ofp_event.EventOFPFlowRemoved,
        MAIN_DISPATCHER
    )
    def flow_removed_handler(self, ev):

        msg = ev.msg

        if msg.priority != BLOCK_PRIO:
            return

        ip = msg.match.get('ipv4_src')

        self.blocked.pop(ip, None)

        if self.detector:
            self.detector.on_expire(ip)

        if msg.reason == msg.datapath.ofproto.OFPRR_HARD_TIMEOUT:

            self.log_event(
                'EXPIRE',
                host=ip,
                reason='hard_timeout'
            )

    # ---------- statistics every 2 seconds ----------
    def _stats_loop(self):

        while True:

            for dp in list(self.datapaths.values()):

                dp.send_msg(
                    dp.ofproto_parser.OFPFlowStatsRequest(dp)
                )

            hub.sleep(2)

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def stats_reply_handler(self, ev):

        per = {}

        for st in ev.msg.body:

            ip = st.match.get('ipv4_src')

            if ip and st.priority == FLOW_PRIO:
                per[ip] = per.get(ip, 0) + st.packet_count

        for ip, pk in per.items():

            self.log_event(
                'STATS',
                host=ip,
                packets=pk
            )

