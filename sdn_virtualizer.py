# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types as ether
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_host


import logging

class Virtualizer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Virtualizer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # This function is to add a flow to drop the packets with this match (using IP addresses)
    def add_flow_ipaddr(self, datapath, ipv4_src, ipv4_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(ipv4_src=ipv4_src, 
                                ipv4_dst=ipv4_dst,
                                eth_type=ether.ETH_TYPE_IP)

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=2000,
                                match=match,
                                instructions=[])

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]        
        ip = pkt.get_protocols(ipv4.ipv4)

        if len(ip) > 0:
            ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

            self.host_add_handler(datapath, ip_src)
            self.host_add_handler(datapath, ip_dst)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)

    def wemo_group(self):
      return [
      	'10.10.4.149',
        '10.10.4.209'
    	]
    
    def tplink_group(self):
      return [
        '10.10.4.233',
        '10.10.4.248'
      ]
      
    def host_add_handler(self, datapath, ip_addr):
        if ip_addr in self.wemo_group():
            self.apply_security_policy(datapath, 'wemo_group_policy', ip_addr)
        elif ip_addr in self.tplink_group():
            self.apply_security_policy(datapath, 'tplink_group_policy', ip_addr)

    def apply_security_policy(self, datapath, policy, host):
        if policy == 'wemo_group_policy':
            for blocked_host in self.tplink_group():
                self.add_flow_ipaddr(datapath, host, blocked_host)
                self.add_flow_ipaddr(datapath, blocked_host, host)       
        elif policy == 'tplink_group_policy':
            for blocked_host in self.wemo_group():
                self.add_flow_ipaddr(datapath, host, blocked_host)
                self.add_flow_ipaddr(datapath, blocked_host, host)

    # @set_ev_cls(event.EventHostAdd)
    # def handle_host_add(self, ev):
    #     ip = ev.host.ipv4
    #     switch = get_switch(self, None)[0]
    #     print switch
    #     dp = switch.dp
    #     print dp
    #     print ip
    #     print "reached handling..."
    #     self.host_add_handler(g_dp, ip)        