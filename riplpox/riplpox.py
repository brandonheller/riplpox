"""
RipL+POX.  As simple a data center controller as possible.
"""

import logging
import random
from struct import pack
from zlib import crc32

from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin
from pox.lib.addresses import EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp

from ripl.mn import topos

from util import buildTopo, getRouting

log = core.getLogger()

# Number of bytes to send for packet_ins
MISS_SEND_LEN = 2000

MODES = ['reactive', 'proactive', 'hybrid']
DEF_MODE = MODES[0]

IDLE_TIMEOUT = 10

HYBRID_IDLE_TIMEOUT = 0

PRIO_HYBRID_FLOW_DOWN = 1000
PRIO_HYBRID_VLAN_DOWN = 900
PRIO_HYBRID_FLOW_UP = 500
PRIO_HYBRID_VLAN_UP = 10


# Borrowed from pox/forwarding/l2_multi
class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None

  def __repr__ (self):
    return dpidToStr(self.dpid)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)

  def send_packet_data(self, outport, data = None):
    msg = of.ofp_packet_out(in_port=of.OFPP_NONE, data = data)
    msg.actions.append(of.ofp_action_output(port = outport))
    self.connection.send(msg)

  def send_packet_bufid(self, outport, buffer_id = -1):
    msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
    msg.actions.append(of.ofp_action_output(port = outport))
    msg.buffer_id = buffer_id
    self.connection.send(msg)

  def install(self, port, match, buf = -1, idle_timeout = 0, hard_timeout = 0,
              priority = of.OFP_DEFAULT_PRIORITY):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.idle_timeout = idle_timeout
    msg.hard_timeout = hard_timeout
    msg.priority = priority
    msg.actions.append(of.ofp_action_output(port = port))
    msg.buffer_id = buf
    self.connection.send(msg)

  def install_multiple(self, actions, match, buf = -1, idle_timeout = 0,
                       hard_timeout = 0, priority = of.OFP_DEFAULT_PRIORITY):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.idle_timeout = idle_timeout
    msg.hard_timeout = hard_timeout
    msg.priority = priority
    for a in actions:
      msg.actions.append(a)
    msg.buffer_id = buf
    self.connection.send(msg)

  def _handle_ConnectionDown (self, event):
    self.disconnect()
    pass


def sep():
  log.info("************************************************")

class RipLController(EventMixin):

  def __init__ (self, t, r, mode):
    self.switches = {}  # Switches seen: [dpid] -> Switch
    self.t = t  # Master Topo object, passed in and never modified.
    self.r = r  # Master Routing object, passed in and reused.
    self.mode = mode # One in MODES.
    self.macTable = {}  # [mac] -> (dpid, port)

    # TODO: generalize all_switches_up to a more general state machine.
    self.all_switches_up = False  # Sequences event handling.
    self.listenTo(core.openflow, priority=0)

  def _raw_dpids(self, arr):
    "Convert a list of name strings (from Topo object) to numbers."
    return [self.t.id_gen(name = a).dpid for a in arr]

  def _ecmp_hash(self, packet):
    "Return an ECMP-style 5-tuple hash for TCP/IP packets, otherwise 0."
    hash_input = [0] * 5
    if isinstance(packet.next, ipv4):
      ip = packet.next
      hash_input[0] = ip.srcip.toUnsigned()
      hash_input[1] = ip.dstip.toUnsigned()
      hash_input[2] = ip.protocol
      if isinstance(ip.next, tcp) or isinstance(ip.next, udp):
        l4 = ip.next
        hash_input[3] = l4.srcport
        hash_input[4] = l4.dstport
        return crc32(pack('LLHHH', *hash_input))
    return 0

  def _install_reactive_path(self, event, out_dpid, final_out_port, packet):
    "Install entries on route between two switches."
    in_name = self.t.id_gen(dpid = event.dpid).name_str()
    out_name = self.t.id_gen(dpid = out_dpid).name_str()
    hash_ = self._ecmp_hash(packet)
    route = self.r.get_route(in_name, out_name, hash_)
    log.info("route: %s" % route)
    match = of.ofp_match.from_packet(packet)
    for i, node in enumerate(route):
      node_dpid = self.t.id_gen(name = node).dpid
      if i < len(route) - 1:
        next_node = route[i + 1]
        out_port, next_in_port = self.t.port(node, next_node)
      else:
        out_port = final_out_port
      self.switches[node_dpid].install(out_port, match, idle_timeout =
                                       IDLE_TIMEOUT)

  def _src_dst_hash(self, src_dpid, dst_dpid):
    "Return a hash based on src and dst dpids."
    return crc32(pack('QQ', src_dpid, dst_dpid))

  def _install_proactive_path(self, src, dst):
    """Install entries on route between two hosts based on MAC addrs.
    
    src and dst are unsigned ints.
    """
    src_sw = self.t.up_nodes(self.t.id_gen(dpid = src).name_str())
    assert len(src_sw) == 1
    src_sw_name = src_sw[0]
    dst_sw = self.t.up_nodes(self.t.id_gen(dpid = dst).name_str())
    assert len(dst_sw) == 1
    dst_sw_name = dst_sw[0]
    hash_ = self._src_dst_hash(src, dst)
    route = self.r.get_route(src_sw_name, dst_sw_name, hash_)
    log.info("route: %s" % route)

    # Form OF match
    match = of.ofp_match()
    match.dl_src = EthAddr(src).toRaw()
    match.dl_dst = EthAddr(dst).toRaw()

    dst_host_name = self.t.id_gen(dpid = dst).name_str()
    final_out_port, ignore = self.t.port(route[-1], dst_host_name)
    for i, node in enumerate(route):
      node_dpid = self.t.id_gen(name = node).dpid
      if i < len(route) - 1:
        next_node = route[i + 1]
        out_port, next_in_port = self.t.port(node, next_node)
      else:
        out_port = final_out_port
      self.switches[node_dpid].install(out_port, match)

  def _flood(self, event):
    packet = event.parsed
    dpid = event.dpid
    #log.info("PacketIn: %s" % packet)
    in_port = event.port
    t = self.t

    # Broadcast to every output port except the input on the input switch.
    # Hub behavior, baby!
    for sw in self._raw_dpids(t.layer_nodes(t.LAYER_EDGE)):
      #log.info("considering sw %s" % sw)
      ports = []
      sw_name = t.id_gen(dpid = sw).name_str()
      for host in t.down_nodes(sw_name):
        sw_port, host_port = t.port(sw_name, host)
        if sw != dpid or (sw == dpid and in_port != sw_port):
          ports.append(sw_port)
      # Send packet out each non-input host port
      # TODO: send one packet only.
      for port in ports:
        #log.info("sending to port %s on switch %s" % (port, sw))
        #buffer_id = event.ofp.buffer_id
        #if sw == dpid:
        #  self.switches[sw].send_packet_bufid(port, event.ofp.buffer_id)
        #else:
        self.switches[sw].send_packet_data(port, event.data)
        #  buffer_id = -1

  def _handle_packet_reactive(self, event):
    packet = event.parsed
    dpid = event.dpid
    #log.info("PacketIn: %s" % packet)
    in_port = event.port
    t = self.t

    # Learn MAC address of the sender on every packet-in.
    self.macTable[packet.src] = (dpid, in_port)

    #log.info("mactable: %s" % self.macTable)

    # Insert flow, deliver packet directly to destination.
    if packet.dst in self.macTable:
      out_dpid, out_port = self.macTable[packet.dst]
      self._install_reactive_path(event, out_dpid, out_port, packet)

      #log.info("sending to entry in mactable: %s %s" % (out_dpid, out_port))
      self.switches[out_dpid].send_packet_data(out_port, event.data)

    else:
      self._flood(event)

  def _handle_packet_proactive(self, event):
    packet = event.parse()

    if packet.dst.isMulticast():
      self._flood(event)
    else:
      hosts = self._raw_dpids(self.t.layer_nodes(self.t.LAYER_HOST))
      if packet.src.toInt() not in hosts:
        raise Exception("unrecognized src: %s" % packet.src)
      if packet.dst.toInt() not in hosts:
        raise Exception("unrecognized dst: %s" % packet.dst)
      raise Exception("known host MACs but entries weren't pushed down?!?")

  # Get host index.
  def dpid_port_to_host_index(self, dpid, port):
    node = self.t.id_gen(dpid = dpid)
    return node.pod * ((self.t.k ** 2) / 4) + node.sw * (self.t.k / 2) + ((port - 2) / 2)

  def _install_hybrid_dynamic_flows(self, event, out_dpid, final_out_port, packet):
    "Install entry at ingress switch."
    in_name = self.t.id_gen(dpid = event.dpid).name_str()
    #log.info("in_name: %s" % in_name) 
    out_name = self.t.id_gen(dpid = out_dpid).name_str()
    #log.info("out_name: %s" % out_name) 
    hash_ = self._ecmp_hash(packet)
    src_dst_route = self.r.get_route(in_name, out_name, hash_)
    # Choose a random core switch.
    core_sws = sorted(self._raw_dpids(self.t.layer_nodes(self.t.LAYER_CORE)))
    core_sw = random.choice(core_sws)
    core_sw_id = self.t.id_gen(dpid = core_sw)
    core_sw_name = self.t.id_gen(dpid = core_sw).name_str()

    route = self.r.get_route(in_name, core_sw_name, None)    
    assert len(route) == 3
    log.info("route: %s" % route)

    match = of.ofp_match.from_packet(packet)

    assert core_sw_id.pod == self.t.k
    core_sw_index = ((core_sw_id.sw - 1) * 2) + (core_sw_id.host - 1)
    #log.info("core_sw_index: %s" % core_sw_index)

    dst_host_index = self.dpid_port_to_host_index(out_dpid, final_out_port)
    #log.info("dst_host_index: %s" % dst_host_index) 

    vlan = (dst_host_index << 2) + core_sw_index
    log.info("vlan: %s" % vlan) 
    log.info("len(src_dst_route): %i" % len(src_dst_route))

    if len(src_dst_route) == 1:
      # Don't bother with VLAN append; directly send to out port.
      log.info("adding edge-only entry from %s to %s on sw %s" %
               (match.dl_src, match.dl_dst, in_name))
      self.switches[event.dpid].install(final_out_port, match, idle_timeout =
                                     HYBRID_IDLE_TIMEOUT,
                                     priority = PRIO_HYBRID_FLOW_DOWN)      
    else:
      # Write VLAN and send up
      src_port, dst_port = self.t.port(route[0], route[1])
      actions = [of.ofp_action_vlan_vid(vlan_vid = vlan),
                 of.ofp_action_output(port = src_port)]
      self.switches[event.dpid].install_multiple(actions, match, idle_timeout =
                                              HYBRID_IDLE_TIMEOUT,
                                              priority = PRIO_HYBRID_FLOW_UP)

  def _handle_packet_hybrid(self, event):
    packet = event.parsed
    dpid = event.dpid
    #log.info("PacketIn: %s" % packet)
    in_port = event.port
    t = self.t

    # Learn MAC address of the sender on every packet-in.
    self.macTable[packet.src] = (dpid, in_port)
    #log.info("mactable: %s" % self.macTable)
    #log.info("learned that %s is on dpid %s, port %s" % (packet.src, dpid, in_port))

    # Insert flow, deliver packet directly to destination.
    if packet.dst in self.macTable:
      out_dpid, out_port = self.macTable[packet.dst]
      log.info("found %s on dpid %s, port %s" % (packet.dst, out_dpid, out_port))      
      self._install_hybrid_dynamic_flows(event, out_dpid, out_port, packet)

      #log.info("sending to entry in mactable: %s %s" % (out_dpid, out_port))
      self.switches[out_dpid].send_packet_data(out_port, event.data)

    else:
      self._flood(event)

  def _handle_PacketIn(self, event):
    #log.info("Parsing PacketIn.")
    if not self.all_switches_up:
      log.info("Saw PacketIn before all switches were up - ignoring.")
      return
    else:
      if self.mode == 'reactive':
        self._handle_packet_reactive(event)
      elif self.mode == 'proactive':
        self._handle_packet_proactive(event)
      elif self.mode == 'hybrid':
        self._handle_packet_hybrid(event)

  def _install_proactive_flows(self):
    t = self.t
    # Install L2 src/dst flow for every possible pair of hosts.
    for src in sorted(self._raw_dpids(t.layer_nodes(t.LAYER_HOST))):
      for dst in sorted(self._raw_dpids(t.layer_nodes(t.LAYER_HOST))):
        self._install_proactive_path(src, dst)

  def _install_hybrid_static_flows(self):
    t = self.t
    hosts = sorted(self._raw_dpids(t.layer_nodes(t.LAYER_HOST)))
    edge_sws = sorted(self._raw_dpids(t.layer_nodes(t.LAYER_EDGE)))
    agg_sws = sorted(self._raw_dpids(t.layer_nodes(t.LAYER_AGG)))
    core_sws = sorted(self._raw_dpids(t.layer_nodes(t.LAYER_CORE)))

    # For each host, add entries to that host, from each core switch.
    sep()
    #log.info("***adding down entries from each core switch")
    for host in hosts:
      host_name = self.t.id_gen(dpid = host).name_str()
      log.info("for host %i (%s)" % (host, host_name))
      for core_sw in core_sws:
        core_sw_name = self.t.id_gen(dpid = core_sw).name_str()
        log.info("for core switch  %i (%s)" % (core_sw, core_sw_name))
        route = self.r.get_route(host_name, core_sw_name, None)
        assert route[0] == host_name
        assert route[-1] == core_sw_name
        # Form OF match
        match = of.ofp_match()
        # Highest-order four bits are host index
        host_id = self.t.id_gen(dpid = host)
        k = self.t.k
        host_index = host_id.pod * k + (host_id.sw * k / 2) + (host_id.host - 2)
        # Lowest-order two bits are core switch ID
        core_sw_id = self.t.id_gen(dpid = core_sw)
        log.info("core_sw_id: %s; sw: %i host: %i" % (core_sw, core_sw_id.sw, core_sw_id.host))
        core_index = ((core_sw_id.sw - 1) * 2) + (core_sw_id.host - 1)
        vlan = (host_index << 2) + core_index
        #log.info("setting vlan to %i" % vlan)
        match.dl_vlan = vlan
        #log.info("vlan: %s" % match.dl_vlan)

        # Add one flow entry for each element on the path pointing down, except host
        for i, node in enumerate(route):  # names
          if i == 0:
            pass  # Don't install flow entries on hosts :-)
          else:
            # Install downward-facing entry
            node_dpid = self.t.id_gen(name = node).dpid
            node_below = route[i - 1]
            src_port, dst_port = self.t.port(node, node_below)
            log.info("adding entry from %s to %s via VLAN %i and port %i" %
                     (node, node_below, match.dl_vlan, src_port))
            if i == 1:
              # Strip VLAN too
              actions = [of.ofp_action_strip_vlan(),
                         of.ofp_action_output(port = src_port)]
              self.switches[node_dpid].install_multiple(actions, match,
                                                        priority = PRIO_HYBRID_VLAN_DOWN)
            elif i > 1:
              self.switches[node_dpid].install(src_port, match, priority = PRIO_HYBRID_VLAN_DOWN)


#    # Add one flow entry for each edge switch pointing up
#    sep()
#    log.info("***adding up entries from each edge switch")
#    for edge_sw in edge_sws:  # DPIDs
#      edge_sw_name = self.t.id_gen(dpid = edge_sw).name_str()
#      log.info("for edge sw %i (%s)" % (edge_sw, edge_sw_name))
#      for core_sw in core_sws:  # DPIDs
#        core_sw_name = self.t.id_gen(dpid = core_sw).name_str()
#        log.info("for core switch  %i (%s)" % (core_sw, core_sw_name))
#
#        route = self.r.get_route(edge_sw_name, core_sw_name, None)
#        assert route[0] == edge_sw_name
#        assert route[-1] == core_sw_name
#
#        # Form OF match
#        match = of.ofp_match()
#        # Highest-order four bits are host index
#
#        # Lowest-order two bits are core switch ID
#        core_sw_id = self.t.id_gen(dpid = core_sw)
#        core_index = (core_sw_id.sw - 1) * 2 + (core_sw_id.host - 1)
#
#        agg_sw_name = route[1]
#        agg_sw = self.t.id_gen(name = agg_sw_name).dpid
#
#        for host_index in range((self.t.k ** 3) / 4):
#          match.dl_vlan = (host_index << 2) + core_index
#          #log.info("vlan: %s" % match.dl_vlan)
#
#          edge_port, agg_port = self.t.port(edge_sw_name, agg_sw_name)
#          log.info("adding entry from %s to %s via VLAN %i and port %i" %
#                   (edge_sw_name, agg_sw_name, match.dl_vlan, edge_port))
#          self.switches[edge_sw].install(edge_port, match, 
#                                         priority = PRIO_HYBRID_VLAN_UP)

    # Add one flow entry for each agg switch pointing up
    sep()
    log.info("***adding up entries from each agg switch")
    for agg_sw in agg_sws:  # DPIDs
      agg_sw_name = self.t.id_gen(dpid = agg_sw).name_str()
      log.info("for agg sw %i (%s)" % (agg_sw, agg_sw_name))
      for core_sw in core_sws:  # DPIDs
        core_sw_name = self.t.id_gen(dpid = core_sw).name_str()
        log.info("for core switch  %i (%s)" % (core_sw, core_sw_name))
        if agg_sw_name in self.t.g[core_sw_name]:
            # If connected, add entry.
            agg_port, core_port = self.t.port(agg_sw_name, core_sw_name)
            
            # Form OF match
            match = of.ofp_match()
            # Highest-order four bits are host index
    
            # Lowest-order two bits are core switch ID
            core_sw_id = self.t.id_gen(dpid = core_sw)
            core_index = (core_sw_id.sw - 1) * 2 + (core_sw_id.host - 1)
    
            for host_index in range((self.t.k ** 3) / 4):
              match.dl_vlan = (host_index << 2) + core_index
              #log.info("vlan: %s" % match.dl_vlan)

              log.info("adding entry from %s to %s via VLAN %i and port %i" %
                       (agg_sw_name, core_sw_name, match.dl_vlan, agg_port))
              self.switches[agg_sw].install(agg_port, match,
                                             priority = PRIO_HYBRID_VLAN_UP)
      

  def _handle_ConnectionUp (self, event):
    sw = self.switches.get(event.dpid)
    sw_str = dpidToStr(event.dpid)
    log.info("Saw switch come up: %s", sw_str)
    name_str = self.t.id_gen(dpid = event.dpid).name_str()
    if name_str not in self.t.switches():
      log.warn("Ignoring unknown switch %s" % sw_str)
      return
    if sw is None:
      log.info("Added fresh switch %s" % sw_str)
      sw = Switch()
      self.switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      log.info("Odd - already saw switch %s come up" % sw_str)
      sw.connect(event.connection)
    sw.connection.send(of.ofp_set_config(miss_send_len=MISS_SEND_LEN))

    if len(self.switches) == len(self.t.switches()):
      log.info("Woo!  All switches up")
      self.all_switches_up = True
      if self.mode == 'proactive':
        self._install_proactive_flows()
      if self.mode == 'hybrid':
        self._install_hybrid_static_flows()


def launch(topo = None, routing = None, mode = None):
  """
  Args in format toponame,arg1,arg2,...
  """
  if not mode:
    mode = DEF_MODE
  # Instantiate a topo object from the passed-in file.
  if not topo:
    raise Exception("please specify topo and args on cmd line")
  else:
    t = buildTopo(topo, topos)
    r = getRouting(routing, t)

  core.registerNew(RipLController, t, r, mode)

  log.info("RipL-POX running with topo=%s." % topo)
