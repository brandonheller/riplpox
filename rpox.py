"""
Ripcord+POX.  As simple a data center controller as possible.
"""

from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin

from ripcord.mn import topos

from util import buildTopo

log = core.getLogger()


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

  def _handle_ConnectionDown (self, event):
    self.disconnect()
    pass


class RipcordController(EventMixin):

  def __init__ (self, t):
    self.switches = {}  # Switches seen: [dpid] -> Switch
    self.t = t  # Master Topo object, passed in and never modified.
    # TODO: generalize all_switches_up to a more general state machine.
    self.all_switches_up = False  # Sequences event handling.
    self.listenTo(core.openflow, priority=0)

  def _raw_dpids(self, arr):
    "Convert a list of name strings (from Topo object) to numbers."
    return [self.t.id_gen(name = a).dpid for a in arr]

  def _handle_PacketIn(self, event):
    #log.info("Parsing PacketIn.")
    if not self.all_switches_up:
      log.info("Saw PacketIn before all switches were up - ignoring.")
      return
    else:
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

    if len(self.switches) == len(self.t.switches()):
      log.info("Woo!  All switches up")
      self.all_switches_up = True


def launch(topo = None):
  """
  Args in format toponame,arg1,arg2,...
  """
  # Instantiate a topo object from the passed-in file.
  if not topo:
    raise Exception("please specify topo and args on cmd line")
  else:
    t = buildTopo(topo, topos)

  core.registerNew(RipcordController, t)

  log.info("Ripcord running with topo=%s." % topo)
