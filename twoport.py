from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()

c = None

def _handle_PacketIn(event):
  global c
  log.info("Parsing PacketIn.")
  if event.port == 1:
    out_port = 2
  elif event.port == 2:
    out_port = 1
  else:
    raise Exception("?")
  #msg = of.ofp_packet_out(data=event.data, in_port=of.OFPP_CONTROLLER)
  # Note: w/older ovs-openflowd, using OFPP_NONE or OFPP_CONTROLLER does
  # not seem to work, and results in an invalid argument error.
  # OFPP_NONE seems to work properly on more recent OVS versions like 1.4
  msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
  msg.actions.append(of.ofp_action_output(port = out_port, max_len = 0x2000))
  msg.buffer_id = event.ofp.buffer_id
  if not c:
    log.info("?")
  else:
    c.send(msg)

def _handle_ConnectionUp(event):
  global c
  c = event.connection


def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

  log.info("Hub running.")
