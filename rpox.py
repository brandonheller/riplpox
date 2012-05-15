"""
Ripcord+POX.  As simple a data center controller as possible.
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.revent import EventMixin

from ripcord.mn import topos

from util import buildTopo

log = core.getLogger()


class RipcordController(EventMixin):

  def __init__ (self, t):
    self.switches_up = set([])  # Set of switches seen up.
    self.t = t  # Master Topo object, passed in and never modified.
    self.listenTo(core.openflow, priority=0)

  def _handle_ConnectionUp(self, event):
    sws = self.t.switches()
    sw = event.dpid
    sw_str = dpidToStr(sw)
    log.info("Saw switch come up: %s", sw_str)
    if sw not in sws:
      log.warn("Ignoring unknown switch %s" % sw_str)
      return
    else:
      log.info("Saw expected switch %s" % sw_str)
  
    if sw in self.switches_up:
      log.info("Odd - already saw switch %s come up.  Whatever." % sw_str)
    else:
      log.info("Added fresh switch %s." % sw_str)
      self.switches_up.add(sw)
  
    if len(self.switches_up) == len(sws):
      log.info("Woo!  All switches up.")


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
