from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

def _handle_ConnectionUp(event):
    # s2 is DPID 2 - THE FIREWALL
    if event.dpid == 2:
        log.info("FIREWALL ACTIVE ON S2")
        
        # 1. ALLOW ARP (Priority 200)
        msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)

        # 2. ALLOW h1 <-> h3 (Priority 100)
        for src, dst in [("10.0.0.1", "10.0.0.3"), ("10.0.0.3", "10.0.0.1")]:
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = 0x0800
            msg.match.nw_src = IPAddr(src)
            msg.match.nw_dst = IPAddr(dst)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            event.connection.send(msg)

        # 3. DEFAULT DROP for S2 (Priority 1)
        msg = of.ofp_flow_mod()
        msg.priority = 1
        event.connection.send(msg)

    else:
        # S1 and S3 act as simple hubs
        log.info("SWITCH %s ACTING AS HUB", event.dpid)
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)