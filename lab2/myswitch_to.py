'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''

import switchyard
import time
from switchyard.lib.userlib import *

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    learndist = dict()
    timestamp = dict()
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        for mac in list(learndist.keys()):
            if time.time() - timestamp[mac] > 10:
                learndist.pop(mac)
                timestamp.pop(mac)
        if eth.src not in learndist.keys():
            learndist[eth.src] = fromIface
        timestamp[eth.src] = time.time()
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in learndist.keys():
                for intf in my_interfaces:
                    if learndist[eth.dst] == intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
    net.shutdown()

