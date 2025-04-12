#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.myrecord = dict()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        my_interfaces = self.net.interfaces()
        arp = packet.get_header(Arp)
        for item in list(self.myrecord.keys()):
            if time.time() - self.myrecord[item][1] > 100:
                log_info (f"Delete an entry: {item} -> {self.myrecord[item][0]}")
                self.myrecord.pop(item)
        if arp is not None:
            self.myrecord[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
            log_info (f"Add an entry: {arp.senderprotoaddr} -> {arp.senderhwaddr}")
            print(self.myrecord)
            if arp.operation == 1:
                log_info (f"Router received ARP request {packet} on {ifaceName}")
                for intf in my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:
                        answer = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, answer)
                        log_info (f"Router flooding ARP reply {answer} to {intf.name}")
        
                        
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()