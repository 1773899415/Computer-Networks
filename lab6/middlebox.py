#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate = "0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_info("Middlebox : Received from blaster")
            R = randint(1, 100)
            if R <= self.dropRate * 100:
                log_info("Drop")
            else:
                log_info("Forward")
                packet[Ethernet].src = '40:00:00:00:00:02'
                packet[Ethernet].dst = '20:00:00:00:00:01'
                self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_info("Middlebox : Received from blastee")
            log_info("Forward")
            packet[Ethernet].src = '40:00:00:00:00:01'
            packet[Ethernet].dst = '10:00:00:00:00:01'
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_info("Middlebox : Oops :))")

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
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()

def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()