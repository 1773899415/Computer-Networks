#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        self.blasterIp = IPv4Address(blasterIp)
        self.num = int(num)
    
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_info(f"Blastee : I got a packet from {fromIface} Pkt: {packet}")
        log_info("answer ACK")
        ACK = Ethernet() + IPv4() + UDP()
        ACK[0].src = '20:00:00:00:00:01'
        ACK[0].dst = '40:00:00:00:00:02'
        ACK[0].ethertype = EtherType.IPv4
        ACK[1].src = '192.168.200.1'
        ACK[1].dst = '192.168.100.1'
        ACK[1].protocol = IPProtocol.UDP
        ACK[1].ttl = 64
        ACK += RawPacketContents(packet[3].to_bytes()[0:4])
        len = int.from_bytes(packet[3].to_bytes()[4:6], 'big')
        if len >= 8:
            ACK += RawPacketContents(packet[3].to_bytes()[6:14])
        else:
            ACK += RawPacketContents(packet[3].to_bytes()[6:6 + len] + (0).to_bytes(8 - len, 'big'))
        self.net.send_packet(fromIface, ACK)

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout = 1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()

def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()