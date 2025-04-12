#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length = "100",
            senderWindow = "5",
            timeout = "300",
            recvTimeout = "100"
    ):
        self.net = net
        self.blasteeIp = IPv4Address(blasteeIp)
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = int(timeout)
        self.recvTimeout = int(recvTimeout)
        self.waitreforward = list()
        self.Acked = dict()
        self.pktbuffer = dict()
        self.clock = time.time()
        self.starttime = time.time()
        self.left = 1
        self.right = 1
        self.Number_of_reTX = 0
        self.Number_of_coarse_TOs = 0

    def forward(self):
        if len(self.waitreforward) > 0:
            log_info("Refoward")
            self.net.send_packet('blaster-eth0', self.pktbuffer[self.waitreforward[0]])
            self.waitreforward.pop(0)
            return
        if self.right - self.left == self.senderWindow:
            log_info("Window full")
            return
        if self.right > self.num:
            log_info("Right largest")
            return
        log_info("Newfoward")
        pkt = Ethernet() + IPv4() + UDP()
        pkt[0].src = '10:00:00:00:00:01'
        pkt[0].dst = '40:00:00:00:00:01'
        pkt[0].ethertype = EtherType.IPv4
        pkt[1].src = '192.168.100.1'
        pkt[1].dst = '192.168.200.1'
        pkt[1].protocol = IPProtocol.UDP
        pkt[1].ttl = 64
        pkt += RawPacketContents(self.right.to_bytes(4, 'big') + self.length.to_bytes(2, 'big') + (0).to_bytes(self.length, 'big'))
        self.net.send_packet('blaster-eth0', pkt)
        self.Acked[self.right] = False
        self.pktbuffer[self.right] = pkt
        self.right = self.right + 1

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        log_info("Blaster : I got a packet")
        _, fromIface, packet = recv
        order = int.from_bytes(packet[3].to_bytes()[0:4], 'big')
        self.Acked[order] = True
        if order == self.left:
            while self.left < self.right and self.Acked[self.left]:
                self.pktbuffer.pop(self.left)
                self.left = self.left + 1
            self.clock = time.time()
        self.forward()


    def handle_no_packet(self):
        log_info("Blaster : Didn't receive anything")
        if (time.time() - self.clock) > (float(self.timeout) / 1000):
            for i in range(self.left, self.right):
                if not self.Acked[i]:
                    self.waitreforward.append(i)
                    self.Number_of_reTX = self.Number_of_reTX + 1
            self.clock = time.time()
            self.Number_of_coarse_TOs = self.Number_of_coarse_TOs + 1
        self.forward()

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(self.recvTimeout / 1000)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
            if self.left > self.num:
                break
        Total_TX_time = time.time() - self.starttime
        print(f'Total_TX_time : {Total_TX_time}')
        print(f'Number_of_reTX : {self.Number_of_reTX}')
        print(f'Number_of_coarse_TOs : {self.Number_of_coarse_TOs}')
        print(f'Throughput : {float((self.num + self.Number_of_reTX) * self.length) / Total_TX_time}')
        print(f'Goodput : {float(self.num * self.length) / Total_TX_time}')
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()

def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
