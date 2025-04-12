#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class Packetforwarding:
    def __init__(self, net, packet, intf, next, lasttime, count):
        self.net = net
        self.packet = packet
        self.intf = intf
        self.next = next
        self.lasttime = lasttime
        self.count = count
    def forwardarp(self, macdst):
        self.packet[0].src = self.intf.ethaddr
        self.packet[0].dst = macdst
        self.net.send_packet(self.intf, self.packet)


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.myrecordarp = dict()
        self.myrecordforward = dict()
        self.firstwait = dict()
        self.ipwait = dict()

    def longestmatch(self, addr):
        maxlen = 0
        forward = None
        next = None
        for item in self.myrecordforward.keys():
            if addr in item and item.prefixlen > maxlen:
                forward = item
                maxlen = item.prefixlen
        if maxlen > 0:
            if self.myrecordforward[forward][0] != IPv4Address('0.0.0.0'):
                next = self.myrecordforward[forward][0]
            else:
                next = addr    
        return [maxlen, forward, next]
    
    def forwardipv4(self, packet, forward, next):
        my_interfaces = self.net.interfaces()
        if next in self.myrecordarp.keys():
            for intf in my_interfaces:
                if self.myrecordforward[forward][1] == str(intf.name):
                    packet[0].src = intf.ethaddr
                    packet[0].dst = self.myrecordarp[next]
                    packet[0].ethertype = EtherType.IPv4
                    self.net.send_packet(intf, packet)
        else:
            for intf in my_interfaces:
                if self.myrecordforward[forward][1] == str(intf.name):
                    packet[0].src = intf.ethaddr
                    tmppacket = Packetforwarding(self.net, packet, intf, next, time.time(), 5)
                    if next in list(self.firstwait.keys()):
                        self.ipwait[next].append(tmppacket)
                    else:
                        ask = create_ip_arp_request(intf.ethaddr, intf.ipaddr, next)
                        self.net.send_packet(intf, ask)
                        tmppacket.count = tmppacket.count - 1
                        self.firstwait[next] = tmppacket
                        self.ipwait[next] = [tmppacket]
    
    def check_or_timeout(self):
        for item in list(self.firstwait.keys()):
            tmp = self.firstwait[item]
            if time.time() - tmp.lasttime > 1.0:
                if tmp.count > 0:
                    ask = create_ip_arp_request(tmp.intf.ethaddr, tmp.intf.ipaddr, tmp.next)
                    self.net.send_packet(tmp.intf, ask)
                    tmp.lasttime = time.time()
                    tmp.count = tmp.count - 1
                    self.firstwait[item] = tmp
                else:
                    self.firstwait.pop(item)
                    self.ipwait.pop(item)
        
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        my_interfaces = self.net.interfaces()
        eth = packet.get_header(Ethernet)
        myname = [intf.name for intf in my_interfaces]
        myip = [intf.ipaddr for intf in my_interfaces]
        if str(ifaceName) not in myname:
            return
        interface = self.net.interface_by_name(ifaceName)
        if eth.dst != interface.ethaddr and eth.dst != "ff:ff:ff:ff:ff:ff":
            return
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        if eth.ethertype == EtherType.IPv4 and ipv4:
            if 14 + packet[IPv4].total_length != packet.size():
                return
            packet[1].ttl = packet[1].ttl - 1
            if packet[1].dst in myip:
                return
            else:
                [maxlen, forward, next] = self.longestmatch(packet[1].dst)
                if maxlen > 0:
                    self.forwardipv4(packet, forward, next)
        elif eth.ethertype == EtherType.ARP and arp:
            if arp.operation == ArpOperation.Request:
                for intf in my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:
                        answer = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, answer)
                        self.myrecordarp[arp.senderprotoaddr] = arp.senderhwaddr
            else:
                for intf in my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr and arp.senderhwaddr != 'ff:ff:ff:ff:ff:ff':
                        if arp.senderprotoaddr in list(self.ipwait.keys()):
                            for item in self.ipwait[arp.senderprotoaddr]:
                                item.forwardarp(arp.senderhwaddr)
                            if arp.senderprotoaddr in list(self.firstwait.keys()):
                                self.firstwait.pop(arp.senderprotoaddr)
                            self.ipwait.pop(arp.senderprotoaddr)
                        self.myrecordarp[arp.senderprotoaddr] = arp.senderhwaddr          
            
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            ipaddr = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            key = IPv4Network(str(ipaddr) + '/' + str(intf.netmask))
            self.myrecordforward[key] = [IPv4Address('0.0.0.0'), str(intf.name)]
        with open("forwarding_table.txt") as file:
            for line in file:
                entry = line.rsplit()
                if entry:
                    key = IPv4Network(entry[0] + '/' + entry[1])
                    self.myrecordforward[key] = [IPv4Address(entry[2]), entry[3]]
        while True:
            handle = True
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                handle = False
            except Shutdown:
                break
            if handle:
                self.handle_packet(recv)
            self.check_or_timeout()
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