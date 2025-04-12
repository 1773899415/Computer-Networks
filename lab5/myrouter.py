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
        self.packet[Ethernet].src = self.intf.ethaddr
        self.packet[Ethernet].dst = macdst
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
        intf = None
        for item in self.myrecordforward.keys():
            if addr in item and item.prefixlen > maxlen:
                forward = item
                maxlen = item.prefixlen
        if maxlen > 0:
            if self.myrecordforward[forward][0] != IPv4Address('0.0.0.0'):
                next = self.myrecordforward[forward][0]
            else:
                next = addr
            intf = self.myrecordforward[forward][1]
        return [maxlen, forward, next, intf]
    
    def forwardipv4(self, packet, forward, next):
        my_interfaces = self.net.interfaces()
        if next in self.myrecordarp.keys():
            for intf in my_interfaces:
                if self.myrecordforward[forward][1] == str(intf.name):
                    packet[Ethernet].src = intf.ethaddr
                    packet[Ethernet].dst = self.myrecordarp[next]
                    packet[Ethernet].ethertype = EtherType.IPv4
                    self.net.send_packet(intf, packet)
        else:
            for intf in my_interfaces:
                if self.myrecordforward[forward][1] == str(intf.name):
                    packet[Ethernet].src = intf.ethaddr
                    tmppacket = Packetforwarding(self.net, packet, intf, next, time.time(), 5)
                    if next in list(self.firstwait.keys()):
                        self.ipwait[next].append(tmppacket)
                    else:
                        ask = create_ip_arp_request(intf.ethaddr, intf.ipaddr, next)
                        self.net.send_packet(intf, ask)
                        tmppacket.count = tmppacket.count - 1
                        self.firstwait[next] = tmppacket
                        self.ipwait[next] = [tmppacket]

    def errorjudge(self, packet):
        if packet[IPv4].protocol == IPProtocol.ICMP:
            if packet[ICMP].icmptype == ICMPType.DestinationUnreachable or packet[ICMP].icmptype == ICMPType.TimeExceeded:
                return True
        return False

    def check_or_timeout(self):
        for item1 in list(self.firstwait.keys()):
            tmp = self.firstwait[item1]
            if time.time() - tmp.lasttime > 1.0:
                if tmp.count > 0:
                    ask = create_ip_arp_request(tmp.intf.ethaddr, tmp.intf.ipaddr, tmp.next)
                    self.net.send_packet(tmp.intf, ask)
                    tmp.lasttime = time.time()
                    tmp.count = tmp.count - 1
                    self.firstwait[item1] = tmp
                else:
                    for item2 in self.ipwait[item1]:
                        if self.errorjudge(item2.packet):
                            continue
                        [maxlen, forward, next, intf] = self.longestmatch(item2.packet[IPv4].src)
                        if maxlen > 0:
                            index = item2.packet.get_header_index(Ethernet)
                            del item2.packet[index]
                            icmperror = Ethernet() + IPv4() + ICMP()
                            icmperror[IPv4].src = self.net.interface_by_name(intf).ipaddr
                            icmperror[IPv4].dst = item2.packet[IPv4].src
                            icmperror[IPv4].protocol = IPProtocol.ICMP
                            icmperror[IPv4].ttl = 64
                            icmperror[ICMP].icmptype = ICMPType.DestinationUnreachable
                            icmperror[ICMP].icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
                            icmperror[ICMP].icmpdata.data = item2.packet.to_bytes()[:28]
                            icmperror[ICMP].icmpdata.origdgramlen = len(item2.packet)
                            icmperror[IPv4]._totallen = icmperror.size() - 14
                            self.forwardipv4(icmperror, forward, next)
                    self.firstwait.pop(item1)
                    self.ipwait.pop(item1)
        
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
            if packet[IPv4].dst in myip:
                if ipv4.protocol == IPProtocol.ICMP and packet[ICMP].icmptype == ICMPType.EchoRequest:
                    [maxlen, forward, next, intf] = self.longestmatch(packet[IPv4].src)
                    if maxlen > 0:
                        icmpreply = Ethernet() + IPv4() + ICMP()
                        icmpreply[IPv4].src = packet[IPv4].dst
                        icmpreply[IPv4].dst = packet[IPv4].src
                        icmpreply[IPv4].protocol = IPProtocol.ICMP
                        icmpreply[IPv4].ttl = 64
                        icmpreply[ICMP].icmptype = ICMPType.EchoReply
                        icmpreply[ICMP].icmpdata.data = packet[ICMP].icmpdata.data
                        icmpreply[ICMP].icmpdata.identifier = packet[ICMP].icmpdata.identifier
                        icmpreply[ICMP].icmpdata.sequence = packet[ICMP].icmpdata.sequence
                        icmpreply[IPv4]._totallen = icmpreply.size() - 14
                        self.forwardipv4(icmpreply, forward, next)
                    return
                if self.errorjudge(packet):
                    return
                [maxlen, forward, next, intf] = self.longestmatch(packet[IPv4].src)
                if maxlen > 0:
                    index = packet.get_header_index(Ethernet)
                    del packet[index]
                    icmperror = Ethernet() + IPv4() + ICMP()
                    icmperror[IPv4].src = self.net.interface_by_name(intf).ipaddr
                    icmperror[IPv4].dst = packet[IPv4].src
                    icmperror[IPv4].protocol = IPProtocol.ICMP
                    icmperror[IPv4].ttl = 64
                    icmperror[ICMP].icmptype = ICMPType.DestinationUnreachable
                    icmperror[ICMP].icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
                    icmperror[ICMP].icmpdata.data = packet.to_bytes()[:28]
                    icmperror[ICMP].icmpdata.origdgramlen = len(packet)
                    icmperror[IPv4]._totallen = icmperror.size() - 14
                    self.forwardipv4(icmperror, forward, next)
                return
            [maxlen, forward, next, intf] = self.longestmatch(packet[IPv4].dst)
            if maxlen == 0:
                if self.errorjudge(packet):
                    return
                [maxlen, forward, next, intf] = self.longestmatch(packet[IPv4].src)
                if maxlen > 0:
                    index = packet.get_header_index(Ethernet)
                    del packet[index]
                    icmperror = Ethernet() + IPv4() + ICMP()
                    icmperror[IPv4].src = self.net.interface_by_name(intf).ipaddr
                    icmperror[IPv4].dst = packet[IPv4].src
                    icmperror[IPv4].protocol = IPProtocol.ICMP
                    icmperror[IPv4].ttl = 64
                    icmperror[ICMP].icmptype = ICMPType.DestinationUnreachable
                    icmperror[ICMP].icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
                    icmperror[ICMP].icmpdata.data = packet.to_bytes()[:28]
                    icmperror[ICMP].icmpdata.origdgramlen = len(packet)
                    icmperror[IPv4]._totallen = icmperror.size() - 14
                    self.forwardipv4(icmperror, forward, next)
                return
            if packet[IPv4].ttl == 0 or (packet[IPv4].ttl > 0 and packet[IPv4].ttl - 1 == 0):
                if self.errorjudge(packet):
                    return
                [maxlen, forward, next, intf] = self.longestmatch(packet[IPv4].src)
                if maxlen > 0:
                    index = packet.get_header_index(Ethernet)
                    del packet[index]
                    icmperror = Ethernet() + IPv4() + ICMP()
                    icmperror[IPv4].src = self.net.interface_by_name(intf).ipaddr
                    icmperror[IPv4].dst = packet[IPv4].src
                    icmperror[IPv4].protocol = IPProtocol.ICMP
                    icmperror[IPv4].ttl = 64
                    icmperror[ICMP].icmptype = ICMPType.TimeExceeded
                    icmperror[ICMP].icmpcode = ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired
                    icmperror[ICMP].icmpdata.data = packet.to_bytes()[:28]
                    icmperror[ICMP].icmpdata.origdgramlen = len(packet)
                    icmperror[IPv4]._totallen = icmperror.size() - 14
                    self.forwardipv4(icmperror, forward, next)
                return
            packet[IPv4].ttl = packet[IPv4].ttl - 1
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