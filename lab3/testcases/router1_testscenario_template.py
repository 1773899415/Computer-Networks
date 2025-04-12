#!/usr/bin/env python

from switchyard.lib.userlib import *
from copy import deepcopy

def mk_arpreq(hwsrc, ipsrc, ipdst):
    arp_req = Arp()
    arp_req.operation = ArpOperation.Request
    arp_req.senderprotoaddr = IPAddr(ipsrc)
    arp_req.targetprotoaddr = IPAddr(ipdst)
    arp_req.senderhwaddr = EthAddr(hwsrc)
    arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr("ff:ff:ff:ff:ff:ff")
    ether.ethertype = EtherType.ARP
    return ether + arp_req

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply

def arp_tests():
    s = TestScenario("ARP reply tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    # Your tests here

    testpkt1 = mk_arpreq(
        '11:11:11:11:11:11',
        '10.10.0.2',
        "10.10.0.1",
    )
    s.expect(
        PacketInputEvent("router-eth1", testpkt1,  display=Ethernet),
        ("ARPrequest should arrive on router-eth1")
    )

    testpkt2 = mk_arpresp(
        testpkt1,
        "10:00:00:00:00:02"
    )
    s.expect(
        PacketOutputEvent("router-eth1", testpkt2, display=Ethernet),
        ("ARPreply should forward from eth1")
    )

    testpkt3 = mk_arpreq(
        '11:11:11:11:11:11',
        '10.10.0.2',
        "192.168.1.5",
    )
    s.expect(
        PacketInputEvent("router-eth1", testpkt3,  display=Ethernet),
        ("ARPrequest should arrive on router-eth1")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("The router should do nothing")
    )

    return s

scenario = arp_tests()
