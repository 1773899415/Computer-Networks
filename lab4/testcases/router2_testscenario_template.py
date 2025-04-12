#!/usr/bin/env python

from switchyard.lib.userlib import *
from copy import deepcopy

def get_raw_pkt(pkt, xlen):
    pkt = deepcopy(pkt)
    i = pkt.get_header_index(Ethernet)
    if i >= 0:
        del pkt[i]
    b = pkt.to_bytes()[:xlen]
    return b

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

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
        icmppkt.icmpcode = ICMPCodeEchoReply.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
        icmppkt.icmpcode = ICMPCodeEchoRequest.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 

def forward_tests():
    s = TestScenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
''')

    nottinyttl = '''lambda pkt: pkt.get_header(IPv4).ttl >= 8'''

    # Your tests here
    testpkt1 = mk_ping(
        "11:11:11:11:11:11",
        "10:00:00:00:00:01",
        "192.168.1.5",
        "172.16.64.1",
        False,
        64,
        ''
    )
    s.expect(
        PacketInputEvent("router-eth0", testpkt1, display=Ethernet),
        ("Ping should arrive on router-eth1")
    )
    testpkt2 = mk_arpreq(
        '10:00:00:00:00:02',
        "10.10.0.1",
        "10.10.1.254"
    )
    s.expect(
        PacketOutputEvent("router-eth1", testpkt2,  display=Ethernet),
        ("ARPrequest should leave from router-eth1")
    )
    testpkt3 = mk_arpresp(
        testpkt2,
        "22:22:22:22:22:22"
    )
    s.expect(
        PacketInputEvent("router-eth1", testpkt3,  display=Ethernet),
        ("ARPreply should arrive on router-eth1")
    )
    testpkt4 = mk_ping(
        "10:00:00:00:00:02",
        "22:22:22:22:22:22",
        "192.168.1.5",
        "172.16.64.1",
        False,
        63,
        ''
    )
    s.expect(
        PacketOutputEvent("router-eth1", testpkt4,  display=Ethernet),
        ("Ping should leave from router-eth1")
    )

    testpkt5 = mk_ping(
        "11:11:11:11:11:11",
        "10:00:00:00:00:01",
        "192.168.1.5",
        "192.168.1.1",
        False,
        64,
        ''
    )
    s.expect(
        PacketInputEvent("router-eth0", testpkt5, display=Ethernet),
        ("Ping should arrive on router-eth0")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("The router should do nothing")
    )

    return s

scenario = forward_tests()
