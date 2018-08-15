import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces

# most hops
maxhop = 25

# sending a search request for falun gong
triggerfetch = "GET /search?q=Falun+Gong HTTP/1.1\nHost: www.google.com\n\n"

# id packets and helper
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

class PacketUtils:
    def __init__(self, dst=None):
        # get source ip and interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" % (self.src, self.iface, self.netmask, self.enet))
        # packet queue
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0
        self.ethrdst = ""
        # arp request for the address
        self.arp()
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # arp request help from
    # https://stackoverflow.com/questions/35348012/make-arp-request-on-python
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet, pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet with all options customizable, cant just call sendp() everytime
    # https://scapy.readthedocs.io/en/latest/usage.html
    def send_pkt(self, payload=None, ttl=32, flags="", seq=None, ack=None, sport=None, dport=80, ipid=None, dip=None,debug=False):
        # check inputs otherwise they are random
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        # set tcp and ip
        t = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src, dst=self.dst, id=ipid, ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        # Have to send as Ethernet to avoid interface issues
        e = Ether(dst=self.etherdst, type=0x0800)
        # send packet
        sendp([e/p], verbose=1, iface=self.iface)
        # cant send too many packets at the same time
        time.sleep(.05)
        return p


    # get off queue with timeout
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # sniffer = packet analyzer https://en.wikipedia.org/wiki/Packet_analyzer more info
    # needs a queue for sniffer for sniff(scapy) function
    def sniffer(self, packet):
        try:
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    # actually runs the sniffer
    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer, filter=rule, iface=self.iface, store=0)


    # Returns "DEAD" if server isn't alive, "LIVE" if teh server is alive, and
    # "FIREWALL" if it is behind the Great Firewall
    def checkfirewall(self, target):
        sp = random.randint(2000, 30000)
        self.send_pkt(flags="S", sport=sp, dip=target)
        packet = self.get_pkt()
        # check if dead connection
        if packet == None:
            return "DEAD"
        live = False
        pack = packet[IP][TCP].ack
        pseq = packet[IP][TCP].seq
        # keep up connection to check if RST is sent back
        self.send_pkt(sport = sp, flags="A", seq=pack,  ack = pseq+1, dip=target)
        self.send_pkt(payload = triggerfetch, flags = "AP", sport = sp, seq=pack,  ack = pseq+1, dip=target)
        # loop through self.get_pkt() to see if RST was given otherwise check if connection dead or alive
        packet = self.get_pkt()
        while packet != None:
            if isRST(packet):
                return "FIREWALL"
            else:
                live = True
                packet = self.get_pkt()
        if live:
            return "LIVE"
        else:
            return "DEAD"
    
    # not an actual traceroute as it also shows with an "*" 
    # whether or not there is a rst packet there
    # Returns ([], [])
    # The first list of IPs that have a hop if it exists
    # The second list whether or not there is a RST at that ip 
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol for detail on sending packet
    def traceroute(self, target, hops): 
        tempip = [None for x in range(1, hops+1)]
        temptf = [False for x in range(1, hops+1)]
        sp = random.randint(2000, 29000)
        for i in range (1, hops+1):
            rstget = False
            expget = False
            ip = None
            # 3 tries on sending packets and sets ip and rsts if it recieves once out of the 3
            for j in range(0, 3):
                sp += 1
                self.send_pkt(flags="S", sport=sp, dip=target)
                packet = self.get_pkt()
                # check is syn packet gets stuff back so it knows what to send for the ack packets
                if packet == None:
                    continue
                if TCP in packet:
                    if isRST(packet) or isICMP(packet):
                        continue
                    pack = packet[TCP].ack
                    pseq = packet[TCP].seq
                else:
                    # no TCP in packet
                    continue
                # send ack
                self.send_pkt(sport = sp, flags="A", seq=pack,  ack = pseq+1, dip=target)
                self.send_pkt(payload = triggerfetch, flags="PA", ttl = i, sport = sp, seq=pack,  ack = pseq+1, dip=target)
                # looks at received packet and checks if rst is there or not
                packet = self.get_pkt()
                while packet != None:
                    if expget and rstget:
                        break
                    if(isRST(packet)):
                        rstget = True
                    if (isTimeExceeded(packet)):
                        expget = True
                        ip = packet[IP].src
                    packet = self.get_pkt(timeout = 1)
                # sets the returns, print handled in the caller/main
                temptf[i - 1] = rstget
                tempip[i - 1] = ip 
        return (tempip, temptf)

    # packet fragmentation
    # Sends the message to the target in such a way that the target receives  msg without interference by the Great Firewall 
    # ttl is a ttl which triggers the Great Firewall but is before the server itself (use traceroute)
    # send packet with splitup payload, increments the sequence by the len of previous payload each bit of info sent
    def frag(self, target, msg, ttl):
        sp = random.randint(2000, 30000)
        pack = 0
        pseq = 0
        # handshake
        self.send_pkt(flags="S", sport=sp, dip=target)
        packet = self.get_pkt()
        if packet == None:
                return("handshake failed")
        if TCP in packet:
            if isRST(packet) or isICMP(packet):
                return("handshake failed")
            else:
                pack = packet[TCP].ack
                pseq = packet[TCP].seq
        self.send_pkt(sport = sp, flags="A", seq=pack,  ack = pseq+1, dip=target)
        #handshake complete
        totlen = 0
        # send packets
        while msg != "":
            chunk = msg[0]
            msg = msg[1:]
            # real stuff
            self.send_pkt(payload = "a", flags = "AP", sport = sp, seq=pack + totlen,  ack = pseq+1, dip=target, ttl = ttl)
            self.send_pkt(payload = "b", flags = "AP", sport = sp, seq=pack + totlen,  ack = pseq+1, dip=target, ttl = ttl)
            self.send_pkt(payload = chunk, flags = "AP", sport = sp, seq=pack + totlen,  ack = pseq+1, dip=target)
            totlen += 1
            #fake packet goes here
            self.send_pkt(payload = "aaaaa", flags = "AP", sport = sp, seq=pack + totlen,  ack = pseq+1, dip=target, ttl = ttl)
        self.send_pkt(payload = "\n\n", flags = "AP", sport = sp, seq=pack + totlen,  ack = pseq+1, dip=target)
        returnstring = ""
        packet = self.get_pkt()
        # iterates to see if rst packet was given
        while packet != None:
            if isRST(packet):
                #returnstring += "ERROR: RST RECIEVED"
                break
            if 'Raw' in packet:
                returnstring += packet['Raw'].load
            packet = self.get_pkt(1)
        return returnstring


        
 

