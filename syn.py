import dpkt
import socket
import datetime
from collections import defaultdict

#Flags
ACK = 0x010
SYN = 0x002
SYNACK = 0x012
FIN = 0x01 
RST = 0x04  
PUSH = 0x08

class Suspect:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.port = defaultdict(str)
    
def synScanDetect(filePath):
    f = open(filePath,'rb')
    pcap = dpkt.pcap.Reader(f)
    ipPool = {}
    start ,end = 0, 0

    for ts, buf in pcap:
        if start == 0:
            start = ts
        end = ts

        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        dport = tcp.dport
        sport = tcp.sport

        if src not in ipPool:
            ipPool[src] = Suspect(src)
        if dst not in ipPool:
            ipPool[dst] = Suspect(dst)
        
        if tcp.flags == SYN:
            ipPool[src].port[dport] = 'SYN'
        elif tcp.flags == SYNACK and ipPool[dst].port[sport] == 'SYN':
            ipPool[dst].port[sport] = 'SYNACK'
        elif tcp.flags == RST and ipPool[dst].port[sport] == 'SYN':
            ipPool[dst].synCount += 1
            ipPool[dst].port[sport] = 0
        elif tcp.flags == RST and ipPool[src].port[dport] == 'SYNACK':
            ipPool[src].synCount += 1
            ipPool[src].port[dport] = 0           

    # ret = { ip : SYN scan times}
    ret = {}
    for ip in ipPool:
        if ipPool[ip].synCount > 1:
            print(str(ip) + " may implement TCP SYN scanning, May have scanned %d times\r\n" % ipPool[ip].synCount, end = '')
            ret[ip] = ipPool[ip].synCount
    return ret


# ret = synScanDetect('/Users/ama666/Downloads/test.pcap')