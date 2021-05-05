import dpkt
import socket
import datetime
from collections import defaultdict

#Flags
ACK = 0x010
ack = 0x002
ackACK = 0x012
FIN = 0x01 
RST = 0x04  
PUSH = 0x08

class Suspect:
    def __init__(self, ip):
        self.ip = ip
        self.ackCount = 0
        self.port = defaultdict(str)
    
def ackScanDetect(filePath):
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
        
        if tcp.flags == ACK and ipPool[src].port[dport] != 1:
            ipPool[src].ackCount += 1
        else:
            ipPool[src].port[dport] = 1

    # ret = { ip : ack scan times}
    ret = {}
    for ip in ipPool:
        if ipPool[ip].ackCount > 1:
            print(str(ip) + " may implement TCP ack scanning, May have scanned %d times\r\n" % ipPool[ip].ackCount, end = '')
            ret[ip] = ipPool[ip].ackCount
    return ret


# ret = ackScanDetect('/Users/ama666/Downloads/test.pcap')