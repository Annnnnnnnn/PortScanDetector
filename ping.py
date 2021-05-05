import dpkt
import socket
from datetime import datetime

class Suspect:
    def __init__(self, ip):
        self.ip = ip
        self.pingCount = 0
        self.start = 0
        self.end = 0
    
def pingScanDetect(filePath):
    f = open(filePath,'rb')
    pcap = dpkt.pcap.Reader(f)
    ipPool = {}

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        if not isinstance(ip.data, dpkt.icmp.ICMP):
            continue

        if src not in ipPool:
            ipPool[src] = Suspect(src)
            ipPool[src].start = ts
        ipPool[src].pingCount += 1
        ipPool[src].end = ts
        
    # Determine whether it is a syn scan
    suspects = []
    ret = {}
    for ip in ipPool:
        start = datetime.fromtimestamp(ipPool[ip].start)
        end = datetime.fromtimestamp(ipPool[ip].end)
        interval = end - start
        ratio = ipPool[ip].pingCount / int(interval.seconds / 60)
        if ratio > 10:
            print(str(ip) + " may implement PING scanning, the ratio of ping/minute is %f\r\n" % ratio, end = '')
            ret[ip] = ipPool[ip].pingCount
    return ret

# pingScanDetect('/Users/ama666/Downloads/test.pcap')