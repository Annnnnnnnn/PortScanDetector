'''
Recognize the scan by analyzing a TCP dump file. 
Output the range of ports scanned and the duration of the scan.

Solution:
Extract the source ip address in pcap, 
if a certain ip address appears too many times in a short time, 
it can be judged as a scan.
Record the port range of the IP address scan and the time from start to end.
'''

import dpkt
import socket
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import time
import numpy as np

filePath = r'c:\Users\SG\Downloads\test.pcap'
f = open(filePath,'rb')
pcap = dpkt.pcap.Reader(f)

class Suspect:
    def __init__(self, ip):
        self.ip = ip
        self.port = []
        self.start = 0
        self.end = 0

ipPool = {}
times = {}

for ts, buf in pcap:
    t = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    if t not in times:
        times[t] = 0
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        # dst = socket.inet_ntoa(ip.dst)
        if src not in ipPool: 
            ipPool[src] = Suspect(src)
            ipPool[src].start = t
        ipPool[src].end = t

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        ipPool[src].port.append(tcp.dport)
        times[t] += 1

    except Exception as err:
        print("[error] %s" % err)
f.close()

def plotNumbersOfPortsScanned(ipPool):
    """
    This function is used to visualize how many ports each ip scanned
    """

    # ret = { ip : numbers of ports scanned}
    ret = {}
    for ip in ipPool:
        ret[ip] = len(ipPool[ip].port)
    plt.figure(figsize=(12,12))
    plt.xlim(0,50)
    # plt.xticks(rotation=-90)
    plt.barh(list(ret.keys()), list(ret.values()))
    plt.ylabel("IP Addresses")
    plt.xlabel("# of Port Scans")
    plt.title("Ports Scanned by IP Address", fontsize=20)
    plt.savefig('02_portScanDetector_py__plotNumbersOfPortsScanned.png', bbox_inches = "tight")  
    plt.show()

def plotNumbersOfPortsScannedSuspectsonly(ipPool):
    """
    This function only shows how many ports the suspicious ip scanned. 
    The criterion for judging whether the ip is bad is to see whether the ip has been scanned more than 50 times.
    """
    # ret = { ip : numbers of ports scanned}
    ret = {}
    for ip in ipPool:
        nums = len(ipPool[ip].port)
        if nums > 50:
            ret[ip] = nums
    plt.figure(figsize=(12,12))
    # plt.xlim(0,50)

    # This line of code controls the display direction of the text on the x and y axes. 
    # If the text is very long, it can be displayed vertically.
    # plt.xticks(rotation=-90)
    plt.barh(list(ret.keys()), list(ret.values()))
    plt.ylabel("IP Addresses")
    plt.xlabel("# of Port Scans")
    plt.title("Number of Ports Scanned [Suspects Only]", fontsize=20)
    plt.savefig('02_portScanDetector_py__plotNumbersOfPortsScannedSuspectsonly.png', bbox_inches = "tight")  
    plt.show()

def numbersOfScanOverTime(times):
    """
    This function is used to show how many ports are scanned per second.
    """
    plt.barh(list(times.keys()), list(times.values()))
    plt.tight_layout()
    plt.ylabel("Time")
    plt.xlabel("# of Scans")
    plt.title("Number of Scans Over Time", fontsize=20)
    plt.savefig('02_portScanDetector_py__numbersOfScanOverTime.png', bbox_inches = "tight") 
    plt.show()

def plotIntervalOfPortsScanned(ipPool):
    """
    This function displays the scan time of each ip. 
    The first data packet sent is the start time, and the last is the end time. 
    The start time and end time are stored in the Suspect class attribute corresponding to each ip.
    """

    # ret = { ip : (start time, end time)}
    x, y = [], []
    for ip in ipPool:
        num = len(ipPool[ip].port)
        if num > 50:
            x.append([ip, ip])
            y.append([ipPool[ip].start, ipPool[ip].end])
    
    for i in range(len(x)):
        plt.plot(x[i], y[i], color='r')
        plt.scatter(x[i], y[i], color='b')
    plt.xticks(rotation=-15)
    plt.title("Invertval of Ports Scanned", fontsize=20)
    plt.ylabel("Interval")
    plt.xlabel("IP Address")
    plt.savefig('02_portScanDetector_py__plotIntervalOfPortsScanned.png', bbox_inches = "tight")  
    plt.show()

# plt.figure(1)
plotNumbersOfPortsScanned(ipPool)
# plt.figure(2)
plotNumbersOfPortsScannedSuspectsonly(ipPool)
# plt.figure(3)
numbersOfScanOverTime(times)
# plt.figure(4)
plotIntervalOfPortsScanned(ipPool)




