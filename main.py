# import portScanDetector
import ack
import connect
import ping
import syn
import matplotlib.pyplot as plt

filePath = r'c:\Users\SG\Downloads\test.pcap'
ackSuspects = ack.ackScanDetect(filePath)
connectSuspects = connect.connectScanDetect(filePath)
pingSuspects = ping.pingScanDetect(filePath)
synSuspects = syn.synScanDetect(filePath)

print(ackSuspects)
print(connectSuspects)
print(pingSuspects)
print(synSuspects)

labels = ['ACK SCAN','CONNECT SCAN','PING SCAN','SYN SCAN'] 
sizes = [sum(ackSuspects.values()), sum(connectSuspects.values()), sum(pingSuspects.values()), sum(synSuspects.values())] 
plt.pie(sizes, labels = labels, autopct = '%3.2f%%')
plt.axis('equal')
plt.title("Scan Type on Host", fontsize=20)
plt.savefig('01_main_py__scan_type_on_host.png', bbox_inches = "tight") 
plt.show()
