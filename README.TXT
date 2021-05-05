#  Port Scan Detector
## Authors:
### Yiheng An

## Prerequisites
Python Libraries:
- dpkt
- matplotlib
- pandas
- django

## File Input- Hardcoded on Line 19 portScanDetector.py  (e.g.: filePath = r'c:\Users\SG\Downloads\test.pcap')
## File Input- Hardcoded on Line 8 main.py               (e.g.: filePath = r'c:\Users\SG\Downloads\test.pcap')


## Development Enviroment
    IDE- Visual Studio Code
    Python Version- Python 3.9.4
	OS- Windows 10/macOS 10.15.7

## Usage
python -u main.py
python -u portScanDetector.py

## Functions

**Determine the SYN scan standard**
    1. For the same ip and the same port, first send SYN, then receive SYNACK, and then send RST.
    2. For the same ip and the same port, send SYN first, and then receive RST.

**Determine the CONNECT scan standard**
    1. For the same ip and same port, send SYN first, then receive SYNACK, and then send ACK.
    2. For the same ip and the same port, send SYN first, and then receive RST.

**Determine the ACK scan standard**
    1. The first packet sent by the same ip to the same port is ACK.

When there are more than 50 access data packets from the same IP to the host, it is judged as a suspect

