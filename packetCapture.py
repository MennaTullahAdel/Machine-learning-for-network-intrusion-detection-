from scapy.all import *
import time



def write(pkt):
    wrpcap('filtered.pcap', pkt, append=True)  # appends packet to output file



def cap():
    diff = 0
    start = time.time()
    end = time.time()
    print(start - end)
    FIN = 0x01
    counter = 0

    while diff <= 15:

        packet = sniff(count=1)
        for pkt in packet:
            print(packet.show())
            if pkt.haslayer(TCP) and packet is not None :
                write(pkt)
                f = pkt['TCP'].flags
                if f & FIN:
                    counter = 1
                    write(pkt)
            if pkt.haslayer(UDP) and packet is not None:
                write(pkt)
            print('lol')
        end = time.time()
        if counter == 1:
            diff = 20
        else:
            diff = abs(end - start)
