# Code adapted from the P4 learning tutorial from ETH Zurich.
# https://github.com/nsg-ethz/p4-learning/

#!/usr/bin/env python3
from scapy.all import *
import sys
import threading

big_lock = threading.Lock()

class Receiver(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.received_count = 0

    def received(self, p):
        self.received_count += 1
        big_lock.acquire()
        print("Received a packet (total %d): %s" % (
            self.received_count, str(p)))
        big_lock.release()

    def run(self):
        sniff(iface="s4-eth2", prn=lambda x: self.received(x))


def main():
    try:
        packet_int = int(sys.argv[1])
        print("Sending packet with interval", packet_int)
    except:
        print("Usage: sudo python send_and_receive.py <packet_int (seconds)>")
        sys.exit(1)

    Receiver().start()

    p = Ether(src="00:04:00:00:00:00",dst="00:04:00:00:00:04") / IP(dst="172.16.0.4") / UDP()

    sent_count = 1
    while True:
        sendp(p, iface="s1-eth1", verbose=0)
        big_lock.acquire()
        print("Sent a packet (total %d): %s" % (
            sent_count, str(p)))
        big_lock.release()
        sent_count += 1        
        time.sleep(packet_int)


if __name__ == '__main__':
    main()
