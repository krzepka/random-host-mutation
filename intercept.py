import logging

from scapy.all import sniff
from scapy.interfaces import get_if_list

iface_in = "eth0"

mac_dst = ""
ip_dst = "192.168.1.1"


def handle_packet_in(pkt):
    pkt.show()

    # packet = pkt.copy()
    # packet.dst = ip_dst
    #
    # sendp(pkt, iface=iface_out)


def main():
    if_list = get_if_list()
    print(if_list)

    # AsyncSniffer(iface=iface_in, prn=handle_packet_in, store=0)
    sniff(iface=iface_in, prn=handle_packet_in, store=0)

    # sniffer_eth0.start()


if __name__ == "__main__":
    main()

