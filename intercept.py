from scapy.all import sniff
from scapy.all import sendp
from scapy.all import bridge_and_sniff

from netaddr import IPNetwork

def generate_virtual_address_from_range(_range):
    # TODO: handle vAddr generation
    return _range

def encode_packet(pkt):
    # TODO: handle packet encoding
    new_pkt = pkt.clone()
    if rAddr_to_vAddr contains rAddr:
        new_pkt.dst = rAddr_to_vAddr[pkt.dst]
    else
        rAddr_to_vAddr[pkt.dst] = generate_vAddr(pkt.dst)
        new_pkt.dst = rAddr_to_vAddr[pkt.dst]
    return new_pkt

def decode_packet(pkt):
    # TODO: handle packet decoding
    new_pkt = pkt.clone()
    new_pkt.dst = vAddr_to_rAddr[pkt.dst]
    return new_pkt if new_pkt.dst else False

def main():
    bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=decode_packet, xfrm21=encode_packet)

if __name__ == "__main__":
    main()


