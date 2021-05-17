from scapy.all import sniff
from scapy.all import bridge_and_sniff

from netaddr import IPNetwork

vIP_to_rIP = {}
rIP_to_vIP = {}

def save_mapping(rIP, vIP):
    rIP_to_vIP[rIP] = vIP
    vIP_to_rIP[vIP] = rIP

def get_rIP(ip):
    if vIP_to_rIP[ip]
        return vIP_to_rIP[ip]
    else
        return None

def get_vIP(ip):
    if rIP_to_vIP[ip]
        return rIP_to_vIP[ip]
    else
        vIP = generate_vIP(ip)
        save_mapping(ip,  vIP)
        return vIP

def generate_vIP(rIP):
    # TODO
    return vIP

def authorize_packet(pkt):
    # TODO: send packet to MTC, it should accept or reject that packet
    return true

def encode_packet(pkt):
    if !session_is_active(pkt):
        if !authorize_packet(pkt):
            return False
    
    new_pkt = pkt.copy()
    if isSourceHost: #TODO: think how to determine whether the MTG is from the 'Source' side
        new_pkt.dst = get_vIP(new_pkt.dst)
    new_pkt.src = get_vIP(new_pkt.src)
    return new_pkt

def decode_packet(pkt):
    new_pkt = pkt.copy()
    if isSourceHost: #TODO: think how to determine whether the MTG is from the 'Source' side
        new_pkt.src = get_rIP(new_pkt.src)
    new_pkt.dst = get_rIP(new_pkt.dst)
    return new_pkt if (new_pkt.dst and new_pkt.src) else False

def main():
    bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=decode_packet, xfrm21=encode_packet)

if __name__ == "__main__":
    main()


