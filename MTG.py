from scapy.all import bridge_and_sniff

vIP_to_rIP = {}
rIP_to_vIP = {}

shared_key = None
mutation_speeds = {}

def get_shared_key():
    # TODO: retrieve shared_key from MTC
    return "asdf"


def authorize_packet(pkt):
    # TODO: send packet to MTC, it should accept or reject that packet
    return True


def get_mutation_index(rIP):
    # TODO: retrieve mutation_index from MTC for host h_i
    return 1


def get_available_addresses(rIP):
    # TODO: retrieve VAR from MTC for host h_i
    return ['192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5']


async def generate_vIP(rIP):
    available_addresses = await get_available_addresses(rIP)
    mutation_index = await get_mutation_index(rIP)
    new_vIP = available_addresses[get_numeric_hash(shared_key, mutation_index) % len(available_addresses) + 1]
    save_mapping(rIP, new_vIP)
    return new_vIP


def save_mapping(rIP, vIP):
    rIP_to_vIP[rIP] = vIP
    vIP_to_rIP[vIP] = rIP


def get_rIP(ip):
    if vIP_to_rIP[ip]:
        return vIP_to_rIP[ip]
    else:
        return None


def get_vIP(ip):
    if rIP_to_vIP[ip]:
        return rIP_to_vIP[ip]
    else:
        return generate_vIP(ip)


def encode_packet(pkt):
    if not session_is_active(pkt):
        if not authorize_packet(pkt):
            return False

    new_pkt = pkt.copy()
    if isSourceHost:  # TODO: think how to determine whether the MTG is from the 'Source' side
        new_pkt.dst = get_vIP(new_pkt.dst)
    new_pkt.src = get_vIP(new_pkt.src)
    return new_pkt


def decode_packet(pkt):
    new_pkt = pkt.copy()
    if isSourceHost:  # TODO: think how to determine whether the MTG is from the 'Source' side
        new_pkt.src = get_rIP(new_pkt.src)
    new_pkt.dst = get_rIP(new_pkt.dst)
    return new_pkt if (new_pkt.dst and new_pkt.src) else False


def main():
    shared_key = get_shared_key()
    bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=decode_packet, xfrm21=encode_packet)


if __name__ == "__main__":
    main()
