import json
import requests
import hashlib
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from CommunicationUtilities import RequestCommand


class MTG:
    def __init__(self, iface1="Ethernet", iface2="eth1", mtc_ip="192.168.1.12", mtc_port=8080, source_host=False):
        self.vIP_to_rIP = {"192.168.1.20": "192.168.1.2"}
        self.rIP_to_vIP = {"192.168.1.2": "192.168.1.20"}

        self.iface1 = iface1
        self.iface2 = iface2
        self.source_host = source_host

        self.shared_key = None
        self.mutation_speeds = {"192.168.1.2": 20}  # modify vIP every X seconds
        self.mtc_ip = mtc_ip
        self.mtc_port = mtc_port
        self.mtc_mac = ""

    def update_mtc_mac(self):
        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.mtc_ip), verbose=0, timeout=3)
        msg = answered[0]
        self.mtc_mac = msg  # TODO

    def get_shared_key(self):
        payload = {'type': RequestCommand.key.value}
        key = self.send_recv_http(payload=payload)
        return key.text

    def authorize_packet(self, pkt):
        # TODO: send packet to MTC, it should accept or reject that packet
        return True

    def get_mutation_index(self, rIP):
        payload = {'type': RequestCommand.mutation_index.value}
        index = self.send_recv_http(payload=payload).text
        try:
            index = int(index)
        except Exception:
            raise Exception(f"Received from the MTC an incorrect mutation index: {index}")
        return index

    def get_available_addresses(self, rIP):
        payload = {'type': RequestCommand.var.value, 'rIP': rIP}
        response = self.send_recv_http(payload=payload).text
        return json.loads(response)

    def get_numeric_hash(self, index):
        """
        https://stackoverflow.com/questions/16008670/how-to-hash-a-string-into-8-digits
        """
        string = self.shared_key + str(index)
        return int(hashlib.sha256(string.encode('utf-8')).hexdigest(), 16) % 10 ** 8

    def is_session_active(self, pkt):
        return True

    async def generate_vIP(self, rIP):
        available_addresses = await self.get_available_addresses(rIP)
        mutation_index = await self.get_mutation_index(rIP)
        new_vIP = available_addresses[
            self.get_numeric_hash(mutation_index) % len(available_addresses) + 1]
        self.save_mapping(rIP, new_vIP)
        return new_vIP

    def save_mapping(self, rIP, vIP):
        self.rIP_to_vIP[rIP] = vIP
        self.vIP_to_rIP[vIP] = rIP

    def get_rIP(self, ip):
        if self.vIP_to_rIP[ip]:
            return self.vIP_to_rIP[ip]
        else:
            return None

    def get_vIP(self, ip):
        if self.rIP_to_vIP[ip]:
            return self.rIP_to_vIP[ip]
        else:
            return self.generate_vIP(ip)

    def is_source_host(self):
        return self.source_host

    def encode_packet(self, pkt):
        if IP in pkt:
            logging.debug(f"[encode] Received packet from {pkt[IP].src} to {pkt[IP].dst}")
        else:
            logging.debug(f"[encode] Received packet with no IP!")
            return False

        if not self.is_session_active(pkt):
            if not self.authorize_packet(pkt):
                return False

        new_pkt = pkt.copy()
        if new_pkt[IP].dst not in self.rIP_to_vIP:
            return False

        if self.is_source_host():
            new_pkt[IP].dst = self.get_vIP(new_pkt[IP].dst)
        new_pkt[IP].src = self.get_vIP(new_pkt[IP].src)

        logging.debug(f"[encode] Sending a new packet from {pkt[IP].src} to {pkt[IP].dst}")
        return new_pkt

    def decode_packet(self, pkt):
        if IP in pkt:
            logging.debug(f"[decode] Received packet from {pkt[IP].src} to {pkt[IP].dst}")
        else:
            logging.debug(f"[decode] Received packet with no IP!")
            return False

        new_pkt = pkt.copy()
        if self.is_source_host():
            if new_pkt[IP].src in self.rIP_to_vIP:
                new_pkt[IP].src = self.get_rIP(new_pkt[IP].src)
            else:
                return False
        if new_pkt[IP].dst in self.rIP_to_vIP:
            new_pkt[IP].dst = self.get_rIP(new_pkt[IP].dst)
        else:
            return False

        logging.debug(f"[decode] Sending a new packet from {pkt[IP].src} to {pkt[IP].dst}")
        return new_pkt if (new_pkt[IP].dst and new_pkt[IP].src) else False

    def send_recv_http(self, payload):
        logging.debug(f"Sending {payload['type']} request to MTC")
        answer = requests.get(f'http://{self.mtc_ip}:{self.mtc_port}', params=payload)
        logging.debug(f"From MTC received: {answer.text}")
        return answer

    def run(self):
        self.shared_key = self.get_shared_key()
        bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=self.decode_packet, xfrm21=self.encode_packet)


def main():
    logging.basicConfig(level=logging.DEBUG)
    mtg = MTG(mtc_ip='127.0.0.1',
              source_host=True
              # source_host=False
              )
    mtg.run()
    # print(mtg.get_available_addresses('192.168.1.2'))


if __name__ == "__main__":
    main()
