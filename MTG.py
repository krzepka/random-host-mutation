import json
import logging
import requests
import socketserver

from scapy.all import *
import hashlib

from scapy.layers.http import http_request
from scapy.layers.l2 import ARP, Ether

from CommunicationUtilities import RequestCommand


class MTG:
    def __init__(self, iface1="Ethernet", iface2="eth1", mtc_ip="192.168.1.12", mtc_port=8080):
        self.vIP_to_rIP = {}
        self.rIP_to_vIP = {}

        self.iface1 = iface1
        self.iface2 = iface2

        self.shared_key = None
        self.mutation_speeds = {}
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
        # TODO
        return True

    def encode_packet(self, pkt):
        if not self.is_session_active(pkt):
            if not self.authorize_packet(pkt):
                return False

        new_pkt = pkt.copy()
        if self.is_source_host():
            new_pkt.dst = self.get_vIP(new_pkt.dst)
        new_pkt.src = self.get_vIP(new_pkt.src)
        return new_pkt

    def decode_packet(self, pkt):
        new_pkt = pkt.copy()
        if self.is_source_host():
            new_pkt.src = self.get_rIP(new_pkt.src)
        new_pkt.dst = self.get_rIP(new_pkt.dst)
        return new_pkt if (new_pkt.dst and new_pkt.src) else False

    def send_recv_http(self, payload):
        return requests.get(f'http://{self.mtc_ip}:{self.mtc_port}', params=payload)

    def run(self):
        self.shared_key = self.get_shared_key()
        bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=self.decode_packet, xfrm21=self.encode_packet)


def main():
    logging.basicConfig(level=logging.INFO)
    mtg = MTG(mtc_ip='127.0.0.1')
    # print(mtg.get_shared_key())
    # print(mtg.get_mutation_index(False))
    print(mtg.get_available_addresses('192.168.1.2'))


if __name__ == "__main__":
    main()
