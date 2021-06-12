import json
import requests
import hashlib
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from CommunicationUtilities import RequestCommand


class MTG:
    def __init__(self, iface1="eth0", iface2="eth1", mtc_ip="192.168.1.12", mtc_port=8080, source_host=False):
        self.vIP_to_rIP = {"192.168.1.20": "192.168.1.1"}
        self.rIP_to_vIP = {"192.168.1.1": "192.168.1.20"}

        self.iface1 = iface1
        self.iface2 = iface2
        self.source_host = source_host

        self.shared_key = None
        self.mutation_speeds = {"192.168.1.1": 20}  # modify vIP every X seconds
        self.mtc_ip = mtc_ip
        self.mtc_port = mtc_port

        self.iface_mac_src = "96:06:a0:1e:fc:af"
        self.iface_mac_dst = "4a:6c:13:35:4e:e7"

    def get_shared_key(self):
        payload = {'type': RequestCommand.key.value}
        key = self.send_recv_http(payload=payload)
        return key.text

    def get_mutation_index(self, rIP):
        payload = {'type': RequestCommand.mutation_index.value}
        index = self.send_recv_http(payload=payload).text
        try:
            index = int(index)
        except Exception:
            raise Exception("Received from the MTC an incorrect mutation index:" + index)
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

    def generate_vIP(self, rIP):
        available_addresses = self.get_available_addresses(rIP)
        mutation_index = self.get_mutation_index(rIP)
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
            logging.debug("[encode] Received packet from " + pkt[IP].src + " to " + pkt[IP].dst)
        else:
            logging.debug("[encode] Received packet with no IP!")
            return False

        if not self.is_session_active(pkt):
            pass

        new_pkt = pkt.copy()

        if not self.is_source_host():
            if new_pkt[IP].src not in self.rIP_to_vIP:
                logging.debug("[decode] IP " + new_pkt[IP].src + " is NOT present in vIP-rIP mapping!")
                return False

            logging.debug("[encode] Not a source host MTG: modifying source IP")
            new_pkt[IP].src = self.get_vIP(new_pkt[IP].src)
            del new_pkt[IP].chksum
            new_pkt[IP].show2()

        logging.debug("[encode] Sending a new packet from " + new_pkt[IP].src + " to " + new_pkt[IP].dst)
        return new_pkt

    def decode_packet(self, pkt):
        if IP in pkt:
            logging.debug("[decode] Received packet from " + pkt[IP].src + " to " + pkt[IP].dst)
        else:
            logging.debug("[decode] Received packet with no IP!")
            return False

        pkt.show()
        new_pkt = pkt.copy()
        if not self.is_source_host():
            logging.debug("[decode] MTG is a source host: modifying dst IP")
            if new_pkt[IP].dst in self.vIP_to_rIP:
                new_ip = self.get_rIP(new_pkt[IP].dst)
                logging.debug(
                    "[decode] IP " + new_pkt[IP].dst + " is present in vIP-rIP mapping, modifying to " + new_ip)
                new_pkt[IP].show2()
                new_pkt[IP].dst = new_ip
                del new_pkt[IP].chksum
                new_pkt[IP].show2()
                new_pkt.dst = self.iface_mac_dst
                new_pkt.src = self.iface_mac_src
            else:
                logging.debug(
                    "[decode] IP " + new_pkt[IP].dst + " is NOT present in vIP-rIP mapping! Dropping packet...")
                return False

        logging.debug("[decode] Sending a new packet from " + new_pkt[IP].src + " to " + new_pkt[IP].dst)

        if new_pkt[IP].dst and new_pkt[IP].src:
            logging.debug("[decode] Sending a new packet from " + new_pkt[IP].src + " to " + new_pkt[IP].dst)
            new_pkt.show()
            return new_pkt
        else:
            return False

    def send_recv_http(self, payload):
        logging.debug("Sending " + payload['type'] + " request to MTC")
        answer = requests.get('http://' + self.mtc_ip + ":" + str(self.mtc_port), params=payload)
        logging.debug("From MTC received: " + answer.text)
        return answer

    def run(self):
        self.shared_key = self.get_shared_key()
        bridge_and_sniff(if1="eth0", if2="eth1", xfrm12=self.encode_packet, xfrm21=self.decode_packet)


def main():
    logging.basicConfig(level=logging.DEBUG)
    mtg = MTG(mtc_ip='192.168.4.5',
              source_host=False
              )
    mtg.run()
    # print(mtg.get_available_addresses('192.168.1.2'))


if __name__ == "__main__":
    main()
