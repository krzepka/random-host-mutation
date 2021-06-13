import os
import json
import requests
import hashlib
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP

from CommunicationUtilities import RequestCommand


class MTG:
    def __init__(self, iface1, iface2, adjacent_host_ip, mtc_ip="192.168.4.5", mtc_port=8080,
                 source_host=False):
        self.vIP_to_rIP = {"192.168.1.20": "192.168.1.1"}
        self.rIP_to_vIP = {"192.168.1.1": "192.168.1.20"}
        self.mutation_speeds = {"192.168.1.1": 20}  # modify vIP every X seconds
        self.mutation_timestamps = {"192.168.1.1": time.time()}  # modify vIP every X seconds

        self.iface1 = iface1
        self.iface2 = iface2
        self.source_host = source_host

        self.shared_key = None
        self.mtc_ip = mtc_ip
        self.mtc_port = mtc_port

        self.iface_mac_src = self.get_local_mac()
        self.iface_mac_dst = self.get_host_mac(adjacent_host_ip)
        logging.debug("Retrieved local (src) MAC: " + self.iface_mac_src)
        logging.debug("From " + adjacent_host_ip + " retrieved remote (dst) MAC: " + self.iface_mac_dst)

    def get_local_mac(self):
        return get_if_hwaddr(self.iface1)

    def get_host_mac(self, ip):
        result = sr1(ARP(op=ARP.who_has, psrc=get_if_addr(self.iface1), pdst=ip))
        return result.hwsrc

    def start_quagga(self):
        os.system('/etc/inid.d/quagga start')

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

    def clear_mapping_after_interval(self, ip):
        if ip in self.mutation_speeds and ip in self.mutation_timestamps:
            current_timestamp = time.time()
            if current_timestamp - self.mutation_timestamps[ip] > self.mutation_speeds[ip]:
                self.rIP_to_vIP[ip] = ""
                self.vIP_to_rIP[ip] = ""

                self.mutation_timestamps[ip] = current_timestamp

    def get_vIP(self, ip):
        self.clear_mapping_after_interval(ip)

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

        pkt.show()
        new_pkt = pkt.copy()

        if not self.is_source_host():
            if new_pkt[IP].src not in self.rIP_to_vIP:
                logging.debug("[decode] IP " + new_pkt[IP].src + " is NOT present in vIP-rIP mapping!")
                return False

            logging.debug("[encode] Not a source host MTG: modifying source IP")
            new_pkt[IP].src = self.get_vIP(new_pkt[IP].src)

        logging.debug("[encode] Sending a new packet from " + new_pkt[IP].src + " to " + new_pkt[IP].dst)
        del new_pkt[IP].chksum
        new_pkt[IP].show2()
        return new_pkt

    def decode_packet(self, pkt):
        if IP in pkt:
            logging.debug("[decode] Received packet from " + pkt[IP].src + " to " + pkt[IP].dst)
        else:
            logging.debug("[decode] Received packet with no IP!")
            return False

        new_pkt = pkt.copy()
        if not self.is_source_host():
            logging.debug("[decode] MTG is a source host: modifying dst IP")
            if new_pkt[IP].dst in self.vIP_to_rIP:
                new_ip = self.get_rIP(new_pkt[IP].dst)
                logging.debug(
                    "[decode] IP " + new_pkt[IP].dst + " is present in vIP-rIP mapping, modifying to " + new_ip)
                new_pkt[IP].dst = new_ip
                del new_pkt[IP].chksum
                new_pkt[IP].show2()
            else:
                logging.debug("[decode] IP " + new_pkt[IP].dst + " is NOT present in vIP-rIP mapping!")
                return False
        new_pkt.src = self.iface_mac_src
        new_pkt.dst = self.iface_mac_dst

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
        self.start_quagga()
        self.shared_key = self.get_shared_key()
        bridge_and_sniff(if1=self.iface1, if2=self.iface2, xfrm12=self.encode_packet, xfrm21=self.decode_packet)
