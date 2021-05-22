import os
import random
import time

from scapy.all import sniff
from scapy.layers.http import *
from dotenv import load_dotenv
from functools import reduce
from os.path import dirname, join

import schedule
import logging

from scapy.sessions import TCPSession

"""
Example:

MThost1 -------- MTG1 -------|
                            |
                            ---- switch ----- MTG --------
                            |
MThost2 -------- MTG2 -------|



address space: (2, 254)

1)
    select first VARs for the two MT hosts: (2, 3, 6), (17, 18,19)
2)
    them send to MTG1, MTG2
3)
    MTG1 selects 3 for MThost1
    MTG2 selects 18 for MThost2
4)
    invoke LFM algorithm
    (2, 254) - ((3, 18) + (2, 3, 6) + (17, 18, 19))
    result = (2, 4, 5,...)
"""


def flatten_list_of_lists(list_of_lists):
    return [element for lst in list_of_lists for element in lst]


class MTC:
    def __init__(self, shared_key, LFM_interval=900, default_host_space_requirement=1,
                 default_host_mutation_interval=10):
        self.shared_key = shared_key
        self.LFM_interval = LFM_interval
        self.default_host_space_requirement = default_host_space_requirement
        self.default_host_mutation_interval = default_host_mutation_interval

        self.hosts = [3]
        self.host_space_requirement = {3: 2}  # minimal number of addresses for host
        self.host_mutation_interval = {}  # mutation interval
        self.address_space = [i for i in range(2, 255)]  # single subnet has addresses from 2 to 255
        self.assigned_addresses = {3: None}  # active sessions, starting with single rIP=192.168.1.3
        self.assigned_ranges = {3: []}  # assigned VAR's

    def mask_addresses_out(self, used_addresses):
        # create sets of contiguous addresses by masking used addresses out from the address space
        address_set = []
        counter = -1
        previous_address_added_to_set = False
        for address in self.address_space:
            if address not in used_addresses:
                if previous_address_added_to_set is False:
                    address_set.append([])
                    counter += 1
                address_set[counter].append(address)
                previous_address_added_to_set = True
            else:
                previous_address_added_to_set = False

        return address_set

    def get_unused_addresses(self):

        used_addresses = list(self.assigned_addresses.values()) + reduce(lambda x, y: x + y,
                                                                         self.assigned_ranges.values(), [])
        return self.mask_addresses_out(used_addresses)
        # return [address for address in address_space if address not in used_addresses]

    def calculate_var_size(self, rIP, available_addresses):
        available_addresses_count = len(flatten_list_of_lists(available_addresses))
        return max(self.host_space_requirement[rIP],
                   int((available_addresses_count / 2) * (
                           self.host_space_requirement[rIP] / reduce(lambda x, y: x + y,
                                                                     self.host_space_requirement.values(),
                                                                     0))))

    def assign_new_address_range(self, rIP):
        available_addresses = self.get_unused_addresses()
        flattened_available_addresses = flatten_list_of_lists(available_addresses)
        range_size = self.calculate_var_size(rIP, available_addresses)
        if len(flattened_available_addresses) < range_size:
            raise Exception("Address space too small")

        new_range = random.sample(flattened_available_addresses, range_size)
        self.assigned_ranges[rIP] = new_range

        logging.debug(f"Assigned new VAR: {new_range}, for rIP: {rIP}")
        return new_range

    def raise_incorrect_assigned_range_access(self, rIP):
        if rIP not in self.assigned_ranges:
            raise Exception(f"Tried to access nonexistent host address: {rIP}")

    def get_host_address_range(self, rIP):
        self.raise_incorrect_assigned_range_access(rIP)

        if not self.assigned_ranges[rIP]:
            self.assign_new_address_range(rIP)

        logging.debug(f"Returning VAR for rIP {rIP}: {self.assigned_ranges[rIP]}")
        return self.assigned_ranges[rIP]

    def low_frequency_mutation(self):
        logging.debug("LFM invoked")
        for host_ip in self.hosts:
            self.assign_new_address_range(rIP=host_ip)
            # TODO: LFM constraints

    def add_host(self, rIP, space_requirement=None, mutation_interval=None):
        if space_requirement is None:
            space_requirement = self.default_host_space_requirement
        if mutation_interval is None:
            mutation_interval = self.default_host_mutation_interval
        self.hosts.append(rIP)
        self.host_space_requirement[rIP] = space_requirement
        self.host_mutation_interval[rIP] = mutation_interval

    def handle_shared_key_request(self, pkt):
        # TODO: implement
        pass

    def handle_authorization_request(self, pkt):
        # TODO: implement
        pass

    def handle_mutation_index_request(self, pkt):
        # TODO: implement
        pass

    def handle_virtual_address_ranges_request(self, pkt):
        # TODO: implement
        pass

    def handle_http_request(self, pkt):
        pass

    def handle_packet(self, pkt):
        pkt.summary()
        schedule.run_pending()

        if pkt:
            self.handle_http_request(pkt)


def main():
    logging.basicConfig(level=logging.DEBUG)
    load_dotenv(dotenv_path=join(dirname(__file__), ".env"))
    lfm_interval = int(os.environ["LFM_INTERVAL"])  # in seconds
    shrd_key = os.environ["SHARED_KEY"]

    mtc = MTC(shared_key=shrd_key, LFM_interval=lfm_interval)

    schedule.every(lfm_interval).seconds.do(mtc.low_frequency_mutation)
    sniff(session=TCPSession, iface="Ethernet", prn=mtc.handle_packet)


if __name__ == "__main__":
    main()
