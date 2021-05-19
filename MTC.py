import os
import random

from scapy.all import sniff
from dotenv import load_dotenv
from functools import reduce
from os.path import dirname, join

import schedule

load_dotenv(dotenv_path=join(dirname(__file__), ".env"))

LFM_interval = int(os.environ["LFM_INTERVAL"])  # in seconds

shared_key = os.environ["SHARED_KEY"]

default_host_space_requirement = 1
default_host_mutation_interval = 10

hosts = [3]
host_space_requirement = {3: 2}  # minimal number of addresses for host
host_mutation_interval = {}  # mutation interval

address_space = [i for i in range(2, 255)]  # single subnet has addresses from 2 to 255
assigned_addresses = {3: None}  # active sessions, starting with single rIP=192.168.1.3
assigned_ranges = {3: []}  # assigned VAR's

max_var_count = 5
min_var_count = 2


def mask_addresses_out(used_addresses):
    # create sets of contiguous addresses by masking used addresses out from the address space
    address_set = []
    counter = -1
    previous_address_added_to_set = False
    for address in address_space:
        if address not in used_addresses:
            if previous_address_added_to_set is False:
                address_set.append([])
                counter += 1
            address_set[counter].append(address)
            previous_address_added_to_set = True
        else:
            previous_address_added_to_set = False

    return address_set


def get_unused_addresses():
    used_addresses = list(assigned_addresses.values()) + reduce(lambda x, y: x + y, assigned_ranges.values(), [])
    return mask_addresses_out(used_addresses)
    # return [address for address in address_space if address not in used_addresses]


def flatten_list_of_lists(list_of_lists):
    return [element for l in list_of_lists for element in l]


def calculate_var_size(rIP, available_addresses):
    available_addresses_count = len(flatten_list_of_lists(available_addresses))
    return min(host_space_requirement[rIP],
               int((available_addresses_count / 2) * (
                       host_space_requirement[rIP] / reduce(lambda x, y: x + y, host_space_requirement.values(),
                                                            0))))


def assign_new_address_range(rIP):
    available_addresses = get_unused_addresses()
    flattened_available_addresses = flatten_list_of_lists(available_addresses)
    range_size = calculate_var_size(rIP, available_addresses)
    if len(flattened_available_addresses) < range_size:
        raise Exception("Address space too small")

    new_range = random.sample(flattened_available_addresses, range_size)
    assigned_ranges[rIP] = new_range
    return new_range


def raise_incorrect_assigned_range_access(rIP):
    if rIP not in assigned_ranges:
        raise Exception(f"Tried to access nonexistent host address: {rIP}")


def get_host_address_range(rIP):
    raise_incorrect_assigned_range_access(rIP)

    if assigned_ranges[rIP]:
        return assigned_ranges[rIP]
    else:
        return assign_new_address_range(rIP)


def low_frequency_mutation():
    temp_assigned_addresses = {}
    for host_ip in hosts:
        unused_addresses = get_unused_addresses()
        # TODO: r_j must be divided into p separate sub-VARs proportional to the V_i requirement for each MT host
        # TODO: to avoid address collision within a VAR, participating MT hosts will be eventually allocated non-overlapping ranges within the shared VAR
        var = get_host_address_range(rIP=host_ip)


def add_host(rIP, space_requirement=default_host_space_requirement, mutation_interval=default_host_mutation_interval):
    hosts.append(rIP)
    host_space_requirement[rIP] = space_requirement
    host_mutation_interval[rIP] = mutation_interval


def handle_packet(pkt):
    schedule.run_pending()
    # TODO: handle packets from MTG's


def main():
    var = get_host_address_range(3)
    print(var)

    # schedule.every(LFM_interval).seconds.do(low_frequency_mutation)
    # sniff(iface="eth0", prn=handle_packet)


if __name__ == "__main__":
    main()
