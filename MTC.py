from scapy.all import sniff
from dotenv import load_env
from functools import reduce

import schedule

load_env()

LFM_interval = os.environ["LFM_INTERVAL"]    # in seconds

shared_key = os.environ["SHARED_KEY"]

default_host_space_requirement = 1
default_host_mutation_interval = 10

hosts = []
host_space_requirement = {} # minimal number of addresses for host
host_mutation_interval = {} # mutation interval

address_space = []
assigned_addresses = [] # active sessions
assigned_ranges = {}    # assigned VAR's


def get_available_addresses():
    used_addresses = assigned_addresses + reduce(lambda x,y: x+y, assigned_ranges.values(), [])
    return [address for address in address_space if not address in used_addresses]


def get_address_range(rIP):
    if assigned_ranges[rIP]:
        return assigned_ranges[rIP]

    available_addresses = get_available_addresses()
    range_size = min(host_space_requirement[rIP], (len(available_addresses) / 2) * (host_space_requirement[rIP] / reduce(lambda x,y: x + y, host_space_requirement.values(), 0)))
    if len(available_addresses) < range_size:
        raise Exception("Address space too small")
        return
    new_range = random.sample(available_addresses, range_size)
    assigned_ranges[rIP] = new_range
    return new_range


def low_frequency_mutation():
    # TODO: detailed LFM
    assigned_ranges = {} # temporary


def add_host(rIP, space_requirement = default_host_space_requirement, mutation_interval = default_host_mutation_interval):
    hosts.append(rIP)
    host_space_requirement[rIP] = space_requirement
    host_mutation_interval[rIP] = mutation_interval


def handle_packet(pkt):
    schedule.run_pending()
    # TODO: handle packets from MTG's


def main():
    schedule.every(LFM_interval).seconds.do(low_frequency_mutation)
    sniff(iface="eth0", prn=handle_packet)


if __name__ == "__main__":
    main()
