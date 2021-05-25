import os
import random
import time
import logging
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from netaddr import *

from scapy.all import sniff
from scapy.layers.http import *
from dotenv import load_dotenv
from functools import reduce
from os.path import dirname, join

import schedule
import logging

from CommunicationUtilities import RequestCommand

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


def addresses_to_string(ip_set):
    return [str(addr) for addr in ip_set]


class MTC:
    def __init__(self, shared_key, LFM_interval=900, default_host_space_requirement=1,
                 default_host_mutation_interval=10):
        self.shared_key = shared_key
        self.LFM_interval = LFM_interval
        self.last_LFM_timestamp = time.time()
        self.default_host_space_requirement = default_host_space_requirement
        self.default_host_mutation_interval = default_host_mutation_interval

        self.hosts = []
        self.host_space_requirement = {}  # minimal number of addresses for host
        self.host_mutation_interval = {}  # mutation interval
        self.address_space = IPSet(IPRange('192.168.1.2', '192.168.1.254'))
        self.assigned_addresses = {}  # active sessions, starting with single rIP=192.168.1.3
        self.assigned_ranges = {}  # assigned VAR's
        self.mutation_index = 0
        self.init_LFM_schedule()

        self.add_host('192.168.1.2')
        self.add_host('192.168.1.3')

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
        self.assigned_ranges[str(rIP)] = new_range
        logging.debug("assigning new range to host: " + rIP)
        logging.debug(addresses_to_string(self.assigned_ranges[str(rIP)]))

        return new_range

    def get_host_address_range(self, rIP):
        if rIP not in self.hosts:
            raise Exception(f"Host does not exist: {rIP}")

        if rIP not in self.assigned_ranges.keys():
            logging.debug("assigning new address range for host: " + str(rIP))
            self.assign_new_address_range(rIP)

        return self.assigned_ranges[str(rIP)]

    def low_frequency_mutation(self):
        logging.debug("LFM invoked")
        self.assigned_ranges = {}
        self.last_LFM_timestamp = time.time()

    def handle_time_check(self):
        now = time.time()
        if abs(int(self.last_LFM_timestamp - now)) > 2 * self.LFM_interval:
            lfm_job = schedule.get_jobs('LFM')
            schedule.clear(lfm_job)
            self.low_frequency_mutation()
            self.init_LFM_schedule()
        else:
            schedule.run_pending()

    def init_LFM_schedule(self):
        self.mutation_index = 0
        schedule.every(self.LFM_interval).seconds.do(self.low_frequency_mutation).tag('LFM')

    def add_host(self, rIP, space_requirement=None, mutation_interval=None):
        if space_requirement is None:
            space_requirement = self.default_host_space_requirement
        if mutation_interval is None:
            mutation_interval = self.default_host_mutation_interval
        self.hosts.append(rIP)
        self.host_space_requirement[rIP] = space_requirement
        self.host_mutation_interval[rIP] = mutation_interval

    def handle_shared_key_request(self):
        return str(self.shared_key)

    def handle_authorization_request(self, data):
        # TODO: implement
        pass

    def handle_mutation_index_request(self):
        return str(self.mutation_index)

    def handle_virtual_address_ranges_request(self, rIP):
        var = self.get_host_address_range(rIP)
        return json.dumps(addresses_to_string(var))


logging.basicConfig(level=logging.DEBUG)
load_dotenv(dotenv_path=join(dirname(__file__), ".env"))

lfm_interval = int(os.environ["LFM_INTERVAL"])  # in seconds
shrd_key = os.environ["SHARED_KEY"]

mtc = MTC(shared_key=shrd_key, LFM_interval=lfm_interval)


class MTCRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args):
        self.map_type_to_GET_request = {
            RequestCommand.key.value: mtc.handle_shared_key_request,
            RequestCommand.mutation_index.value: mtc.handle_mutation_index_request,
            RequestCommand.var.value: mtc.handle_virtual_address_ranges_request,
        }
        super().__init__(*args)

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        mtc.handle_time_check()
        query = parse_qs(urlparse(self.path).query)
        logging.info("GET request,\nrequestParams: %s", query)
        request = {
            key: value[0] for key, value in query.items()
        }
        r_args = []
        if request['type'] == 'var':
            r_args.append(request['rIP'])
        if request['type'] in self.map_type_to_GET_request.keys():
            try:
                response = self.map_type_to_GET_request[request['type']](*r_args)
                self._set_response()
                self.wfile.write(response.encode('utf-8'))
                return
            except Exception as inst:
                self.send_error(400, message=str(inst))
                return

        self.send_error(400, message="Wrong request type")

    def do_POST(self):
        mtc.handle_time_check()
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                     str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))


def run_http_server(server_class=HTTPServer,
                    ip='',
                    port=8080,
                    handler_class=MTCRequestHandler):
    server_address = (ip, port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting MTC HTTP server on address ' + str(ip) + ' port ' + str(port) + '\n')

    httpd.serve_forever()
    httpd.server_close()
    logging.info('Stopping MTC HTTP server\n')


def main():
    run_http_server(ip='127.0.0.1')


if __name__ == "__main__":
    main()
