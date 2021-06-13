import logging
import argparse

from MTG import MTG


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--adjacent_host_ip', type=str, required=True)
    parser.add_argument('--source_host', action='store_true', required=False)

    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(level=logging.INFO)
    mtg = MTG(iface1="eth0",
              iface2="eth1",
              mtc_ip='192.168.4.5',
              adjacent_host_ip=args.adjacent_host_ip,
              source_host=args.source_host)

    mtg.run()


if __name__ == "__main__":
    main()
