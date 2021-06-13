import logging
import argparse

from MTG import MTG


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--decode_mac_src', type=str, required=True)
    parser.add_argument('--decode_mac_dst', type=str, required=True)
    parser.add_argument('--source_host', action='store_true', required=True)

    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(level=logging.DEBUG)
    mtg = MTG(iface1="eth0",
              iface2="eth1",
              iface_mac_src=args.decode_mac_src,
              iface_mac_dst=args.decode_mac_dst,
              mtc_ip='192.168.4.5',
              source_host=args.source_host)

    mtg.run()


if __name__ == "__main__":
    main()
