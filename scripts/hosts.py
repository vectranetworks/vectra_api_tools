#! /usr/bin/evn python

import argparse

import requests

import vat.vectra as vectra
from vat.cli import commonArgs, getPassword

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action")

    # Host score subparser
    parser_score = subparsers.add_parser(
        "score", help="retrieve hosts base on threat/certainty score"
    )
    parser_score = commonArgs(parser_score)
    parser_score.add_argument(
        "-t",
        "--threat",
        dest="threat_gte",
        type=int,
        help="minimum threat score (default: %(default)s)",
        default=75,
    )
    parser_score.add_argument(
        "-c",
        "--certainty",
        type=int,
        dest="certainty_gte",
        help="minimum certainty score (default: %(default)s)",
        default=75,
    )

    # Host tags subparser
    parser_tags = subparsers.add_parser(
        "tags", help="retrieve hosts base on threat/certainty score"
    )
    parser_tags = commonArgs(parser_tags)
    parser_tags.add_argument(
        "-g", "--tags", required=True, help="tags assigned to hosts"
    )

    # Advanced query
    parser_adv = subparsers.add_parser(
        "advance", help="retrieve hosts base on threat/certainty score"
    )
    parser_adv = commonArgs(parser_adv)
    parser_adv.add_argument(
        "-c",
        "--certainty",
        type=int,
        dest="certainty_gte",
        help="minimum certainty score (default: %(default)s)",
    )
    parser_adv.add_argument("-g", "--tags", help="tags assigned to hosts")
    parser_adv.add_argument("-i", "--ip", dest="last_source", help="ip address of host")
    parser_adv.add_argument(
        "-k", "--key_asset", action="store_true", help="host marked as a key asset"
    )
    parser_adv.add_argument(
        "-m", "--mac", dest="mac_address", help="mac address of host"
    )
    parser_adv.add_argument(
        "-t",
        "--threat",
        dest="threat_gte",
        type=int,
        help="minimum threat score (default: %(default)s)",
    )

    args = vars(parser.parse_args())

    if args["user"]:
        args["password"] = getPassword()
        vc = vectra.VectraClient(
            url=args["url"], user=args["user"], password=args["password"]
        )
    else:
        vc = vectra.VectraClient(url=args["url"], token=args["token"])

    resp = vc.get_hosts(
        certainty_gte=args.get("certainty_gte", None),
        threat_gte=args.get("threat_gte", None),
        tags=args.get("tags", None),
        last_source=args.get("last_source", None),
        is_key_asset=args.get("key_asset", None),
        mac_address=args.get("mac_address", None),
    )

    print(resp.json())


if __name__ == "__main__":
    main()
