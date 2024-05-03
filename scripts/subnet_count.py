#! /usr/bin/env python

import argparse
import pprint
import re

import requests

import vat.vectra as vectra
from vat.cli import getPassword

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        required=True,
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="api token")
    group.add_argument("--user", help="username for basic auth")
    parser.add_argument("--csv", help="output to csv", action="store_true")
    parser.add_argument(
        "--list_hosts", help="add host list to csv", action="store_true"
    )
    parser.add_argument(
        "--all-hosts",
        action="store_true",
        help="return active and inactive hosts (only active hosts by default)",
    )

    args = vars(parser.parse_args())
    print(args)

    if args["user"]:
        args["password"] = getPassword()
        vc = vectra.VectraClient(
            url=args["url"], user=args["user"], password=args["password"]
        )
    else:
        vc = vectra.VectraClient(url=args["url"], token=args["token"])

    total_count = 0
    subnets = {}

    for page in vc.get_all_hosts(all=args["all_hosts"], fields="name,last_source"):
        for host in page.json()["results"]:
            if not host["last_source"]:
                continue
            octet = re.search("(?P<subnet>(\d+\.){3})\d+", host["last_source"])
            network = "{subnet}0".format(subnet=octet.group("subnet"))
            if not subnets.get(network):
                subnets[network] = {"count": 0, "hosts": []}
            subnets[network]["count"] += 1
            subnets[network]["hosts"].append(host["name"])
            total_count += 1

    # TODO numeric sorting
    if args["csv"]:
        for key in sorted(subnets.iterkeys()):
            print("{key},{count},".format(key=key, count=subnets[key]["count"])),
            if args["list_hosts"]:
                print(" ".join(subnets[key]["hosts"]))
            else:
                print
    else:
        pprint.pprint(subnets, width=40)

    print("\n\n{:<18} {count}".format("total host count:", count=total_count))


if __name__ == "__main__":
    main()
