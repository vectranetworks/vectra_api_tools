#! /usr/bin/env python

import argparse

import requests

import vat.vectra as vectra

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="type")

    parser_hostname = subparsers.add_parser(
        "hostname", help="Set key asset flag based on hostname"
    )
    parser_hostname = commonArgs(parser_hostname)
    parser_hostname.add_argument(
        "target", help="hostname or file name with list of hostnames"
    )

    parser_ip = subparsers.add_parser(
        "ip", help="Set key asset flag based on ip address"
    )
    parser_ip = commonArgs(parser_ip)
    parser_ip.add_argument(
        "target", help="ip address or file name with list of ip addresses"
    )

    parser_id = subparsers.add_parser("id", help="Set key asset based on id")
    parser_id = commonArgs(parser_id)
    parser_id.add_argument("target", help="host id or file name with list of ids")

    args = vars(parser.parse_args())
    vc = vectra.VectraClient(url=args["url"], token=args["token"])

    set_ka = True if not args["unset"] else False

    if args["file"] and args["type"] == "hostname":
        hostfile = open(args["target"], "r")
        for host in hostfile.readlines():
            try:
                host_id = vc.get_hosts(name=host.strip()).json()["results"][0]["id"]
                resp = vc.set_key_asset(host_id=host_id, set=set_ka)
                respCode(args, resp, host.strip())
            except IndexError:
                print(host.strip() + " is not present in Vectra")
    elif args["file"] and args["type"] == "ip":
        hostfile = open(args["target"], "r")
        for host in hostfile.readlines():
            try:
                host_id = vc.get_hosts(last_source=host.strip()).json()["results"][0][
                    "id"
                ]
                resp = vc.set_key_asset(host_id=host_id, set=set_ka)
                respCode(args, resp, host.strip())
            except IndexError:
                print(host.strip() + " is not present in Vectra")
    else:
        if args["type"] == "hostname":
            hosts = vc.get_hosts(name=args["target"]).json()["results"]
            for host in hosts:
                resp = vc.set_key_asset(host_id=host["id"], set=set_ka)
                respCode(args, resp, args["target"])
        if args["type"] == "ip":
            hosts = vc.get_hosts(last_source=args["target"]).json()["results"]
            for host in hosts:
                resp = vc.set_key_asset(host_id=host["id"], set=set_ka)
                respCode(args, resp, args["target"])
        if args["type"] == "id":
            resp = vc.set_key_asset(host_id=args["target"], set=set_ka)
            respCode(args, resp, args["target"])


def commonArgs(parser):
    parser.add_argument(
        "--url",
        required=True,
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )
    parser.add_argument("--token", required=True, help="api token")
    parser.add_argument("--file", action="store_true", help="set target to file")
    parser.add_argument(
        "--unset", action="store_true", help="set flag to unset host as key asset"
    )
    return parser


def respCode(args, resp, hostname):
    if resp.status_code == 200 and args["unset"]:
        print("Successfully unset host " + str(hostname) + " as key asset")
    elif resp.status_code == 200 and not args["unset"]:
        print("Successfully set host " + str(hostname) + " as key asset")
    else:
        print("Unknown response")


if __name__ == "__main__":
    main()
