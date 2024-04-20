#! /usr/bin/env python

import argparse

import requests

import vat.vectra as vectra
from vat.cli import commonArgs, getPassword

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser()
    parser = commonArgs(parser)
    parser.add_argument(
        "-c",
        "--category",
        choices=["botnet", "command", "reconnaissance", "lateral", "exfiltration"],
        help="detection category",
    )
    parser.add_argument("-t", "--type", dest="detection_type", help="detection type")
    parser.add_argument("--src", dest="src_ip", help="ip address of source host")
    parser.add_argument(
        "--threat", dest="threat_gte", type=int, help="minimum threat score"
    )
    parser.add_argument(
        "--certainty", type=int, dest="certainty_gte", help="minimum certainty score"
    )
    parser.add_argument(
        "--host", dest="host_id", help="host id attributed to detection"
    )

    args = vars(parser.parse_args())

    if args["user"]:
        args["password"] = getPassword()
        vc = vectra.VectraClient(
            url=args["url"], user=args["user"], password=args["password"]
        )
    else:
        vc = vectra.VectraClient(url=args["url"], token=args["token"])

    resp = vc.get_detections(
        category=args.get("category", None),
        certainty_gte=args.get("certainty_gte", None),
        detection_type=args.get("detection_type", None),
        fields=args.get("fields", None),
        host_id=args.get("host_id", None),
        order=args.get("order", None),
        page=args.get("page", None),
        page_size=args.get("page_size", None),
        src_ip=args.get("src_ip", None),
        state=args.get("state", None),
        threat_gte=args.get("threat_gte", None),
    )

    print(resp.json())


if __name__ == "__main__":
    main()
