#! /usr/bin/env python

import argparse
import pprint

import requests

import vat.vectra as vectra

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser(
        description="Manage Vectra threat feeds (This script is only supported by v2 endpoint which requires token auth)"
    )

    # Command line arguments for creating new threat feed
    subparsers = parser.add_subparsers(dest="action")

    parser_create = subparsers.add_parser("create", help="Create new threat feed")
    parser_create.add_argument(
        "--feed", required=True, action="store", help="Name for threat feed"
    )

    parser_create.add_argument(
        "--token", required=True, action="store", help="Authentication token"
    )

    parser_create.add_argument(
        "--url",
        required=True,
        action="store",
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )

    parser_create.add_argument(
        "--file", required=True, action="store", help="STIX file"
    )

    parser_create.add_argument(
        "--category",
        required=True,
        action="store",
        choices=["exfil", "lateral", "cnc"],
        help="Detection category (case sensitive)",
    )

    parser_create.add_argument(
        "--certainty",
        required=True,
        action="store",
        choices=["Low", "Medium", "High"],
        help="Detection certainty (case sensitive)",
    )

    parser_create.add_argument(
        "--type",
        required=True,
        action="store",
        choices=[
            "Anonymization",
            "C2",
            "Exfiltration",
            "Malware Artifacts",
            "Watchlist",
        ],
        help="Indicator type (case sensitive)",
    )

    parser_create.add_argument(
        "--duration", required=True, action="store", type=int, help="Duration"
    )

    # Command line arguments for updating an existing threat feed
    parser_edit = subparsers.add_parser(
        "update", help="Update STIX file for existing threat feed"
    )
    parser_edit.add_argument(
        "--feed", required=True, action="store", help="Name for threat feed"
    )

    parser_edit.add_argument(
        "--token", required=True, action="store", help="Authentication token"
    )

    parser_edit.add_argument(
        "--url",
        required=True,
        action="store",
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )

    parser_edit.add_argument("--file", required=True, action="store", help="STIX file")

    # Command line arguments for deleting a threat feed
    parser_delete = subparsers.add_parser("delete", help="Delete threat feed")
    parser_delete.add_argument(
        "--feed", required=True, action="store", help="Name for threat feed"
    )

    parser_delete.add_argument(
        "--token", required=True, action="store", help="Authentication token"
    )

    parser_delete.add_argument(
        "--url",
        required=True,
        action="store",
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )

    # Command line argument for listing threat feeds
    parser_show = subparsers.add_parser("list", help="Shows list of all threat feeds")
    parser_show.add_argument(
        "--token", required=True, action="store", help="Authentication token"
    )

    parser_show.add_argument(
        "--url",
        required=True,
        action="store",
        help="IP or FQDN for Vectra brain (http://www.example.com)",
    )

    # print(parser.parse_args())
    args = vars(parser.parse_args())
    vc = vectra.VectraClient(url=args["url"], token=args["token"])

    if args["action"] == "create":
        feed_id = vc.create_feed(
            name=args["feed"],
            category=args["category"],
            certainty=args["certainty"],
            itype=args["type"],
            duration=args["duration"],
        ).json()["threatFeed"]["id"]
        print("Threat feed created\nUploading STIX file\n")
        vc.post_stix_file(feed_id=feed_id, stix_file=args["file"])

        print("success")

    if args["action"] == "update":
        feed_id = vc.get_feed_by_name(name=args["feed"])
        if feed_id:
            vc.post_stix_file(feed_id=feed_id, stix_file=args["file"])
            print("success")
        else:
            print("Could not find threat feed")

    if args["action"] == "delete":
        feed_id = vc.get_feed_by_name(name=args["feed"])
        if feed_id:
            vc.delete_feed(feed_id=feed_id)
            print("success")
        else:
            print("Could not find threat feed")

    if args["action"] == "list":
        result = vc.get_feeds()

        for e in result.json()["threatFeeds"]:
            pprint.pprint(e)


if __name__ == "__main__":
    main()
