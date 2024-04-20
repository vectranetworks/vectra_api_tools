import argparse
import json
from operator import itemgetter

import requests

import vat.vectra as vectra
from vat.cli import commonArgs, getPassword

requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser()

subparsers = parser.add_subparsers(dest="action")

parser_host = subparsers.add_parser("host", help="retrieve data from Vectra brain")
parser_host = commonArgs(parser_host)
parser_host.add_argument(
    "--summary",
    help="summarize based on total count or per detection (default: %(default)s)",
    choices=["total", "detection"],
    default="total",
)

parser_file = subparsers.add_parser("file", help="Load data from file")
parser_file.add_argument(
    "--summary",
    help="summarize based on total count or per detection (default: %(default)s)",
    choices=["total", "detection"],
    default="total",
)
parser_file.add_argument("filename", help="file to import data")

args = vars(parser.parse_args())

if args["action"] == "file":
    filename = open(args["filename"], "r")
    response = json.loads(filename.read())
else:
    if args["user"]:
        args["password"] = getPassword()
    else:
        print("This script only supports v1 of the API. Please use --user")
        exit(0)

    vc = vectra.VectraClient(
        url=args["url"], user=args["user"], password=args["password"]
    )

    response = vc.get_detections(
        state=args["state"],
        page_size=args["page_size"],
        page=args["page"],
        fields=args["fields"],
        order=args["order"],
    ).json()

if args["summary"] == "detection":
    detectionList = []
    detectionCount = []
    for result in response["results"]:
        name = result["type_vname"]
        for detection_detail in result["detection_detail_set"]:
            destination = detection_detail["dst_ip"]
            if destination is None:
                continue
            else:
                detectionList.append([name, destination])

    countSet = [list(x) for x in set(tuple(x) for x in detectionList)]
    for pair in countSet:
        value = detectionList.count(pair)
        detectionCount.append([pair[0], pair[1], value])
        # print(pair, value)

    detectionCount = sorted(detectionCount, key=itemgetter(2, 0), reverse=True)

    print("\n\n{:*<40}{:*<30}{:*<5}".format("Detection", "Destination", "Count"))
    for det in detectionCount:
        print("{:<40}{:<30}{:<5}".format(*det))

if args["summary"] == "total":
    dstDict = {}
    for result in response["results"]:
        for detection_detail in result.get("detection_detail_set"):
            if detection_detail["dst_ip"] is None:
                continue
            if detection_detail["dst_ip"] in dstDict:
                dstDict[detection_detail["dst_ip"]] += 1
            else:
                dstDict[detection_detail["dst_ip"]] = 1

    #    pprint.pprint(srcDict)
    print("\n\n{:*<40}{:*<5}".format("Destination", "Count"))
    for key, value in sorted(dstDict.iteritems(), key=lambda k, v: v, reverse=True):
        print("{:<40}{:<5}".format(key, value))
