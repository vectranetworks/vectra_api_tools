import argparse
import json
import requests
import vat.vectra as vectra

from operator import itemgetter
from vat.cli import commonArgs, getPassword

requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser()

subparsers = parser.add_subparsers(dest='action')

parser_host = subparsers.add_parser('host',
                                    help='retrieve data from Vectra brain')
parser_host = commonArgs(parser_host)

parser_file = subparsers.add_parser('file',
                                    help='Load data from file')
parser_file.add_argument('filename',
                                    help='file to import data')

args = vars(parser.parse_args())

if args['action'] == 'file':
    filename = open(args['filename'], 'r')
    response = json.loads(filename.read())
else:
    if args['user']:
        args['password'] = getPassword()
    else:
        print ('This script only supports v1 of the API. Please use --user')
        exit(0)

    vc = vectra.VectraClient(url=args['url'], user=args['user'], password=args['password'])

    response = vc.get_detections(state=args['state'], page_size=args['page_size'], page=args['page'],
                                 fields=args['fields'],
                                 order=args['order']).json()

detectionList = []
detectionCount = []

for result in response['results']:
    name = result['type_vname']
    for detection_detail in result['detection_detail_set']:
        destination = detection_detail['dst_port']
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

print('\n\n{:*<40}{:*<10}{:*<5}'.format('Detection', 'Port', 'Count'))
for det in detectionCount:
    print('{:<40}{:<10}{:<5}'.format(*det))
