import argparse
import json
import requests
import vat.vectra as vectra

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

detectionDict = {}

for result in response['results']:
    if result['type_vname'] not in detectionDict:
        detectionDict[result['type_vname']] = 1
    else:
        detectionDict[result['type_vname']] += 1

# pprint.pprint(detectionDict)

print('\n\n{:*<40}{:*<5}'.format('Detection', 'Count'))
for key, value in sorted(detectionDict.iteritems(), key=lambda k, v: v, reverse=True):
    print('{:<40}{:<5}'.format(key, value))