#! /usr/bin/evn python

import argparse
import requests
import re
import vat.vectra as vectra

from vat.cli import getPassword

requests.packages.urllib3.disable_warnings()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url',
                        required=True,
                        help='IP or FQDN for Vectra brain (http://www.example.com)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--token',
                       help='api token')
    group.add_argument('--user',
                       help='username for basic auth')
    parser.add_argument('--list_hosts',
                        action='store_true')

    args = vars(parser.parse_args())

    if args['user']:
        args['password'] = getPassword()
        vc = vectra.VectraClient(url=args['url'], user=args['user'], password=args['password'])
    else:
        vc = vectra.VectraClient(url=args['url'], token=args['token'])

    subnets = {}

    for page in vc.get_all_hosts(fields='name,last_source'):
        for host in page.json()['results']:
            octet = re.search('(?P<subnet>(\d+\.){3})\d+', host['last_source'])
            network = "{subnet}0".format(subnet=octet.group('subnet'))
            if not subnets.get(network):
                subnets[network] = {
                    'count': 0,
                    'hosts': []
                }
            subnets[network]['count'] += 1
            subnets[network]['hosts'].append(host['name'])

    # TODO numeric sorting
    for key in sorted(subnets.iterkeys()):
        print "{subnet:<18}: {count}".format(subnet=key, count=subnets[key]['count'])
        if args['list_hosts']:
            print subnets[key]['hosts']


if __name__ == '__main__':
    main()