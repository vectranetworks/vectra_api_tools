import argparse
import pprint
import requests
import vat.vectra as vectra

from vat.cli import commonArgs

requests.packages.urllib3.disable_warnings()

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action')

    proxy_list = subparsers.add_parser('list', help='list configured proxies')
    proxy_list = commonArgs(proxy_list)

    proxy_add= subparsers.add_parser('add', help='create proxies')
    proxy_add = commonArgs(proxy_add)
    proxy_add.add_argument('host', help='host to add to proxy list')

    # parser_file = subparsers.add_parser('file',
    #                                     help='Load data from file')
    # parser_file.add_argument('filename',
    #                                     help='file to import data')

    args = vars(parser.parse_args())

    if args['user']:
        print("This script only supports v2 of the API. Please use --token")
        exit()
    else:
        vc = vectra.VectraClient(url=args['url'], token=args['token'])

    if args['action'] == 'list':
        proxies = vc.get_proxies().json()['proxies']
        pprint.pprint(proxies)
    elif args['action'] == 'add':
        resp = vc.add_proxy(host=args['host'])
        pprint.pprint(resp.json()['proxy'])


if __name__ == '__main__':
    main()

