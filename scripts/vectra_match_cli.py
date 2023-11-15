#!/usr/bin/env python
# coding : utf-8

import argparse
import pprint
import sys
import os
import requests
import re
import vat.vectra as vectra
from prettytable import PrettyTable as pt
import logging
import http.client as http_client
import time


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main():
    requests.packages.urllib3.disable_warnings()

    main_parser = argparse.ArgumentParser()
    main_parser.add_argument('--token', required=True, action='store', help='Authentication token')
    main_parser.add_argument('--url', required=True, action='store',
                               help='IP or FQDN for Vectra brain (https://www.example.com)')
    main_parser.add_argument('-v', action='count', help='Print API requests')
    module_subparsers = main_parser.add_subparsers(title='module', dest='module_command', required=True)

    device_parser = module_subparsers.add_parser('device', help='Manage devices')
    device_subparser = device_parser.add_subparsers(title='action', dest='action_command', required=True)

    device_list_subparser = device_subparser.add_parser('list', help='List devices')
    device_list_subparser.add_argument('--details', action='store_true')

    device_stats_subparser = device_subparser.add_parser('stats', help='aaa')
    device_stats_subparser.add_argument('--serial', action='store')

    device_alert_stats_subparser = device_subparser.add_parser('alert-stats', help='aaa')
    device_alert_stats_subparser.add_argument('--serial', action='store')

    device_status_subparser = device_subparser.add_parser('status', help='List devices')
    device_status_subparser.add_argument('--serial', action='store')

    device_enablement_subparser = device_subparser.add_parser('enablement', help='Enable devices')
    device_enablement_subparser.add_argument('--serial', required=True, action='store')
    device_enablement_subparser_group = device_enablement_subparser.add_mutually_exclusive_group(required=True)
    device_enablement_subparser_group.add_argument('--enable', action='store_true')
    device_enablement_subparser_group.add_argument('--disable', action='store_true')

    rule_parser = module_subparsers.add_parser('rule', help='Manage rules')
    rule_subparser = rule_parser.add_subparsers(title='action', dest='action_command', required=True)

    rule_list_subparser = rule_subparser.add_parser('list', help='List rules')
    rule_list_subparser.add_argument('--details', action='store_true')

    rule_upload_subparser = rule_subparser.add_parser('upload', help='Upload rules')
    rule_upload_subparser.add_argument('--file', required=True, action='store')
    rule_upload_subparser.add_argument('--note', action='store')

    rule_delete_subparser = rule_subparser.add_parser('delete', help='Delete rules')
    rule_delete_subparser.add_argument('--uuid', required=True, action='store')

    rule_assign_subparser = rule_subparser.add_parser('assign', help='Add assignments')
    rule_assign_subparser.add_argument('--uuid', required=True, action='store')
    rule_assign_subparser_group = rule_assign_subparser.add_mutually_exclusive_group(required=True)
    rule_assign_subparser_group.add_argument('--serial', action='append')
    rule_assign_subparser_group.add_argument('--all', action='store_true')

    rule_unassign_subparser = rule_subparser.add_parser('unassign', help='Remove assignments')
    rule_unassign_subparser.add_argument('--uuid', required=True, action='store')
    rule_unassign_subparser_group = rule_unassign_subparser.add_mutually_exclusive_group(required=True)
    rule_unassign_subparser_group.add_argument('--serial', action='append')
    rule_unassign_subparser_group.add_argument('--all', action='store_true')

    args = main_parser.parse_args()

    if args.v:
        if args.v > 0:
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
        if args.v > 1:
            http_client.HTTPConnection.debuglevel = 1

    vc = vectra.VectraClientV2_5(url=args.url, token=args.token)

    if args.module_command == 'device':
        if args.action_command == 'list':
            tb = pt()
            devices = vc.get_match_available_devices().json()['devices']
            rules_to_devices_map = vc.get_match_assignment().json()['rules_to_devices_map']
            devices_rules = {}
            for r in rules_to_devices_map:
                for s in r['device_serials']:
                    if s in devices_rules:
                        devices_rules[s].append((r['uuid'], r['name']))
                    else:
                        devices_rules[s] = [(r['uuid'], r['name'])]
            headers = ['Alias', 'Serial', 'Rule UUID', 'Rule name']
            if args.details:
                headers.extend(['Location',
                                'IP Address',
                                'Last seen',
                                'Product name',
                                'Virtual',
                                'Version',
                                'Mode'
                                ])
            tb.field_names = headers
            for device in devices:
                u = []
                n = []
                if device['device_serial'] in devices_rules:
                    u = [s[0] for s in devices_rules[device['device_serial']]]
                    n = [s[1] for s in devices_rules[device['device_serial']]]
                row = [device['alias'] if 'alias' in device else '',
                       device['device_serial'],
                       '\n'.join(u),
                       '\n'.join(n)
                       ]
                if args.details:
                    row.extend([device['location'] if 'location' in device else '',
                                device['ip_address'],
                                device['last_seen'] if 'last_seen' in device else '',
                                device['product_name'],
                                device['is_virtual'],
                                device['version'],
                                device['mode']
                                ])
                tb.add_row(row)
            print(tb)
        elif args.action_command == 'stats':
            if args.serial:
                try:
                    response = vc.get_match_stats(device_serial=args.serial).json()
                except vectra.HTTPException as message:
                    if 'Status code: 404 -' in str(message):
                        print(f'{bcolors.FAIL}Provided device serial is not connected/paired.')
                        sys.exit(1)
                    raise
            else:
                print(vc.get_match_stats().json())
        elif args.action_command == 'alert-stats':
            if args.serial:
                try:
                    alert_stats = vc.get_match_alert_stats(device_serial=args.serial).json()['alert_stats']
                except vectra.HTTPException as message:
                    if 'Status code: 404 -' in str(message):
                        print(f'{bcolors.FAIL}Provided device serial is not connected/paired.')
                        sys.exit(1)
                    raise
            else:
                alert_stats = vc.get_match_alert_stats().json()['alert_stats']
            tb = pt()
            tb.field_names = ['Serial',
                              'Signature',
                              'Signature ID',
                              'Count',
                              'Eve log rotation'
            ]
            for device in alert_stats:
                if device['top_alert_counts']:
                    for alert in device['top_alert_counts']:
                        tb.add_row([device['device_serial'],
                                    alert['signature'],
                                    alert['signature_id'],
                                    alert['count'],
                                    device['eve_log_rotated_time']
                                    ])
                else:
                    tb.add_row([device['device_serial'],
                                '',
                                '',
                                '',
                                device['eve_log_rotated_time']
                                ])
            print(tb)

        elif args.action_command == 'status':
            if args.serial:
                try:
                    status = vc.get_match_status(device_serial=args.serial).json()['status']
                except vectra.HTTPException as message:
                    if 'Provided device serial is not connected/paired' in str(message):
                        print(f'{bcolors.FAIL}Provided device serial is not connected/paired.')
                        sys.exit(1)
                    raise
            else:
                status = vc.get_match_status().json()['status']
            tb = pt()
            tb.field_names = ['Serial',
                              'Enabled',
                              'Process health',
                              'Timestamp',
                              'Process error'
            ]
            for device in status:
                tb.add_row([
                    device['device_serial'],
                    device['is_enabled'],
                    device['process_health'],
                    device['timestamp'],
                    device['process_error_detail']
                ])
            print(tb)
        elif args.action_command == 'enablement':
            if not args.enable and not args.disable:
                enablement = vc.get_match_enablement(device_serial=args.serial).json()
            else:
                if args.enable:
                    state = True
                elif args.disable:
                    state = False
                enablement = vc.set_match_enablement(device_serial=args.serial, state=state).json()
            tb = pt()
            tb.field_names = ['Enabled']
            tb.add_row([enablement['is_enabled']])
            print(tb)
    elif args.module_command == 'rule':
        if args.action_command == 'list':
            rules_to_devices_map = vc.get_match_assignment().json()['rules_to_devices_map']
            devices = vc.get_match_available_devices().json()['devices']
            devices_names = {d['device_serial']: d['alias'] if 'alias' in d else '' for d in devices}
            tb = pt()
            headers = ['Rule UUID', 'Rule name', 'Rule notes', 'Device serial', 'Device alias']
            if args.details:
                headers.extend(['Hash', 'Timestamp'])
            tb.field_names = headers
            for rule in rules_to_devices_map:
                a = [devices_names[s] for s in rule['device_serials']]
                row = [rule['uuid'], rule['name'], rule['notes'], '\n'.join(rule['device_serials']), '\n'.join(a)]
                if args.details:
                    row.extend([rule['hashsum'], rule['timestamp']])
                tb.add_row(row)
            print(tb)
        elif args.action_command == 'upload':
            note = args.note if args.note else None
            if not os.path.exists(args.file):
                print(f'{bcolors.FAIL}Rule file doesn\'t exist')
                sys.exit(1)
            try:
                rule = vc.upload_match_ruleset(file_path=args.file, notes=note).json()
                tb = pt()
                tb.field_names= ['UUID', 'Name', 'Notes', 'Hash', 'Timestamp']
                tb.add_row([rule['uuid'], rule['name'], rule['notes'], rule['hashsum'], rule['timestamp']])
                print(tb)
            except vectra.HTTPException as message:
                if 'Status code: 409 -' in str(message):
                    print(f'{bcolors.FAIL}Provided rules file is a duplicate.')
                    sys.exit(1)
                elif 'Status code: 413 -' in str(message):
                    print(f'{bcolors.FAIL}Provided rules file is too large.')
                    sys.exit(1)
                elif 'Status code: 507 -' in str(message):
                    print(f'{bcolors.FAIL}Could not upload rules. No more space.')
                    sys.exit(1)
                raise
        elif args.action_command == 'delete':
            try:
                details = vc.delete_match_ruleset(uuid=args.uuid).json()
                tb = pt()
                tb.field_names = ['Result']
                tb.add_row([details['details']])
                print(tb)
            except vectra.HTTPException as message:
                if 'Status code: 404 -' in str(message):
                    print(f'{bcolors.FAIL}Provided UUID does not exist.')
                    sys.exit(1)
                raise
        elif args.action_command == 'assign':
            device_serials = [d['device_serial'] for d in vc.get_match_available_devices().json()['devices']]
            if args.all:
                serials = device_serials
            else:
                # Check the provided serial before we use them
                for serial in args.serial:
                    if serial not in device_serials:
                        print(f'{bcolors.FAIL}Provided device serial is not connected/paired.')
                        sys.exit(1)
                serials = args.serial
            # Assign the new rules
            try:
                details = vc.set_match_assignment(uuid=args.uuid, device_list=serials).json()
                tb = pt()
                tb.field_names = ['Result']
                tb.add_row([details['details']])
                print(tb)
            except vectra.HTTPException as message:
                if 'Status code: 404 -' in str(message):
                    print(f'{bcolors.FAIL}Failed to add assignment. Invalid UUID or serial.')
                    sys.exit(1)
                raise
            # Remove all assignments on device
            device_to_rules_map = vc.get_match_assignment().json()['device_to_rules_map']
            device_rules = {d['device_serial']: d['rules'] for d in device_to_rules_map}
            for serial in serials:
                if serial in device_rules:
                    for rule in device_rules[serial]:
                        if rule != args.uuid:
                            vc.delete_match_assignment(uuid=rule, device_serial=serial).json()
        elif args.action_command == 'unassign':
            device_serials = [d['device_serial'] for d in vc.get_match_available_devices().json()['devices']]
            # Check the provided serial before we use them
            if args.all:
                serials = device_serials
            else:
                for serial in args.serial:
                    if serial not in device_serials:
                        print(f'{bcolors.FAIL}Provided device serial is not connected/paired.')
                        sys.exit(1)
                serials = args.serial
            # Remove assignments on device
            for serial in serials:
                try:
                    print(vc.delete_match_assignment(uuid=args.uuid, device_serial=serial).json())
                except vectra.HTTPException as message:
                    print(message)


if __name__ == '__main__':
    main()
