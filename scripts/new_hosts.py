#! /usr/bin/env python

import argparse
import logging
import requests
import smtplib
import vat.vectra as vectra

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from tinydb import TinyDB, Query


requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', action='store_true', help='enable debugging')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

params = {
    'url': '',
    'token': '',
    'smtp_server': '',
    'smtp_port': '',
    'username': '',
    'password': '',
    'fromAddr': '',
    'toAddr': ''
}

vdb = TinyDB('vectra.json')
ht = vdb.table('hosts')
upd = vdb.table('updates')

vc = vectra.VectraClient(url=params['url'], token=params['token'])
hosts = vc.get_hosts(fields='id,name,last_source').json()['results']


def insert_host(db, host):
    db.insert({
        'id': host['id'],
        'name': host['name'],
        'ip': host['last_source']
    })


def send_message(hosts):
    msg = MIMEMultipart()
    msg['From'] = params['fromAddr']
    msg['To'] = params['toAddr']
    msg['Subject'] = 'New hosts discovered'

    message = 'The following hosts have been recently detected:\n\n'
    for host in hosts:
        message += '\t* {name}: {ip}\n'.format(name=host['name'], ip=host['ip'])
    msg.attach(MIMEText(message, 'plain'))

    server = smtplib.SMTP(host=params['smtp_server'], port=params['smtp_port'])
    server.starttls()
    server.login(params['username'], params['password'])
    server.sendmail(params['fromAddr'], params['toAddr'], msg.as_string())
    server.quit()

    logger.info('message sent: {src}, {dst}, {msg}'.format(src=params['fromAddr'], dst=params['toAddr'], msg=message))


def main():
    if len(ht) > 0:
        Host = Query()
        [insert_host(upd, host) for host in hosts if not ht.search(Host.id == host['id'])]
        ht.insert_multiple(upd.all())
        logger.info('hosts added: {num}'.format(num=len(upd)))
        [logger.debug('id: {id}, host: {name}, ip: {ip} added'.format(id=host['id'], name=host['name'],
            ip=host['last_source'])) for host in hosts]

        if len(upd) > 0:
            send_message(upd)
            vdb.purge_table('updates')
    else:
        logger.info('initial pass')
        logger.info('creating hosts table')
        [insert_host(ht, host) for host in hosts]
        logger.info('hosts added: {num}'.format(num=len(ht)))
        [logger.debug('id: {id}, host: {name}, ip: {ip} added'.format(id=host['id'], name=host['name'],
            ip=host['last_source'])) for host in hosts]


if __name__ == '__main__':
    main()
