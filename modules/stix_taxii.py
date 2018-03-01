import datetime
import pytz
import random
import string
import sys

from cabby import create_client
from stix.core import STIXPackage

if sys.version_info.major == 2:
    pyversion = 2
    import cStringIO.StringIO as IOhandler
if sys.version_info.major == 3:
    pyversion = 3
    from io import BytesIO as IOhandler


class TaxiiClient(object):
    def __init__(self, url=None, discovery_path=None, https=True, username=None, password=None, cert=None, key=None):
        self.client = create_client(url, use_https=https, discovery_path=discovery_path)
        self.client.set_auth(username=username, password=password, cert_file=cert, key_file=key)

    def discovery(self, uri=None):
        if uri:
            return self.client.discover_services(uri=uri)
        else:
            return self.client.discover_services(uri=self.client.discovery_path)

    def set_discovery_path(self, uri=None):
        self.client.discovery_path = uri

    def collections(self, uri):
        return self.client.get_collections(uri=uri)

    def poll(self, feed=None, duration=None, discovery_path=None):
        if discovery_path:
            self.client.discovery_path = discovery_path

        if int(duration) < 0:
            duration = int(0 - int(duration))
        else:
            duration = int(duration)

        begin_date = datetime.datetime.today() - datetime.timedelta(duration)
        begin_date = begin_date.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=pytz.utc)
        packages = self.client.poll(collection_name=feed, begin_date=begin_date)

        return self._generate_stix_package(packages)

    @staticmethod
    def _generate_stix_package(packages):
        compiled_package = STIXPackage()
        for package in packages:
            sio = IOhandler(package.content)
            sp = STIXPackage.from_xml(sio)
            if sp.indicators:
                [compiled_package.add_indicator(ind) for ind in sp.indicators]
            if sp.observables:
                [compiled_package.add_observable(obs) for obs in sp.observables]
        return compiled_package

    @staticmethod
    def write_stix_file(stix_package, dir='/tmp'):
        ext = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(10)])
        fd = open('{0}/stix_{1}'.format(dir, str(ext)), 'w')
        if pyversion == 2:
            fd.write(stix_package.to_xml(encoding='utf-8'))
        if pyversion == 3:
            fd.write(stix_package.to_xml(encoding='utf-8').decode())
        fd.close()
        return fd.name
