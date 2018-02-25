import json
import requests

# requests.packages.urllib3.disable_warnings()


def request_error_handler(func):
    def request_handler(self, **kwargs):
        response = func(self, **kwargs)

        if response.status_code in [200, 201]:
            return response
        else:
            # TODO implement execption class to more gracefully hanle exception
            raise Exception(response.status_code, response.content)

    return request_handler


def validate_api_v2(func):
    def api_validator(self, **kwargs):
        if self.version == 2:
            return func(self, **kwargs)
        else:
            raise Exception('Method only accessible via v2 of API')

    return api_validator


class VectraClient(object):

    def __init__(self, url=None, token=None, user=None, password=None, verify=False):
        """
        Initialize Vectra client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param token: API token for authentication when using API v2*
        :param user: Username to authenticate to Vectra brain when using API v1*
        :param password: Password when using username to authenticate using API v1*
        :param verify: Verify SSL (default: False) - optional
        :rtype: requests object
        *Either token or user are required
        """
        self.url = url
        self.version = 2 if token else 1
        self.verify = verify

        if token:
            self.url = url + '/api/v2'
            self.headers = {
                'Authorization': "Token " + token.strip(),
            }
        elif user and password:
            self.url = url + '/api'
            self.auth = (user, password)
        else:
            raise Exception("At least one form of authentication is required. "
                            "Please provide a token or username and password")

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['active_traffic', 'c_score', 'c_score_gte', 'certainty', 'certainty_gte', 'fields',
                      'has_active_traffic', 'include_detection_summaries', 'is_key_asset', 'is_targeting_key_asset',
                      'key_asset', 'last_source', 'mac_address', 'name', 'ordering', 'page', 'page_size', 'state',
                      't_score', 't_score_gte', 'tags', 'threat', 'threat_gte', 'targets_key_asset']
        for k, v in args.items():
            # TODO log deprecated keys
            if k in valid_keys and v is not None: params[k] = v

        return params

    @staticmethod
    def _generate_detection_params(args):
        """
        Generate query parameters for detections based provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['c_score', 'c_score_gte', 'category', 'certainty', 'certainty_gte', 'detection', 'detection_type',
                      'detection_category', 'fields', 'host_id', 'is_targeting_key_asset', 'is_triaged', 'ordering',
                      'page', 'page_size', 'src_ip', 'state', 't_score', 't_score_gte', 'tags', 'targets_key_asset',
                      'threat', 'threat_gte']
        for k, v in args.items():
            # TODO log deprecated keys
            if k in valid_keys and v is not None: params[k] = v

        return params

    @request_error_handler
    def get_hosts(self, **kwargs):
        # TODO convert to generator or create new method get_all_hosts()
        """
        Query all hosts - all parameters are optional
        :param active_traffic: host has active traffic (bool)
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param fields: comma separated string of fields to be filtered and returned
        :param has_active_traffic: host has active traffic (bool)
        :param include_detection_summaries: include detection summary in response (bool)
        :param is_key_asset: host is key asset (bool)
        :param is_targeting_key_asset: host is targeting key asset (bool)
        :param key_asset: host is key asset (bool) - will be removed with deprecation of v1 of api
        :param last_source: registered ip address of host
        :param mac_address: registered mac address of host
        :param name: registered name of host
        :param ordering: field to use to order response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param state: state of host (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score greater than or equal to (int) - will be removed with deprection of v1 of api
        :param tags: tags assigned to host
        :param targets_key_asset: host is targeting key asset (bool)
        :param threat: threat score (int)
        :param threat_gte: threat score greater than or equal to (int)
        """

        if self.version == 2:
            return requests.get(self.url + '/hosts', headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        else:
            return requests.get(self.url + '/hosts', auth=self.auth, params=self._generate_host_params(kwargs),
                                verify=self.verify)

    def get_all_hosts(self, **kwargs):
        """
        Generator to retrieve all hosts page by page
        Same parameters as get_host()
        """
        resp = self.get_hosts(**kwargs)
        yield resp
        while resp.json()['next']:
            url = resp.json()['next']
            path = url.replace(self.url, '')
            resp = self.custom_endpoint(path=path)
            yield resp

    @request_error_handler
    def get_host_by_id(self, host_id=None, **kwargs):
        """
        Get host by id
        :param host_id: host id - required
        :param fields: comma separated string of fields to be filtered and returned - optional
        """
        if not host_id:
            raise Exception('Host id required')

        if self.version == 2:
            return requests.get(self.url + '/hosts/' + str(host_id), headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        else:
            return requests.get(self.url + '/hosts/' + str(host_id), auth=self.auth,
                                params=self._generate_host_params(kwargs), verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def set_key_asset(self, host_id=None, set=True):
        """
        (Un)set host as key asset
        :param id: id of host needing to be set - required
        :param set: set flag to true if setting host as key asset
        """

        if not host_id:
            raise Exception('Host id required')

        headers = self.headers
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded'
        })

        if set:
            payload = 'key_asset=True'
        else:
            payload = 'key_asset=False'

        return requests.patch(self.url + '/hosts/' + str(host_id), headers=headers, data=payload,
                              verify=self.verify)

    @request_error_handler
    def get_detections(self, **kwargs):
        # TODO convert to generator or create new metho get_all_detections()
        """
        Query all detections - all paramters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param category: detection category - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param detection:
        :param detection_type: detection type
        :param detection_category: detection category
        :param fields: comma separated string of fields to be filtered and returned
        :param host_id: detection id (int)
        :param is_targeting_key_asset: detection is targeting key asset (bool)
        :param is_triaged: detection is triaged
        :param ordering: field used to sort response
        :param src_ip: source ip address of host attributed to detection
        :param state: state of detection (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param tags: tags assigned to detection
        :param targets_key_asset: detection targets key asset (bool) - will be removed with deprecation of v1 of api
        :param threat: threat score (int)
        :param threat_gte threat score is greater than or equal to (int)
        """

        if self.version == 2:
            return requests.get(self.url + '/detections', headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        else:
            return requests.get(self.url + '/detections', auth=self.auth, params=self._generate_host_params(kwargs),
                                verify=self.verify)

    def get_all_detections(self, **kwargs):
        """
        Generator to retrieve all detections page by page
        Same parameters as get_detections()
        """
        resp = self.get_detections(**kwargs)
        yield resp
        while resp.json()['next']:
            url = resp.json()['next']
            path = url.replace(self.url, '')
            resp = self.custom_endpoint(path=path).json()
            yield resp

    @request_error_handler
    def get_detection_by_id(self, detection_id=None, **kwargs):
        """
        Get detection by id
        :param det_id: detection id - required
        :param fields: comma separated string of fields to be filtered and returned
        """
        if not detection_id:
            raise Exception('Detection id required')

        if self.version == 2:
            return requests.get(self.url + '/detections/' + str(detection_id), headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        else:
            return requests.get(self.url + '/detections/' + str(detection_id), auth=self.auth,
                                params=self._generate_detection_params(kwargs), verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def create_feed(self, name=None, category=None, certainty=None, itype=None, duration=None):
        """
        Creates new threat feed
        ***Values for category, type, and certainty are case sensitive***
        :param name: name of threat feed
        :param category: category that detection will register. supported values are lateral, exfil, and cnc
        :param certainty: certainty applied to detection. Supported values are Low, Medium, High
        :param itype: indicator type - supported values are Anonymize, Exfiltration, Malware Artifacts, and Watchlist
        :param duration: days that the threat feed will be applied
        :returns: request object
        """

        payload = {
            "threatFeed": {
                "name": name,
                "defaults": {
                    "category": category,
                    "certainty": certainty,
                    "indicatorType": itype,
                    "duration": duration
                }
            }
        }

        headers = self.headers
        headers.update({
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        })

        return requests.post(self.url + '/threatFeeds', data=json.dumps(payload), headers=headers,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def delete_feed(self, feed_id=None):
        """
        Deletes threat feed from Vectra
        :param feed_id: id of threat feed (returned by get_feed_by_name())
        """
        return requests.delete(self.url + '/api/v2/threatFeeds/' + str(feed_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_feeds(self):
        """
        Gets list of currently configured threat feeds
        """
        return requests.get(self.url + '/threatFeeds', headers=self.headers, verify=self.verify)

    @validate_api_v2
    def get_feed_by_name(self, name=None):
        """
        Gets configured threat feed by name and returns id (used in conjunction with updating and deleting feeds)
        :param name: name of threat feed
        """
        try:
            response = requests.get(self.url + '/threatFeeds', headers=self.headers, verify=self.verify)
        except requests.ConnectionError:
            raise Exception('Unable to connect to remote host')

        if response.status_code == 200:
            for feed in response.json()['threatFeeds']:
                if feed['name'].lower() == name.lower():
                    return feed['id']
        else:
            print "Error code: " + str(response.status_code)
            raise Exception(response.content)

    @validate_api_v2
    @request_error_handler
    def post_stix_file(self, feed_id=None, stix_file=None):
        """
        Uploads STIX file to new threat feed or overwrites STIX file in existing threat feed
        :param feed_id: id of threat feed (returned by get_feed_by_name)
        :param stix_file: stix filename
        """
        return requests.post(self.url + '/threatFeeds/' + str(feed_id), headers=self.headers, files={'file': open(stix_file)}, verify=self.verify)

    @request_error_handler
    def custom_endpoint(self, path=None, **kwargs):
        if not str(path).startswith('/'):
            path = '/' + str(path)

        params = {}
        for k, v in kwargs.items():
            params[k] = v

        if self.version == 2:
            return requests.get(self.url + path, headers=self.headers, params=params, verify=self.verify)
        else:
            return requests.get(self.url + path, auth=self.auth, params=params, verify=self.verify)