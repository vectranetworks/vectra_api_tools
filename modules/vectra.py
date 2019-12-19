import json
import requests
import warnings
import html
import sys

warnings.filterwarnings('always', '.*', PendingDeprecationWarning)


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)

        if response.status_code in [200, 201, 204]:
            return response
        else:
            # TODO implement exception class to more gracefully handle exception
            raise Exception(response.status_code, response.content)

    return request_handler


def validate_api_v2(func):
    def api_validator(self, *args, **kwargs):
        if self.version == 2:
            return func(self, *args, **kwargs)
        else:
            raise NotImplementedError('Method only accessible via v2 of API')

    return api_validator


def validate_python_v3(func):
    def python_validator(self, *args, **kwargs):
        if sys.version_info >= (3, 0):
            return func(self, *args, **kwargs)
        else:
            raise NotImplementedError('Method only compatible with Python 3')

    return python_validator

def deprecation(message):
    warnings.warn(message, PendingDeprecationWarning)


def param_deprecation(key):
    message = '{0} will be deprecated with Vectra API v1 which will be annouced in an upcoming release'.format(key)
    warnings.warn(message, PendingDeprecationWarning)


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
            self.url = '{url}/api/v2'.format(url=url)
            self.headers = {
                'Authorization': "Token " + token.strip(),
            }
        elif user and password:
            self.url = '{url}/api'.format(url=url)
            self.auth = (user, password)
            deprecation('Deprecation of the Vectra API v1 will be announced in an upcoming release. Migrate to API v2'
                        ' when possible')
        else:
            raise RuntimeError("At least one form of authentication is required. Please provide a token or username"
                               " and password")

    @validate_api_v2
    @request_error_handler
    def mark_detections_fixed(self, detection_ids=None):
        return self._toggle_detections_fixed(detection_ids, True)

    @validate_api_v2
    @request_error_handler
    def unmark_detections_fixed(self, detection_ids=None):
        return self._toggle_detections_fixed(detection_ids, False)

    def _toggle_detections_fixed(self, detection_ids, fixed):
        headers = self.headers.copy()
        headers.update({
            'Content-Type': "application/json",
        })
        payload = {'detectionIdList': detection_ids, 'mark_as_fixed': str(fixed)}

        return requests.patch('{url}/detections'.format(url=self.url), data=json.dumps(payload), headers=headers,
                             verify=self.verify)

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['all', 'active_traffic', 'c_score', 'c_score_gte', 'certainty', 'certainty_gte', 'fields',
                      'has_active_traffic', 'include_detection_summaries', 'is_key_asset', 'is_targeting_key_asset',
                      'key_asset', 'last_source', 'mac_address', 'name', 'ordering', 'page', 'page_size', 'state',
                      't_score', 't_score_gte', 'tags', 'threat', 'threat_gte', 'targets_key_asset', 'note_modified_timestamp_gte']
        deprecated_keys = ['c_score', 'c_score_gte', 'key_asset', 't_score', 't_score_gte', 'targets_key_asset']
        for k, v in args.items():
            if k in valid_keys and v is not None: params[k] = v
            if k in deprecated_keys: param_deprecation(k)
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
                      'threat', 'threat_gte', 'note_modified_timestamp_gte']
        deprecated_keys = ['c_score', 'c_score_gte', 'category', 'detection', 't_score', 't_score_gte', 'targets_key_asset']
        for k, v in args.items():
            if k in valid_keys and v is not None: params[k] = v
            if k in deprecated_keys: param_deprecation(k)
        return params

    def _transform_hosts(self, host_list):
        transformed_list = []
        for host in host_list:
            if isinstance(host, int) or not host.startswith("http"):
                transformed_list.append("{url}/hosts/{id}".format(url=self.url, id=host))
            else:
                transformed_list.append(host)
        return transformed_list

    @validate_api_v2
    @request_error_handler
    def _get_request(self, url, **kwargs):
        params = {}
        for k, v in kwargs.items():
            params[k] = v
        if self.version == 2:
            return requests.get(url, headers=self.headers, params=params, verify=self.verify)
        else:
            return requests.get(url, auth=self.auth, params=params, verify=self.verify)

    # TODO Consolidate get methods
    @request_error_handler
    def get_hosts(self, **kwargs):
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
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        """

        if self.version == 2:
            return requests.get('{url}/hosts'.format(url=self.url), headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/hosts'.format(url=self.url), auth=self.auth,
                                params=self._generate_host_params(kwargs), verify=self.verify)

    def get_all_hosts(self, **kwargs):
        """
        Generator to retrieve all hosts page by page
        Same parameters as get_host()
        """
        resp = self.get_hosts(**kwargs)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
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
            return requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), auth=self.auth,
                                params=self._generate_host_params(kwargs), verify=self.verify)

    # TODO modify to JSON
    @validate_api_v2
    @request_error_handler
    def set_key_asset(self, host_id=None, set=True):
        """
        (Un)set host as key asset
        :param host_id: id of host needing to be set - required
        :param set: set flag to true if setting host as key asset
        """

        if not host_id:
            raise ValueError('Host id required')

        headers = self.headers.copy()
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded'
        })

        if set:
            payload = 'key_asset=True'
        else:
            payload = 'key_asset=False'

        return requests.patch('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=headers, data=payload,
                              verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_host_tags(self, host_id=None):
        """
        Get host tags
        :param host_id:
        """
        return requests.get('{url}/tagging/host/{id}'.format(url=self.url, id=host_id), headers=self.headers,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def set_host_tags(self, host_id=None, tags=[], append=False):
        """
        Set host tags
        :param host_id:
        :param tags: list of tags to add to host
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear tags (default: False)
        """
        if append and type(tags) == list:
            current_list = self.get_host_tags(host_id=host_id).json()['tags']
            payload = {
                "tags": current_list + tags
            }
        elif type(tags) == list:
            payload = {
                "tags": tags
            }
        else:
            raise TypeError('tags must be of type list')

        headers = self.headers.copy()
        headers.update({
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        })

        return requests.patch('{url}/tagging/host/{id}'.format(url=self.url, id=host_id), headers=headers,
                              data=json.dumps(payload), verify=self.verify)

    @validate_api_v2
    @validate_python_v3
    @request_error_handler
    def get_host_note(self, host_id=None):
        """
        Get host notes
        :param host_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete host body, we alter the response content
        """
        host = requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers, verify=self.verify)
        host_note = host.json()['note']
        # API endpoint return HTML escaped characters
        host_note = html.unescape(host_note) if host_note else ''
        json_dict = {'status': 'success', 'host_id': str(host_id), 'note': host_note}
        host._content = json.dumps(json_dict).encode('utf-8')
        return host

    @validate_api_v2
    @validate_python_v3
    @request_error_handler
    def set_host_note(self, host_id=None, note='', append=False):
        """
        Set host note
        :param host_id:
        :param note: content of the note to set
        :param append: overwrites existing note if set to False, appends if set to True
        Set to empty note string to clear host note
        """
        if append and isinstance(note, str):
            current_note = self.get_host_note(host_id=host_id).json()['note']
            if current_note:
                if len(note) > 0:
                    payload = {
                        "note": '{}{}{}'.format(current_note, '\n', note)
                    }
                else:
                    payload = {
                        "note": current_note
                    }
            else:
                payload = {
                    "note": note
                }
        elif isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('note must be of type str')

        headers = self.headers.copy()
        headers.update({
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        })

        return requests.patch('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=headers, data=json.dumps(payload),
                                      verify=self.verify)

    # TODO consolidate get methods
    @request_error_handler
    def get_detections(self, **kwargs):
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
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        """

        if self.version == 2:
            return requests.get('{url}/detections'.format(url=self.url), headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/detections'.format(url=self.url), auth=self.auth,
                                params=self._generate_detection_params(kwargs), verify=self.verify)

    def get_all_detections(self, **kwargs):
        """
        Generator to retrieve all detections page by page
        Same parameters as get_detections()
        """
        resp = self.get_detections(**kwargs)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @request_error_handler
    def get_detection_by_id(self, detection_id=None, **kwargs):
        """
        Get detection by id
        :param detection_id: detection id - required
        :param fields: comma separated string of fields to be filtered and returned
        """
        if not detection_id:
            raise Exception('Detection id required')

        if self.version == 2:
            return requests.get('{url}/detections/{id}'.format(url=self.url, id=detection_id), headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/detections/{id}'.format(url=self.url, id=detection_id), auth=self.auth,
                                params=self._generate_detection_params(kwargs), verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_detection_tags(self, detection_id=None):
        """
        Get detection tags
        :param detection_id:
        """
        return requests.get('{url}/tagging/detection/{id}'.format(url=self.url, id=detection_id), headers=self.headers,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def set_detection_tags(self, detection_id=None, tags=[], append=False):
        """
        Set  detection tags
        :param detection_id:
        :param tags: list of tags to add to detection
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if append and type(tags) == list:
            current_list = self.get_detection_tags(detection_id=detection_id).json()['tags']
            payload = {
                "tags": current_list + tags
            }
        elif type(tags) == list:
            payload = {
                "tags": tags
            }
        else:
            raise TypeError('tags must be of type list')

        headers = self.headers.copy()
        headers.update({
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        })

        return requests.patch('{url}/tagging/detection/{id}'.format(url=self.url, id=detection_id), headers=headers,
                              data=json.dumps(payload), verify=self.verify)

    @validate_api_v2
    def get_rules(self, name=None, rule_id=None):
        """
        Get triage rules
        This function was only kept for backwards compatibility
        :param name: description of triage rule to retrieve
        :param rule_id: id of triage rule to retrieve
        Returns a <Response> object if rule_id is set
        Returns a dict object if name is set (and matches on rule description)
        """
        if rule_id:
            return self.get_rule_by_id(rule_id)
        elif name:
            # The fucntion get_rules_by_name () return a list of all matching rules
            # For backwards compatibility we return only the first
            # CAUTION: we match based on description, and not the actual name
            return self.get_rules_by_name(description = name)[0]
        else:
            raise KeyError("one of the following required: name, rule_id")

    @validate_api_v2
    @request_error_handler
    def get_rule_by_id(self, rule_id):
        """
        Get triage rules by id
        :param rule_id: id of triage rule to retrieve
        """
        return requests.get('{url}/rules/{id}'.format(url=self.url, id=rule_id), headers=self.headers, verify=False)

    @validate_api_v2
    def get_rules_by_name(self, triage_category=None, description=None):
        """
        Get triage rules by name or description
        Condition are to be read as OR
        :param triage_category: 'Triage as' field of filter
        :param description: Description of the triage filter
        """
        rules = []
        for page in self.get_all_rules():
            for rule in page.json()['results']:
                if rule['description'] is not None and rule['description'] == description:
                    rules.append(rule)
                elif rule['triage_category'] is not None and rule['triage_category'] == triage_category:
                    rules.append(rule)
        return rules

    @validate_api_v2
    def get_all_rules(self):
        """
        Generator to retrieve all rules page by page
        """
        resp = self._get_request(url = '{url}/rules'.format(url=self.url))
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    @request_error_handler
    def create_rule(self, detection_category=None, detection_type=None, triage_category=None, description=None,
                    is_whitelist=False, ip=[], host=[], sensor_luid=[], all_hosts=False, **kwargs):
        """
        Create triage rule
        :param detection_category: detection category to triage [botnet activity, command & control, reconnaissance,
        lateral movement, exfiltration]
        :param detection_type: detection type to triage
        :param triage_category: name that will be used for triaged detection
        :param description: name of the triage rule
        :param is_whitelist: set to True if rule is to whitelist; opposed to tracking detecitons without scores (boolean)
        :param ip: list of ip addresses to apply to triage rule
        :param host: list of host ids to apply to triage rule
        :param sensor_luid: list of sensor luids to triage
        :param all_hosts: apply triage rule to all hosts (boolean)
        :param remote1_ip: destination ip addresses to triage
        :param remote1_dns: destination hostnames to triage
        :param remote1_port: destination ports to  triage
        :returns request object
        """
        if not all([detection_category, detection_type, triage_category, description]):
            raise KeyError("missing required parameter: "
                             "detection_category, detection_type, triage_category, description")

        if detection_category.lower() not in ['botnet activity', 'command & control', 'reconnaissance',
                                              'lateral movement', 'exfiltration']:
            raise ValueError("detection_category not recognized")

        if not any([ip, host, sensor_luid, all_hosts]):
            raise KeyError("one of the following required: ip, host, sensor_luid, all_hosts")

        # TODO migrate detection to detection_type
        # TODO change description to name
        payload = {
            "all_hosts": all_hosts,
            "detection_category": detection_category,
            "detection": detection_type,
            "triage_category": triage_category,
            "description": description,
            "is_whitelist": is_whitelist,
        }

        if host and not all_hosts:
            if type(host) and not type(host) == list:
                raise TypeError("host must be type: list")
            payload['host'] = self._transform_hosts(host)
        elif ip and not all_hosts:
            if ip and not type(ip) == list:
                raise TypeError("ip must be type: list")
            payload['ip'] = ip
        elif sensor_luid and not  all_hosts:
            if sensor_luid and not type(sensor_luid):
                raise TypeError("sensor_luid must be type: list")
            payload['sensor_luid'] = sensor_luid

        for k, v in kwargs.items():
            if not type(v) == list:
                raise TypeError("{} must be of type: list".format(k))
            payload[k] = v

        return requests.post('{url}/rules'.format(url=self.url), headers=self.headers, json=payload,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_rule(self, rule_id=None, name=None, append=False, **kwargs):
        """
        Update triage rule
        :param rule_id: id of rule to update
        :param name: name of rule to update
        :param append: set to True if appending to existing list (boolean)
        :param ip: list of ip addresses to apply to triage rule
        :param host: list of host ids to apply to triage rule
        :param sensor_luid: list of sensor luids to triage
        :param remote1_ip: destination ip addresses to triage
        :param remote1_dns: destination hostnames to triage
        :param remote1_port: destination ports to  triage
        """
        id = None
        if name:
            matching_rules = self.get_rules_by_name(triage_category=name)
            if len(matching_rules) > 1:
                raise Exception('More than one rule matching the name')
            elif len(matching_rules) < 1:
                raise Exception('No rule matching the search')
            else:
                id = matching_rules[0]['id']
        elif rule_id:
            id = rule_id
        else:
            raise ValueError("rule name or id must be provided")

        rule = self.get_rule_by_id(rule_id=id).json()

        valid_keys = ['ip', 'host', 'sensor_luid', 'remote1_ip', 'remote1_dns', 'remote1_port']

        for k, v in kwargs.items():
            if k not in valid_keys:
                raise KeyError('invalid parameter provided. acceptable params: {}'.format(valid_keys))
            if not type(v) == list:
                raise TypeError('{} must be of type: list'.format(k))

            if append:
                if k == 'host':
                    rule[k] += self._transform_hosts(v)
                else:
                    rule[k] += v
            else:
                rule[k] = v

        return requests.put('{url}/rules/{id}'.format(url=self.url, id=id), headers=self.headers, json=rule,
                            verify=self.verify)

    @validate_api_v2
    def delete_rule(self, rule_id=None, restore_detections=True):
        """
        Delete triage rule
        :param rule_id:
        :param restore_detections: restore previously triaged detections (bool) default behavior is to restore
        detections
        """
        params = {
            'restore_detections': restore_detections
        }

        return requests.delete('{url}/rules/{id}'.format(url=self.url, id=rule_id), headers=self.headers, params=params,
                               verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_group_by_id(self, group_id):
        """
        Get groups by id
        :param rule_id: id of group to retrieve
        """
        return requests.get('{url}/groups/{id}'.format(url=self.url, id=group_id), headers=self.headers, verify=False)

    @validate_api_v2
    def get_all_groups(self):
        """
        Generator to retrieve all Groups page by page
        """
        resp = self._get_request(url = '{url}/groups'.format(url=self.url))
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    def get_groups_by_name(self, name=None, description=None):
        """
        Get groups by name or description
        Condition are to be read as OR
        :param name: Name of group
        :param description: Description of the group
        """
        groups = []
        for page in self.get_all_groups():
            for group in page.json()['results']:
                if group['name'] is not None and group['name'] == name:
                    groups.append(group)
                elif group['description'] is not None and group['description'] == description:
                    groups.append(group)
        return groups

    @validate_api_v2
    @request_error_handler
    def create_group(self, name=None, description='', type='host', members=[], rules=[], **kwargs):
        """
        Create group
        :param name: name of the group to create
        :param description: description of the group
        :param type: type of the group to create #TODO specify what type
        :param members: list of host ids to add to group
        :param rules: list of triage rule ids to add to group
        :returns request object
        """
        if not name:
            raise KeyError("missing required parameter: name")
        if not isinstance(members, list):
            raise TypeError("members must be type: list")
        if not isinstance(rules, list):
            raise TypeError("rules must be type: list")

        # TODO migrate detection to detection_type
        # TODO change description to name
        payload = {
            "name": name,
            "description": description,
            "type": type,
            "members": members,
            "rules": rules,
        }

        for k, v in kwargs.items():
            if not type(v) == list:
                raise TypeError("{} must be of type: list".format(k))
            payload[k] = v

        return requests.post('{url}/groups'.format(url=self.url), headers=self.headers, json=payload,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_group(self, group_id, append=False, **kwargs):
        """
        Update group
        :param group_id: id of group to update
        :param name: name of group
        :param description: description of the group
        :param type: type of the group to create #TODO specify what type
        :param members: list of host ids to add to group
        :param rules: list of rule ids to add to group
        :param append: set to True if appending to existing list (boolean)
        """
        valid_keys = ['name', 'description', 'type', 'members', 'rules']

        group = self.get_group_by_id(group_id = group_id).json()
        try:
            id = group['id']
        except KeyError:
            raise KeyError('Group with id {} was not found'.format(str(group_id)))

        for k, v in kwargs.items():
            if k in valid_keys and v is not None:
                if k in ['members', 'rules'] and not isinstance(v, list):
                    raise TypeError('{} must be of type: list'.format(k))
                if append:
                    group[k] += self._transform_hosts(v) if k == 'members' else v
                else:
                    group[k] = v
            else:
                raise KeyError('Key {} is not valid'.format(k))

        return requests.patch('{url}/groups/{id}'.format(url=self.url, id=id), headers=self.headers, json=group,
                            verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def delete_group(self, group_id=None):
        """
        Delete group
        :param group_id:
        detections
        """
        return requests.delete('{url}/groups/{id}'.format(url=self.url, id=group_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_proxies(self, proxy_id=None):
        if proxy_id:
            return requests.get('{url}/proxies/{id}'.format(url=self.url, id=proxy_id), headers=self.headers,
                                verify=self.verify)
        else:
            return requests.get('{url}/proxies'.format(url=self.url), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def add_proxy(self, address=None, enable=True):
        headers = self.headers.copy()
        headers.update({
            "Content-Type": "application/json"
        })

        payload = {
            "proxy": {
                "address": address,
                "considerProxy": enable
            }
        }

        return requests.post('{url}/proxies'.format(url=self.url), json=payload, headers=headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_proxy(self, proxy_id=None, address=None, enable=True):
        headers = self.headers.copy()
        headers.update({
            "Content-Type": "application/json"
        })

        proxy = self.get_proxies(proxy_id=proxy_id).json()['proxies']
        payload = {"proxy": {}}
        if address is not None:
            payload["proxy"]["address"] = address
        if enable is not None:
            payload["proxy"]["considerProxy"] = enable

        return requests.patch('{url}/proxies/{id}'.format(url=self.url, id=proxy_id), json=payload, headers=headers,
                              verify=self.verify)

    @validate_api_v2
    def delete_proxy(self,proxy_id=None):
        return requests.delete('{url}/proxies/{id}'.format(url=self.url, id=proxy_id), headers=self.headers,
                              verify=self.verify)

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

        # TODO update category to detection_category
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

        headers = self.headers.copy()
        headers.update({
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        })

        return requests.post('{url}/threatFeeds'.format(url=self.url), data=json.dumps(payload), headers=headers,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def delete_feed(self, feed_id=None):
        """
        Deletes threat feed from Vectra
        :param feed_id: id of threat feed (returned by get_feed_by_name())
        """
        return requests.delete('{url}/threatFeeds/{id}'.format(url=self.url, id=feed_id),
                               headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_feeds(self):
        """
        Gets list of currently configured threat feeds
        """
        return requests.get('{url}/threatFeeds'.format(url=self.url), headers=self.headers, verify=self.verify)

    @validate_api_v2
    def get_feed_by_name(self, name=None):
        """
        Gets configured threat feed by name and returns id (used in conjunction with updating and deleting feeds)
        :param name: name of threat feed
        """
        try:
            response = requests.get('{url}/threatFeeds'.format(url=self.url), headers=self.headers, verify=self.verify)
        except requests.ConnectionError:
            raise Exception('Unable to connect to remote host')

        if response.status_code == 200:
            for feed in response.json()['threatFeeds']:
                if feed['name'].lower() == name.lower():
                    return feed['id']
        else:
            raise Exception(response.status_code, response.content)

    @validate_api_v2
    @request_error_handler
    def post_stix_file(self, feed_id=None, stix_file=None):
        """
        Uploads STIX file to new threat feed or overwrites STIX file in existing threat feed
        :param feed_id: id of threat feed (returned by get_feed_by_name)
        :param stix_file: stix filename
        """
        return requests.post('{url}/threatFeeds/{id}'.format(url=self.url, id=feed_id), headers=self.headers,
                             files={'file': open(stix_file)}, verify=self.verify)

    @validate_api_v2
    def advanced_search(self, stype=None, page_size=50, query=None):
        """
        Advanced search
        :param stype: search type (hosts, detections)
        :param page_size: number of objects returned per page (default: 50, max: 5000)
        :param advanced query (download the following guide for more details on query language
            https://support.vectranetworks.com/hc/en-us/articles/360003225254-Search-Reference-Guide)
        """
        if stype not in ["hosts", "detections"]:
            raise ValueError("Supported values for stype are hosts or detections")

        url = '{url}/search/{stype}/?page_size={ps}&query_string={query}'.format(url=self.url, stype=stype,
                                                ps=page_size, query=query)
        resp = self._get_request(url=url)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp
