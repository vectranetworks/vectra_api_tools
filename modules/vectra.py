import json
import requests
import warnings
import html
import re
import copy
import ipaddress


warnings.filterwarnings('always', '.*', PendingDeprecationWarning)

class HTTPException(Exception):
    def __init__(self, response):
        """ 
        Custom exception class to report possible API errors
        The body is contructed by extracting the API error code from the requests.Response object
        """
        try: 
            r = response.json()
            if 'detail' in r:
                detail = r['detail']
            elif 'errors' in r:
                detail = r['errors'][0]['title']
            elif '_meta' in r:
                detail = r['_meta']['message']
            else:
                detail = response.content
        except Exception: 
            detail = response.content
        body = 'Status code: {code} - {detail}'.format(code=str(response.status_code), detail=detail)
        super().__init__(body)


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        
        if response.status_code in [200, 201, 204]:
            return response
        else:
            raise HTTPException(response)

    return request_handler


def validate_api_v2(func):
    def api_validator(self, *args, **kwargs):
        if self.version == 2:
            return func(self, *args, **kwargs)
        else:
            raise NotImplementedError('Method only accessible via v2 of API')

    return api_validator


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
        *Either token or user are required
        """
        self.url = url
        self.version = 2 if token else 1
        self.verify = verify

        url = VectraClient._remove_trailing_slashes(url)

        if token:
            self.url = '{url}/api/v2'.format(url=url)
            self.headers = {
                'Authorization': "Token " + token.strip(),
                'Content-Type': "application/json",
                'Cache-Control': "no-cache"
            }
        elif user and password:
            self.url = '{url}/api'.format(url=url)
            self.auth = (user, password)
            deprecation('Deprecation of the Vectra API v1 will be announced in an upcoming release. Migrate to API v2'
                        ' when possible')
        else:
            raise RuntimeError("At least one form of authentication is required. Please provide a token or username"
                               " and password")

    @staticmethod
    def _remove_trailing_slashes(url):
        url = url[:-1] if url.endswith('/') else url
        return url

    @staticmethod
    def _generate_campaign_params(args):
        """
        Generate query parameters for campaigns based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['fields', 'dst_ip', 'target_domain', 'state', 'name', 'last_updated_gte',
            'note_modified_timestamp_gte','page', 'page_size']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid campaign query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['active_traffic', 'all', 'c_score', 'c_score_gte', 'certainty', 'certainty_gte',
            'fields', 'has_active_traffic', 'include_detection_summaries', 'is_key_asset', 'is_targeting_key_asset',
            'key_asset', 'last_detection_timestamp', 'last_source', 'mac_address', 'max_id', 'min_id',
            'name', 'note_modified_timestamp_gte', 'ordering','page', 'page_size', 'privilege_category',
            'privilege_level', 'privilege_level_gte', 'state', 't_score', 't_score_gte', 'tags',
            'targets_key_asset', 'threat', 'threat_gte']
        deprecated_keys = ['c_score', 'c_score_gte', 'key_asset', 't_score', 't_score_gte', 'targets_key_asset']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid host query parameter'.format(str(k)))
            if k in deprecated_keys: param_deprecation(k)
        return params

    @staticmethod
    def _generate_host_by_id_params(args):
        """
        Generate query parameters for host based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['fields', 'include_external', 'include_ldap']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid host query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_detection_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['c_score', 'c_score_gte', 'category', 'certainty', 'certainty_gte', 'description',
            'detection', 'detection_category', 'detection_type', 'fields', 'host_id', 'is_targeting_key_asset',
            'is_triaged', 'last_timestamp', 'max_id', 'min_id', 'note_modified_timestamp_gte', 'ordering',
            'page', 'page_size', 'src_ip', 'state', 't_score', 't_score_gte', 'tags', 'targets_key_asset',
            'threat', 'threat_gte']
        deprecated_keys = ['c_score', 'c_score_gte', 'category', 'detection', 't_score', 't_score_gte', 'targets_key_asset']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid detection query parameter'.format(str(k)))
            if k in deprecated_keys: param_deprecation(k)
        return params

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['description', 'domains', 'host_ids', 'host_names', 'last_modified_by',
            'last_modified_timestamp', 'name', 'page', 'page_size', 'type']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid group query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_rule_params(args):
        """
        Generate query parameters for rules based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['contains', 'fields', 'include_templates', 'page', 'page_size', 'ordering']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid rule query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_rule_by_id_params(args):
        """
        Generate query parameters for rule based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['fields']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid rule query parameter'.format(str(k)))
        return params
    
    @staticmethod
    def _generate_user_params(args):
        """
        Generate query parameters for users based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['username', 'role', 'account_type', 'authentication_profile', 'last_login_gte']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid user query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_ip_address_params(args):
        """
        Generate query parameters for ip address queries based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['include_ipv4', 'include_ipv6']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid ip address query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_subnet_params(args):
        """
        Generate query parameters for subnet queries based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['ordering', 'search']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid subnet query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_internal_network_params(args):
        """
        Generate query parameters for internal network queries based on provided argsbased on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['include_ipv4', 'include_ipv6']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid internal network query parameter'.format(str(k)))
        return params

    @validate_api_v2
    @request_error_handler
    def _get_request(self, url, **kwargs):
        """ 
        Do a get request on the provided URL
        This is used by paginated endpoints
        :rtype: requests.Response
        """
        params = {}
        for k, v in kwargs.items():
            params[k] = v
        if self.version == 2:
            return requests.get(url, headers=self.headers, params=params, verify=self.verify)
        else:
            return requests.get(url, auth=self.auth, params=params, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_campaigns(self, **kwargs):
        """
        Query all campaigns - all parameters are optional
        :param dst_ip: filter on campaign destination IP
        :param target_domain: filter on campaign destination domain
        :param state: campaign state, possible values are: init, active, closed, closed_never_active
        :param name: filter on campaign name
        :param last_updated_gte: return only campaigns with a last updated timestamp gte (datetime)
        :param note_modified_timestamp_gte: return only campaigns with a last updated timestamp on their note gte (datetime)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id, dst_ip, target_domain, state, name, last_updated, 
            note, note_modified_by, note_modified_timestamp
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        return requests.get('{url}/campaigns'.format(url=self.url), headers=self.headers,
                                params=self._generate_campaign_params(kwargs), verify=self.verify)
    
    def get_all_campaigns(self, **kwargs):
        """
        Generator to retrieve all campaigns - all parameters are optional
        :param dst_ip: filter on campaign destination IP
        :param target_domain: filter on campaign destination domain
        :param state: campaign state, possible values are: init, active, closed, closed_never_active
        :param name: filter on campaign name
        :param last_updated_gte: return only campaigns with a last updated timestamp gte (datetime)
        :param note_modified_timestamp_gte: return only campaigns with a last updated timestamp on their note gte (datetime)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id, dst_ip, target_domain, state, name, last_updated, 
            note, note_modified_by, note_modified_timestamp
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        resp = requests.get('{url}/campaigns'.format(url=self.url), headers=self.headers,
                                params=self._generate_campaign_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp

    @validate_api_v2
    @request_error_handler
    def get_campaign_by_id(self, campaign_id=None, **kwargs):
        """
        Get campaign by id
        """
        if not campaign_id:
            raise ValueError('Campaign id required')

        return requests.get('{url}/campaigns/{id}'.format(url=self.url, id=campaign_id),
            headers=self.headers, verify=self.verify)

    @request_error_handler
    def get_hosts(self, **kwargs):
        """
        Query all hosts - all parameters are optional
        :param all: if set to False, endpoint will only return hosts that have active detections, active traffic or are marked as key assets - default False
        :param active_traffic: only return hosts that have seen traffic in the last 2 hours (bool)
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id,name,active_traffic,has_active_traffic,t_score,threat,c_score,
            certainty,severity,last_source,ip,previous_ips,last_detection_timestamp,key_asset,
            is_key_asset,state,targets_key_asset,is_targeting_key_asset,detection_set,
            host_artifact_set,sensor,sensor_name,tags,note,note_modified_by,note_modified_timestamp,
            url,host_url,last_modified,assigned_to,assigned_date,groups,has_custom_model,privilege_level,
            privilege_category,probable_owner,detection_profile
        :param has_active_traffic: host has active traffic (bool)
        :param include_detection_summaries: include detection summary in response (bool)
        :param is_key_asset: host is key asset (bool)
        :param is_targeting_key_asset: host is targeting key asset (bool)
        :param key_asset: host is key asset (bool) - will be removed with deprecation of v1 of api
        :param last_detection_timestamp: timestamp of last detection on this host (datetime)
        :param last_source: registered ip addst modified timestamp greater than or equal to (datetime)ress of host
        :param mac_address: registered mac address of host
        :param max_id: maximum ID of host returned
        :param min_id: minimum ID of host returned
        :param name: registered name of host
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        :param ordering: field to use to order response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param privilege_category: privilege category of host (low/medium/high)
        :param privilege_level: privilege level of host (0-10)
        :param privilege_level_gte: privilege level of host greater than or equal to (int)
        :param state: state of host (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score greater than or equal to (int) - will be removed with deprection of v1 of api
        :param tags: tags assigned to host
        :param targets_key_asset: host is targeting key asset (bool)
        :param threat: threat score (int)
        :param threat_gte: threat score greater than or equal to (int)
        """

        if self.version == 2:
            return requests.get('{url}/hosts'.format(url=self.url), headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/hosts'.format(url=self.url), auth=self.auth,
                                params=self._generate_host_params(kwargs), verify=self.verify)

    def get_all_hosts(self, **kwargs):
        """
        Generator to retrieve all hosts - all parameters are optional
        :param all: if set to False, endpoint will only return hosts that have active detections, active traffic or are marked as key assets - default False
        :param active_traffic: only return hosts that have seen traffic in the last 2 hours (bool)
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id,name,active_traffic,has_active_traffic,t_score,threat,c_score,
            certainty,severity,last_source,ip,previous_ips,last_detection_timestamp,key_asset,
            is_key_asset,state,targets_key_asset,is_targeting_key_asset,detection_set,
            host_artifact_set,sensor,sensor_name,tags,note,note_modified_by,note_modified_timestamp,
            url,host_url,last_modified,assigned_to,assigned_date,groups,has_custom_model,privilege_level,
            privilege_category,probable_owner,detection_profile
        :param has_active_traffic: host has active traffic (bool)
        :param include_detection_summaries: include detection summary in response (bool)
        :param is_key_asset: host is key asset (bool)
        :param is_targeting_key_asset: host is targeting key asset (bool)
        :param key_asset: host is key asset (bool) - will be removed with deprecation of v1 of api
        :param last_detection_timestamp: timestamp of last detection on this host (datetime)
        :param last_source: registered ip addst modified timestamp greater than or equal to (datetime)ress of host
        :param mac_address: registered mac address of host
        :param max_id: maximum ID of host returned
        :param min_id: minimum ID of host returned
        :param name: registered name of host
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        :param ordering: field to use to order response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param privilege_category: privilege category of host (low/medium/high)
        :param privilege_level: privilege level of host (0-10)
        :param privilege_level_gte: privilege level of host greater than or equal to (int)
        :param state: state of host (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score greater than or equal to (int) - will be removed with deprection of v1 of api
        :param tags: tags assigned to host
        :param targets_key_asset: host is targeting key asset (bool)
        :param threat: threat score (int)
        :param threat_gte: threat score greater than or equal to (int)
        """
        resp = requests.get('{url}/hosts'.format(url=self.url), headers=self.headers,
                                params=self._generate_host_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp

    @request_error_handler
    def get_host_by_id(self, host_id=None, **kwargs):
        """
        Get host by id
        :param host_id: host id - required
        :param include_external: include fields regarding external connectors (e.g. CrowdStrike) - optional
        :param include_ldap: include LDAP context pulled over AD connector - optional
        :param fields: comma separated string of fields to be filtered and returned - optional
            possible values are: active_traffic, assigned_date, assigned_to, c_score, campaign_summaries,
            carbon_black, certainty, crowdstrike, detection_profile, detection_set, detection_summaries,
            groups, has_active_traffic, has_custom_model, has_shell_knocker_learnings, host_artifact_set,
            host_luid, host_session_luid, host_url, id, ip, is_key_asset, is_targeting_key_asset, key_asset,
            last_detection_timestamp, last_modified, last_seen, last_source, ldap, name, note, note_modified_by,
            note_modified_timestamp, previous_ips, privilege_category, privilege_level, probable_owner, sensor,
            sensor_name, severity, shell_knocker, state, suspicious_admin_learnings, t_score, tags, targets_key_asset,
            threat, url, vcenter
        """
        if not host_id:
            raise ValueError('Host id required')

        if self.version == 2:
            return requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers,
                                params=self._generate_host_by_id_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), auth=self.auth,
                                params=self._generate_host_by_id_params(kwargs), verify=self.verify)

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

        if set:
            payload = {'key_asset':'true'}
        else:
            payload = {'key_asset':'false'}

        return requests.patch('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers, json=payload,
                              verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_host_tags(self, host_id=None):
        """
        Get host tags
        :param host_id: ID of the host for which to retrieve the tags
        """
        if not host_id:
            raise ValueError('Host id required')

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
        if not host_id:
            raise ValueError('Host id required')

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

        return requests.patch('{url}/tagging/host/{id}'.format(url=self.url, id=host_id), headers=self.headers,
                              json=payload, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def bulk_set_hosts_tag(self, tag, host_ids):
        """
        Set a tag in bulk on multiple hosts. Only one tag can be set at a time
        :param host_ids: IDs of the hosts for which to set the tag
        """
        if not isinstance(host_ids, list):
            raise TypeError('Host IDs must be of type list')

        payload = {
            'objectIds': host_ids,
            'tag': tag
        }
        return requests.post('{url}/tagging/host'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def bulk_delete_hosts_tag(self, tag, host_ids):
        """
        Delete a tag in bulk on multiple hosts. Only one tag can be deleted at a time
        :param host_ids: IDs of the hosts on which to delete the tag
        """
        if not isinstance(host_ids, list):
            raise TypeError('Host IDs must be of type list')

        payload = {
            'objectIds': host_ids,
            'tag': tag
        }
        return requests.delete('{url}/tagging/host'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def get_host_note(self, host_id=None):
        """
        Get host notes
        :param host_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete host body, we alter the response content
        """

        if not host_id:
            raise ValueError('Host id required')

        host = requests.get('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers, verify=self.verify)
        if host.status_code == 200:
            host_note = host.json()['note']
            # API endpoint return HTML escaped characters
            host_note = html.unescape(host_note) if host_note else ''
            json_dict = {'status': 'success', 'host_id': str(host_id), 'note': host_note}
            host._content = json.dumps(json_dict).encode('utf-8')
        return host

    @validate_api_v2
    @request_error_handler
    def set_host_note(self, host_id=None, note='', append=False):
        """
        Set host note
        :param host_id:
        :param note: content of the note to set
        :param append: overwrites existing note if set to False, appends if set to True
        Set to empty note string to clear host note
        """
        if not host_id:
            raise ValueError('Host id required')

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
            raise TypeError('Note must be of type str')

        return requests.patch('{url}/hosts/{id}'.format(url=self.url, id=host_id), headers=self.headers, data=json.dumps(payload),
                                      verify=self.verify)

    @request_error_handler
    def get_detections(self, **kwargs):
        """
        Query all detections - all parameters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param category: detection category - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param detection: detection type
        :param detection_type: detection type
        :param detection_category: detection category
        :param description:
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id, url, detection_url, category, detection, detection_category, 
            detection_type, custom_detection, description, src_ip, state, t_score, c_score,
            certainty, threat, first_timestamp, last_timestamp, targets_key_asset, 
            is_targeting_key_asset, src_account, src_host, note, note_modified_by, 
            note_modified_timestamp, sensor, sensor_name, tags, triage_rule_id, assigned_to, 
            assigned_date, groups, is_marked_custom, is_custom_model
        :param host_id: host id (int)
        :param is_targeting_key_asset: detection is targeting key asset (bool)
        :param is_triaged: detection is triaged
        :param last_timestamp: timestamp of last activity on detection (datetime)
        :param max_id: maximum ID of detection returned
        :param min_id: minimum ID of detection returned
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param src_ip: source ip address of host attributed to detection
        :param state: state of detection (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param tags: tags assigned to detections; this uses substring matching 
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
        Generator to retrieve all detections - all parameters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param category: detection category - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param detection: detection type
        :param detection_type: detection type
        :param detection_category: detection category
        :param description:
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: id, url, detection_url, category, detection, detection_category, 
            detection_type, custom_detection, description, src_ip, state, t_score, c_score,
            certainty, threat, first_timestamp, last_timestamp, targets_key_asset, 
            is_targeting_key_asset, src_account, src_host, note, note_modified_by, 
            note_modified_timestamp, sensor, sensor_name, tags, triage_rule_id, assigned_to, 
            assigned_date, groups, is_marked_custom, is_custom_model
        :param host_id: detection id (int)
        :param is_targeting_key_asset: detection is targeting key asset (bool)
        :param is_triaged: detection is triaged
        :param last_timestamp: timestamp of last activity on detection (datetime)
        :param max_id: maximum ID of detection returned
        :param min_id: minimum ID of detection returned
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param src_ip: source ip address of host attributed to detection
        :param state: state of detection (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param tags: tags assigned to detection; this uses substring matching
        :param targets_key_asset: detection targets key asset (bool) - will be removed with deprecation of v1 of api
        :param threat: threat score (int)
        :param threat_gte threat score is greater than or equal to (int)
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        """
        resp = requests.get('{url}/detections'.format(url=self.url), headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @request_error_handler
    def get_detection_by_id(self, detection_id=None, **kwargs):
        """
        Get detection by id
        :param detection_id: detection id - required
        :param fields: comma separated string of fields to be filtered and returned - optional
            possible values are: id, url, detection_url, category, detection, detection_category, 
            detection_type, custom_detection, description, src_ip, state, t_score, c_score,
            certainty, threat, first_timestamp, last_timestamp, targets_key_asset, 
            is_targeting_key_asset, src_account, src_host, note, note_modified_by, 
            note_modified_timestamp, sensor, sensor_name, tags, triage_rule_id, assigned_to, 
            assigned_date, groups, is_marked_custom, is_custom_model
        """
        if not detection_id:
            raise ValueError('Detection id required')

        if self.version == 2:
            return requests.get('{url}/detections/{id}'.format(url=self.url, id=detection_id), headers=self.headers,
                                params=self._generate_detection_params(kwargs), verify=self.verify)
        else:
            return requests.get('{url}/detections/{id}'.format(url=self.url, id=detection_id), auth=self.auth,
                                params=self._generate_detection_params(kwargs), verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def mark_detections_fixed(self, detection_ids=None):
        """
        Mark detections as fixed
        :param detection_ids: list of detections to mark as fixed
        """
        if not isinstance(detection_ids, list):
            raise ValueError('Must provide a list of detection IDs to mark as fixed')
        return self._toggle_detections_fixed(detection_ids, fixed=True)

    @validate_api_v2
    @request_error_handler
    def unmark_detections_fixed(self, detection_ids=None):
        """
        Unmark detections as fixed
        :param detection_ids: list of detections to unmark as fixed
        """
        if not isinstance(detection_ids, list):
            raise ValueError('Must provide a list of detection IDs to unmark as fixed')
        return self._toggle_detections_fixed(detection_ids, fixed=False)

    def _toggle_detections_fixed(self, detection_ids, fixed):
        """
        Internal function to mark/unmark detections as fixed
        """
        payload = {
            'detectionIdList': detection_ids, 
            'mark_as_fixed': str(fixed)
            }

        return requests.patch('{url}/detections'.format(url=self.url), json=payload, headers=self.headers,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def mark_detections_custom(self, detection_ids=[], triage_category=None):
        """
        Mark detections as custom
        :param detection_ids: list of detection IDs to mark as custom
        :param triage_category: custom name to give detection
        :rtype: requests.Response
        """
        if not isinstance(detection_ids, list):
            raise ValueError('Must provide a list of detection IDs to mark as custom')

        payload = {
            "triage_category": triage_category,
            "detectionIdList": detection_ids
        }

        return requests.post('{url}/rules'.format(url=self.url), headers=self.headers, json=payload,
                             verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def unmark_detections_custom(self, detection_ids=[]):
        """
        Unmark detection as custom
        :param detection_ids: list of detection IDs to unmark as custom
        :rtype: requests.Response
        """
        if not isinstance(detection_ids, list):
            raise ValueError('Must provide a list of detection IDs to unmark as custom')

        payload = {
            "detectionIdList": detection_ids
        }

        response = requests.delete('{url}/rules'.format(url=self.url), headers=self.headers, json=payload,
                             verify=self.verify)

        # DELETE returns an empty response, but we populate the response for consistency with the mark_as_fixed() function
        json_dict = {'_meta': {'message': 'Successfully unmarked detections', 'level': 'Success'}}
        response._content = json.dumps(json_dict).encode('utf-8')

        return response

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

        return requests.patch('{url}/tagging/detection/{id}'.format(url=self.url, id=detection_id), headers=self.headers,
                              json=payload, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def bulk_set_detections_tag(self, tag, detection_ids):
        """
        Set a tag in bulk on multiple detections. Only one tag can be set at a time
        :param detection_ids: IDs of the detections for which to set the tag
        """
        if not isinstance(detection_ids, list):
            raise TypeError('Detection IDs must be of type list')

        payload = {
            'objectIds': detection_ids,
            'tag': tag
        }
        return requests.post('{url}/tagging/detection'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def bulk_delete_detections_tag(self, tag, detection_ids):
        """
        Delete a tag in bulk on multiple detections. Only one tag can be deleted at a time
        :param detection_ids: IDs of the detections for which to delete the tag
        """
        if not isinstance(detection_ids, list):
            raise TypeError('Detection IDs must be of type list')

        payload = {
            'objectIds': detection_ids,
            'tag': tag
        }
        return requests.delete('{url}/tagging/detection'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @validate_api_v2
    @request_error_handler
    def get_detection_note(self, detection_id=None):
        """
        Get detection notes
        :param detection_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete detection body, we alter the response content
        """
        detection = requests.get('{url}/detections/{id}'.format(url=self.url, id=detection_id), headers=self.headers, verify=self.verify)
        if detection.status_code == 200:
            detection_note = detection.json()['note']
            # API endpoint return HTML escaped characters
            detection_note = html.unescape(detection_note) if detection_note else ''
            json_dict = {'status': 'success', 'detection_id': str(detection_id), 'note': detection_note}
            detection._content = json.dumps(json_dict).encode('utf-8')
        return detection

    @validate_api_v2
    @request_error_handler
    def set_detection_note(self, detection_id=None, note='', append=False):
        """
        Set detection note
        :param detection_id:
        :param note: content of the note to set
        :param append: overwrites existing note if set to False, appends if set to True
        Set to empty note string to clear detection note
        """
        if append and isinstance(note, str):
            current_note = self.get_detection_note(detection_id=detection_id).json()['note']
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
            raise TypeError('Note must be of type str')

        return requests.patch('{url}/detections/{id}'.format(url=self.url, id=detection_id), headers=self.headers, json=payload,
            verify=self.verify)

    @validate_api_v2
    def get_detection_pcap(self, detection_id=None, filename=None):
        """
        Get detection pcap
        :param detection_id: ID of the detection for which to get a pcap
        :param filename: filename to write the pcap to. Will be overwriten if already exists.
        """
        response = requests.get('{url}/detections/{id}/pcap'.format(url=self.url, id=detection_id), headers=self.headers,
                            verify=False)
        if response.status_code not in [200, 201, 204]:
            raise HTTPException(response)

        with open(filename, 'wb') as f:
            f.write(response.content)

        # Return a <Response> object for consistency
        json_dict = {'status': 'success', 'detection_id': str(detection_id), 'file_created': filename}
        response._content = json.dumps(json_dict).encode('utf-8')
        return response

    # TODO add request_error_handler decorator as soon as get_rules_by_name() returns requests.Response object
    @validate_api_v2
    def get_rules(self, name=None, rule_id=None, **kwargs):
        """
        Query all rules
        :param name: name of rule to search (substring matching)
        :param rule_id: ID of rule to return
        :param contains:
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, all_hosts, category, created_timestamp, description,
            enabled, flex1, flex2, flex3, flex4, flex5, flex6, host, host_group, id, identity, ip,
            ip_group, is_whitelist, last_timestamp, priority, remote1_dns, remote1_dns_groups,
            remote1_ip, remote1_ip_groups, remote1_kerb_account, remote1_kerb_service, remote1_port,
            remote1_proto, remote2_dns, remote2_dns_groups, remote2_ip, remote2_ip_groups, remote2_port,
            remote2_proto, sensor_luid, smart_category, template, total_detections, type_vname, url
        :param include_templates: include rule templates, default is False
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        deprecation('Some rules are no longer compatible with the APIv2, please switch to the APIv2.1')
        if name:
            deprecation('The "name" argument will be removed from this function, please use get_all_rules with the "contains" query parameter')
            return self.get_rules_by_name(triage_category=name)
        elif rule_id:
            deprecation('The "rule_id" argument will be removed from this function, please use the corresponding get_rule_by_id function')
            return self.get_rule_by_id(rule_id)
        else:
            return requests.get('{url}/rules'.format(url=self.url), headers=self.headers,
                                params=self._generate_rule_params(kwargs), verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_rule_by_id(self, rule_id, **kwargs):
        """
        Get triage rules by id
        :param rule_id: id of triage rule to retrieve
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, all_hosts, category, created_timestamp, description,
            enabled, flex1, flex2, flex3, flex4, flex5, flex6, host, host_group, id, identity, ip,
            ip_group, is_whitelist, last_timestamp, priority, remote1_dns, remote1_dns_groups,
            remote1_ip, remote1_ip_groups, remote1_kerb_account, remote1_kerb_service, remote1_port,
            remote1_proto, remote2_dns, remote2_dns_groups, remote2_ip, remote2_ip_groups, remote2_port,
            remote2_proto, sensor_luid, smart_category, template, total_detections, type_vname, url
        """
        if not rule_id:
            raise ValueError('Rule id required')

        deprecation('Some rules are no longer compatible with the APIv2, please switch to the APIv2.1')

        return requests.get('{url}/rules/{id}'.format(url=self.url, id=rule_id), headers=self.headers,
                                params=self._generate_rule_by_id_params(kwargs), verify=False)

    # TODO make return type requests.Reponse
    @validate_api_v2
    def get_rules_by_name(self, triage_category=None, description=None):
        """
        Get triage rules by name or description
        Condition are to be read as OR
        :param triage_category: 'Triage as' field of filter
        :param description: Description of the triage filter
        :rtype list: to be backwards compatible
        """
        search_query = triage_category if triage_category else description
        response = self.get_rules(contains=search_query)
        return response.json()['results']

    @validate_api_v2
    def get_all_rules(self, **kwargs):
        """
        Generator to retrieve all rules page by page - all parameters are optional
        :param contains:
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, all_hosts, category, created_timestamp, description,
            enabled, flex1, flex2, flex3, flex4, flex5, flex6, host, host_group, id, identity, ip,
            ip_group, is_whitelist, last_timestamp, priority, remote1_dns, remote1_dns_groups,
            remote1_ip, remote1_ip_groups, remote1_kerb_account, remote1_kerb_service, remote1_port,
            remote1_proto, remote2_dns, remote2_dns_groups, remote2_ip, remote2_ip_groups, remote2_port,
            remote2_proto, sensor_luid, smart_category, template, total_detections, type_vname, url
        :param include_templates: include rule templates, default is False
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        resp = requests.get('{url}/rules'.format(url=self.url), headers=self.headers,
                                params=self._generate_rule_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    @request_error_handler
    def create_rule(self, detection_category=None, detection_type=None, triage_category=None, is_whitelist=False, **kwargs):
        """
        Create triage rule
        :param detection_category: detection category to triage [botnet activity, command & control, reconnaissance,
        lateral movement, exfiltration]
        :param detection_type: detection type to triage
        :param triage_category: name that will be used for triaged detection
        :param description: name of the triage rule
        :param is_whitelist: set to True if rule is to whitelist; opposed to tracking detections without scores (boolean)
        :param ip: list of ip addresses to apply to triage rule
        :param ip_group: list of IP groups IDs to add to rule
        :param host: list of host ids to apply to triage rule
        :param host_group: list of Host groups IDs to add to rule
        :param sensor_luid: list of sensor luids to triage
        :param priority: used to determine order of triage filters (int)
        :param all_hosts: apply triage rule to all hosts (boolean)
        :param remote1_ip: destination IP where this Triage filter will be applied to
        :param remote1_ip_groups: destination IP Groups where this Triage filter will be applied to
        :param remote1_proto: destination protocol where this Triage filter will be applied to
        :param remote1_port: destination port where this Triage filter will be applied to
        :param remote1_dns: destination FQDN where this Triage filter will apply to
        :param remote1_dns_groups: domain groups where this Triage filter will apply to
        :param remote2_ip: destination IP where this Triage filter will be applied to
        :param remote2_ip_groups: destination IP Groups where this Triage filter will be applied to
        :param remote2_proto: destination protocol where this Triage filter will be applied to
        :param remote2_port: destination port where this Triage filter will be applied to
        :param remote2_dns: destination FQDN where this Triage filter will apply to
        :param remote2_dns_groups: domain groups where this Triage filter will apply to
        :param account: accounts where this triage filter will apply to (list)
        :param named_pipe: (Suspicious Remote Execution) named pipes where this triage filter will apply to (list)
        :param uuid: (Suspicious Remote Execution) UUID where this triage filter will apply to (list)
        :param identity: (Kerberos detection) identity where this triage filter will apply to (list)
        :param service: (PAA detections) services where this triage filter will apply to (list)
        :param file_share: (Ransomware File Activity) file share where this triage filter will apply to - escape backslashes with "\" (list)
        :param file_extensions: (Ransomware File Activity) file extensions where this triage filter will apply to (list)
        :param rdp_client_name: (Suspicious Remote Desktop) RDP client name where this triage filter will apply to (list)
        :param rdp_client_token: (Suspicious Remote Desktop) RDP client token where this triage filter will apply to (list)
        :param keyboard_name: (Suspicious Remote Desktop) RDP keyboard name where this triage filter will apply to (list)
        :returns request object
        """
        if not all([detection_category, detection_type, triage_category]):
            raise KeyError("missing required parameter: "
                             "detection_category, detection_type, triage_category")
        if detection_category.lower() not in ['botnet activity', 'command & control', 'reconnaissance', 'lateral movement', 'exfiltration']:
            raise ValueError("detection_category not recognized")

        payload = {
            'detection_category': detection_category,
            'detection': detection_type,
            'triage_category': triage_category,
            'is_whitelist': is_whitelist
            }

        valid_keys = ['description', 'is_whitelist', 'ip', 'ip_group', 'host', 'host_group',
            'sensor_luid', 'priority', 'all_hosts', 'remote1_ip', 'remote1_ip_groups',
            'remote1_proto', 'remote1_port', 'remote1_dns', 'remote1_dns_groups', 'remote2_ip',
            'remote2_ip_groups', 'remote2_proto', 'remote2_port', 'remote2_dns',
            'remote2_dns_groups', 'account', 'named_pipe', 'uuid', 'identity', 'service',
            'file_share', 'file_extensions', 'rdp_client_name', 'rdp_client_token', 'keyboard_name']

        for k, v in kwargs.items():
            if k in valid_keys:
                payload[k] = v
            else:
                raise ValueError('argument {} is an invalid field for rule creation'.format(str(k)))

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
        :param description: name of the triage rule
        :param is_whitelist: set to True if rule is to whitelist; opposed to tracking detections without scores (boolean)
        :param ip: list of ip addresses to apply to triage rule
        :param ip_group: list of IP groups IDs to add to rule
        :param host: list of host ids to apply to triage rule
        :param host_group: list of Host groups IDs to add to rule
        :param sensor_luid: list of sensor luids to triage
        :param priority: used to determine order of triage filters (int)
        :param all_hosts: apply triage rule to all hosts (boolean)
        :param remote1_ip: destination IP where this Triage filter will be applied to
        :param remote1_ip_groups: destination IP Groups where this Triage filter will be applied to
        :param remote1_proto: destination protocol where this Triage filter will be applied to
        :param remote1_port: destination port where this Triage filter will be applied to
        :param remote1_dns: destination FQDN where this Triage filter will apply to
        :param remote1_dns_groups: domain groups where this Triage filter will apply to
        :param remote2_ip: destination IP where this Triage filter will be applied to
        :param remote2_ip_groups: destination IP Groups where this Triage filter will be applied to
        :param remote2_proto: destination protocol where this Triage filter will be applied to
        :param remote2_port: destination port where this Triage filter will be applied to
        :param remote2_dns: destination FQDN where this Triage filter will apply to
        :param remote2_dns_groups: domain groups where this Triage filter will apply to
        :param account: accounts where this triage filter will apply to (list)
        :param named_pipe: (Suspicious Remote Execution) named pipes where this triage filter will apply to (list)
        :param uuid: (Suspicious Remote Execution) UUID where this triage filter will apply to (list)
        :param identity: (Kerberos detection) identity where this triage filter will apply to (list)
        :param service: (PAA detections) services where this triage filter will apply to (list)
        :param file_share: (Ransomware File Activity) file share where this triage filter will apply to - escape backslashes with "\" (list)
        :param file_extensions: (Ransomware File Activity) file extensions where this triage filter will apply to (list)
        :param rdp_client_name: (Suspicious Remote Desktop) RDP client name where this triage filter will apply to (list)
        :param rdp_client_token: (Suspicious Remote Desktop) RDP client token where this triage filter will apply to (list)
        :param keyboard_name: (Suspicious Remote Desktop) RDP keyboard name where this triage filter will apply to (list)
        :returns request object
        """

        if name:
            deprecation('The "name" argument will be removed from this function, please use get_all_rules with the "contains" query parameter')
            matching_rules = self.get_rules_by_name(triage_category=name)
            if len(matching_rules) > 1:
                raise Exception('More than one rule matching the name')
            elif len(matching_rules) < 1:
                raise Exception('No rule matching the search')
            else:
                rule = matching_rules[0]
        elif rule_id:
            rule = self.get_rule_by_id(rule_id=rule_id).json()
        else:
            raise ValueError("rule name or id must be provided")


        valid_keys = ['description', 'is_whitelist', 'ip', 'ip_group', 'host', 'host_group',
            'sensor_luid', 'priority', 'all_hosts', 'remote1_ip', 'remote1_ip_groups',
            'remote1_proto', 'remote1_port', 'remote1_dns', 'remote1_dns_groups', 'remote2_ip',
            'remote2_ip_groups', 'remote2_proto', 'remote2_port', 'remote2_dns',
            'remote2_dns_groups', 'account', 'named_pipe', 'uuid', 'identity', 'service',
            'file_share', 'file_extensions', 'rdp_client_name', 'rdp_client_token', 'keyboard_name']

        for k, v in kwargs.items():
            if k in valid_keys:
                if append:
                    if isinstance(rule[k], list):
                        rule[k] += v
                    else:
                        rule[k] = v
                else:
                    rule[k] = v
            else:
                raise ValueError('invalid parameter provided: {}'.format(str(k)))

        return requests.put('{url}/rules/{id}'.format(url=self.url, id=rule['id']), headers=self.headers, json=rule,
                            verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def delete_rule(self, rule_id=None, restore_detections=True):
        """
        Delete triage rule
        :param rule_id:
        :param restore_detections: restore previously triaged detections (bool) default behavior is to restore
        detections
        """

        if not rule_id:
            raise ValueError('Rule id required')

        params = {
            'restore_detections': restore_detections
        }

        return requests.delete('{url}/rules/{id}'.format(url=self.url, id=rule_id), headers=self.headers, params=params,
                               verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_groups(self, **kwargs):
        """
        Query all groups - all parameters are optional
        :param description: description of groups to search
        :param domains: search for groups containing those domains (list)
        :param host_ids: search for groups containing those host IDs (list)
        :param host_names: search for groups containing those hosts (list)
        :param last_modified_by: username of last person to modify this group
        :param last_modified_timestamp: timestamp of last modification of group (datetime)
        :param name: name of groups to search
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param type: type of group to search (domain/host/ip)
        """

        return requests.get('{url}/groups'.format(url=self.url), headers=self.headers,
                            params=self._generate_group_params(kwargs), verify=self.verify)

    @validate_api_v2
    def get_all_groups(self, **kwargs):
        """
        Generator to retrieve all groups - all parameters are optional
        :param description: description of groups to search
        :param domains: search for groups containing those domains (list)
        :param host_ids: search for groups containing those host IDs (list)
        :param host_names: search for groups containing those hosts (list)
        :param last_modified_by: username of last person to modify this group
        :param last_modified_timestamp: timestamp of last modification of group (datetime)
        :param name: name of groups to search
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param type: type of group to search (domain/host/ip)
        """
        resp = requests.get('{url}/groups'.format(url=self.url), headers=self.headers,
                            params=self._generate_group_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    @request_error_handler
    def get_group_by_id(self, group_id):
        """
        Get groups by id
        :param rule_id: id of group to retrieve
        """
        return requests.get('{url}/groups/{id}'.format(url=self.url, id=group_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    def get_groups_by_name(self, name=None, description=None):
        """
        Get groups by name or description
        :param name: Name of group*
        :param description: Description of the group*
        *params are to be read as OR
        """
        if name and description:
            raise Exception('Can only provide a name OR a description')
        if name:
            response = self.get_groups(name=name)
            return response.json()['results']
        elif description:
            response = self.get_groups(description=description)
            return response.json()['results']

    @validate_api_v2
    @request_error_handler
    def create_group(self, name=None, description='', type=None, members=[], rules=[], **kwargs):
        """
        Create group
        :param name: name of the group to create
        :param description: description of the group
        :param type: type of the group to create (domain/host/ip)
        :param members: list of host ids to add to group
        :param rules: list of triage rule ids to add to group
        :rtype requests.Response:
        """
        if not name:
            raise ValueError("missing required parameter: name")
        if not type:
            raise ValueError("missing required parameter: type")
        if type not in ['host', 'domain', 'ip']:
            raise ValueError('parameter type must have value "domain", "ip" or "host"')
        if not isinstance(members, list):
            raise TypeError("members must be type: list")
        if not isinstance(rules, list):
            raise TypeError("rules must be type: list")

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
        :param type: type of the group (domain/host/ip)
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

        # Transform members into flat list as API returns dicts for host groups
        if group['type'] == 'host':
            members = set()
            for member in group['members']:
                members.add(member['id'])
            group['members'] = list(members)

        for k, v in kwargs.items():
            if k in valid_keys and v is not None:
                if k in ['members', 'rules'] and not isinstance(v, list):
                    raise TypeError('{} must be of type: list'.format(k))
                if append:
                    group[k] +=  v
                else:
                    group[k] = v
            else:
                raise KeyError('Key {} is not valid'.format(k))


        group['members'] = list(set(group['members']))

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
    def get_all_users(self, **kwargs):
        """
        Generator to query all users
        :param username: filter by username
        :param role: filter by role
        :param account_type: filter by account type (local, ldap, radius or tacacs)
        :param authentication_profile: filter by authentication profile
        :param last_login_gte: filter for users that have logged in since the given timestamp
        """
        resp = requests.get('{url}/users'.format(url=self.url), headers=self.headers,
                                params=self._generate_user_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    @request_error_handler
    def get_user_by_id(self, user_id=None):
        """
        Get users by id
        :param user: id of user to retrieve
        """
        if not user_id:
            raise ValueError('User id required')

        return requests.get('{url}/users/{id}'.format(url=self.url, id=user_id), headers=self.headers,
                              verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_user(self, user_id=None, account_type=None, authentication_profile=None):
        """
        Update the authentication type for a user
        :param user_id: user ID
        :param account_type: new user account type (local, ldap, radius, tacacs)
        :param authentication_profile: authentication profile name
        """
        if not user_id:
            raise ValueError('User id required')
        
        if not account_type in ['local', 'ldap', 'radius', 'tacacs']:
            raise ValueError('Invalid account_type provided')

        if not authentication_profile:
            raise ValueError('Authentication profile required')

        payload = {
            'account_type': account_type,
            'authentication_profile': authentication_profile
        }

        return requests.patch('{url}/users/{id}'.format(url=self.url, id=user_id), json=payload, headers=self.headers,
                              verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_proxies(self, proxy_id=None):
        """ 
        Get all defined proxies
        """
        if proxy_id:
            deprecation('The "proxy_id" argument will be removed from this function, please use the get_proxy_by_id() function')
            return self.get_proxy_by_id(proxy_id=proxy_id)
        else:
            return requests.get('{url}/proxies'.format(url=self.url), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_proxy_by_id(self, proxy_id=None):
        """
        Get proxy by id
        :param proxy_id: id of proxy to retrieve - caution those are UUIDs not int
        """
        if not proxy_id:
            raise ValueError('Proxy id required')

        return requests.get('{url}/proxies/{id}'.format(url=self.url, id=proxy_id), headers=self.headers,
                                verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def add_proxy(self, address=None, enable=True):
        """
        Add a proxy to the proxy list
        :param address: IP address of the proxy to add
        :param enable: set to true to consider the IP as a proxy, false to never consider it as proxy
        """
        payload = {
            "proxy": {
                "address": address,
                "considerProxy": enable
            }
        }

        return requests.post('{url}/proxies'.format(url=self.url), json=payload, headers=self.headers, verify=self.verify)

    # TODO PATCH request modifies the proxy ID  and 404 is actually a 500 - APP-10753
    @validate_api_v2
    @request_error_handler
    def update_proxy(self, proxy_id=None, address=None, enable=True):
        """
        Update an existing proxy in the system
        :param proxy_id: ID of the proxy to update
        :param address: IP address to set for this proxy
        :param enable: set to true to consider the IP as a proxy, false to never consider it as proxy
        CAUTION: the proxy ID (ressource identifier) gets modified by the PATCH request at the moment
        CAUTION: PATCHing an invalid ID returns a HTTP 500 instead of 404 at the moment
        """
        if not proxy_id:
            raise ValueError('Proxy id required')

        payload = {"proxy": {}}
        if address is not None:
            payload["proxy"]["address"] = address
        if enable is not None:
            payload["proxy"]["considerProxy"] = enable

        return requests.patch('{url}/proxies/{id}'.format(url=self.url, id=proxy_id), json=payload, headers=self.headers,
                              verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def delete_proxy(self,proxy_id=None):
        """ 
        Delete a proxy from the proxy list
        :param proxy_id: ID of the proxy to delete
        """
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
        if not category in ['lateral', 'exfil', 'cnc']:
            raise ValueError('Invalid category provided: {}'.format(category))

        if not certainty in ['Low', 'Medium', 'High']:
            raise ValueError('Invalid certainty provided: {}'.format(str(certainty)))

        if not itype in ['Anonymize', 'Exfiltration', 'Malware Artifacts', 'Watchlist', 'C2']:
            raise ValueError('Invalid itype provided: {}'.format(str(itype)))

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

        return requests.post('{url}/threatFeeds'.format(url=self.url), json=payload, headers=self.headers,
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
            raise HTTPException(response)

    @validate_api_v2
    @request_error_handler
    def post_stix_file(self, feed_id=None, stix_file=None):
        """
        Uploads STIX file to new threat feed or overwrites STIX file in existing threat feed
        :param feed_id: id of threat feed (returned by get_feed_by_name)
        :param stix_file: stix filename
        """
        headers = copy.deepcopy(self.headers)
        headers.pop('Content-Type', None)
        return requests.post('{url}/threatFeeds/{id}'.format(url=self.url, id=feed_id), headers=headers,
                             files={'file': open(stix_file)}, verify=self.verify)

    @validate_api_v2
    def advanced_search(self, stype=None, page_size=50, query=None):
        """
        Advanced search
        :param stype: search type (hosts, detections)
        :param page_size: number of objects returned per page
        :param advanced query (download the following guide for more details on query language
            https://support.vectranetworks.com/hc/en-us/articles/360003225254-Search-Reference-Guide)
        """
        if stype not in ["hosts", "detections"]:
            raise ValueError("Supported values for stype are hosts or detections")

        if not query:
            raise ValueError('Query parameter is required')

        params = {
            'page_size': page_size,
            'query_string': query
        }

        resp = requests.get('{url}/search/{stype}'.format(url=self.url, stype=stype), headers=self.headers,
                                params=params, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp

    @validate_api_v2
    def get_all_traffic_stats(self):
        """
        Generator to get all traffic stats
        """
        resp = requests.get('{url}/traffic'.format(url=self.url), headers=self.headers, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    def get_all_sensor_traffic_stats(self, sensor_luid=None):
        """
        Generator to get all traffic stats from a sensor
        :param sensor_luid: LUID of the sensor for which to get the stats. Can be retrived in the UI under Manage > Sensors
        """
        if not sensor_luid:
            raise ValueError('Sensor LUID required')

        resp = requests.get('{url}/traffic/{luid}'.format(url=self.url, luid=sensor_luid), headers=self.headers, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    def get_all_subnets(self, **kwargs):
        """
        Generator to get all subnets seen by the brain
        :param ordering: ordering key of the results.
            possible values are: subnet, hosts, firstSeen, lastSeen
        :param search: only return subnets containing the search string
        """
        resp = requests.get('{url}/subnets'.format(url=self.url), params=self._generate_subnet_params(kwargs),
            headers=self.headers, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @validate_api_v2
    def get_all_sensor_subnets(self, sensor_luid=None, **kwargs):
        """
        Generator to get all subnets seen by a sensor
        :param sensor_luid: LUID of the sensor for which to get the subnets seen - required
        :param ordering: ordering key of the results.
            possible values are: subnet, hosts, firstSeen, lastSeen
        :param search: only return subnets containing the search string
        """
        if not sensor_luid:
            raise ValueError('Sensor LUID required')

        resp = requests.get('{url}/subnets/{luid}'.format(url=self.url, luid=sensor_luid), 
            params=self._generate_subnet_params(kwargs), headers=self.headers, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    # TODO see if the endpoint should become a generator
    @validate_api_v2
    @request_error_handler
    def get_ip_addresses(self, **kwargs):
        """
        Get all active IPs seen by the brain
        CAUTION: this is not a generator
        :param include_ipv4: Include IPv4 addresses - default True
        :param include_ipv6: Include IPv6 addresses - default True
        """
        return requests.get('{url}/ip_addresses'.format(url=self.url), params=self._generate_ip_address_params(kwargs),
            headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def get_internal_networks(self):
        """
        Get all internal networks configured on the brain
        """
        return requests.get('{url}/settings/internal_network'.format(url=self.url),
            headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def set_internal_networks(self, include=[], exclude=[], drop=[], append=True):
        """
        Set internal networks configured on the brain
        :param include: list of subnets to add  the internal subnets list
        :param exclude: list of subnets to exclude from the internal subnets list
        :param drop: list of subnets to add to the drop list
        :param append: overwrites existing lists if set to False, appends to existing lists if set to True
        """
        # Check that all provided ranges are valid
        all(ipaddress.ip_network(i) for i in include+exclude+drop)
        
        if append and all(isinstance(i, list) for i in [include, exclude, drop]):
            current_list = self.get_internal_networks().json()
            # We must make all entries unique
            payload = {
                'include': list(set(include).union(set(current_list['included_subnets']))),
                'exclude': list(set(exclude).union(set(current_list['excluded_subnets']))),
                'drop': list(set(drop).union(set(current_list['dropped_subnets'])))
            }
        elif all(isinstance(i, list) for i in [include, exclude, drop]):
            payload = {
                'include': include,
                'exclude': exclude,
                'drop': drop
            }
        else:
            raise TypeError('subnets must be of type list')

        return requests.post('{url}/settings/internal_network'.format(url=self.url),
            json=payload, headers=self.headers, verify=self.verify)

    # TODO see if check parameter has been fixed - APP-10753
    @request_error_handler
    def get_health_check(self, check=None):
        """
        Get health statistics for the appliance
        :param check: specific check to run - optional
            possible values are: cpu, disk, hostid, memory, network, power, sensors, system
        """
        if not check:
            return requests.get('{url}/health'.format(url=self.url), headers=self.headers, verify=self.verify)
        else:
            if not isinstance(check, str):
                raise ValueError('check need to be a string')
            return requests.get('{url}/health/{check}'.format(url=self.url, check=check), headers=self.headers, verify=self.verify)
        

class VectraClientV2_1(VectraClient):

    def __init__(self, url=None, token=None, verify=False):
        """
        Initialize Vectra client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param token: API token for authentication when using API v2*
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(url=url, token=token, verify=verify)
        # Remove potential trailing slash
        url = VectraClient._remove_trailing_slashes(url)
        # Set endpoint to APIv2.1
        self.url = '{url}/api/v2.1'.format(url=url)

    @staticmethod
    def _generate_account_params(args):
        """
        Generate query parameters for accounts based provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ['all', 'c_score', 'c_score_gte', 'certainty', 'certainty_gte', 'fields', 'first_seen',
            'include_detection_summaries', 'last_seen', 'last_source', 'max_id', 'min_id', 'name',
            'note_modified_timestamp_gte', 'ordering', 'page', 'page_size', 'privilege_category',
            'privilege_level', 'privilege_level_gte', 'state', 't_score', 't_score_gte', 'tags',
            'threat', 'threat_gte', 'uid']

        for k, v in args.items():
            if k in valid_keys:
                if v is not None: params[k] = v
            else:
                raise ValueError('argument {} is an invalid account query parameter'.format(str(k)))
        return params

    @staticmethod
    def _generate_detect_usage_params(args):
        """
        Generate query parameters for detect usage query based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        search = re.compile('[0-9]{4}-[0-9]{2}')
        valid_keys = ['start', 'end']
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    # We validate the parameters here as the error thrown by the endpoint is not very verbose 
                    if search.match(v):
                        params[k] = v
                    else:
                        raise ValueError('{} is not a valid date string for detect usage query'.format(str(v)))
            else:
                raise ValueError('argument {} is an invalid detect usage query parameter'.format(str(k)))
        return params

    def get_campaigns(self, **kwargs):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_campaigns() which supports pagination')

    def get_hosts(self, **kwargs):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_hosts() which supports pagination')

    def get_detections(self, **kwargs):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_detections() which supports pagination')

    def get_all_accounts(self, **kwargs):
        """
        Generator to retrieve all accounts - all parameters are optional
        :param all: does nothing 
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are id, url, name, state, threat, certainty, severity, account_type, 
            tags, note, note_modified_by, note_modified_timestamp, privilege_level, privilege_category, 
            last_detection_timestamp, detection_set, probable_home
        :param first_seen: first seen timestamp of the account (datetime)
        :param include_detection_summaries: include detection summary in response (bool)
        :param last_seen: last seen timestamp of the account (datetime)
        :param last_source: registered ip address of host
        :param max_id: maximum ID of account returned
        :param min_id: minimum ID of account returned
        :param name: registered name of host
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        :param ordering: field to use to order response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param privilege_category: privilege category of account (low/medium/high)
        :param privilege_level: privilege level of account (0-10)
        :param privilege_level_gte: privilege of account level greater than or equal to (int)
        :param state: state of host (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score greater than or equal to (int) - will be removed with deprection of v1 of api
        :param tags: tags assigned to account
        :param threat: threat score (int)
        :param threat_gte: threat score greater than or equal to (int)
        """
        resp = requests.get('{url}/accounts'.format(url=self.url), headers=self.headers,
                                params=self._generate_account_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp

    @request_error_handler
    def get_account_by_id(self, account_id=None, **kwargs):
        """
        Get account by id
        :param account_id: account id - required
        :param fields: comma separated string of fields to be filtered and returned - optional
            possible values are id, url, name, state, threat, certainty, severity, account_type, 
            tags, note, note_modified_by, note_modified_timestamp, privilege_level, privilege_category, 
            last_detection_timestamp, detection_set, probable_home
        """
        if not account_id:
            raise ValueError('Account id required')

        return requests.get('{url}/accounts/{id}'.format(url=self.url, id=account_id), headers=self.headers,
                                params=self._generate_account_params(kwargs), verify=self.verify)

    @request_error_handler
    def get_account_tags(self, account_id=None):
        """
        Get Account tags
        :param account_id: ID of the account for which to retrieve the tags
        """
        return requests.get('{url}/tagging/account/{id}'.format(url=self.url, id=account_id), headers=self.headers,
                            verify=False)

    @request_error_handler
    def set_account_tags(self, account_id=None, tags=[], append=False):
        """
        Set account tags
        :param account_id: ID of the account for which to set the tags
        :param tags: list of tags to add to account
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear tags (default: False)
        """
        if append and type(tags) == list:
            current_list = self.get_account_tags(account_id=account_id).json()['tags']
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

        return requests.patch('{url}/tagging/account/{id}'.format(url=self.url, id=account_id), headers=headers,
                              json=payload, verify=self.verify)

    @request_error_handler
    def bulk_set_accounts_tag(self, tag, account_ids):
        """
        Set a tag in bulk on multiple accounts. Only one tag can be set at a time
        :param account_ids: IDs of the accounts for which to set the tag
        """
        if not isinstance(account_ids, list):
            raise TypeError('account IDs must be of type list')

        payload = {
            'objectIds': account_ids,
            'tag': tag
        }
        return requests.post('{url}/tagging/account'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @request_error_handler
    def bulk_delete_accounts_tag(self, tag, account_ids):
        """
        Delete a tag in bulk on multiple accounts. Only one tag can be deleted at a time
        :param account_ids: IDs of the accounts on which to delete the tag
        """
        if not isinstance(account_ids, list):
            raise TypeError('account IDs must be of type list')

        payload = {
            'objectIds': account_ids,
            'tag': tag
        }
        return requests.delete('{url}/tagging/account'.format(url=self.url), headers=self.headers, json=payload,
                            verify=False)

    @request_error_handler
    def get_account_note(self, account_id=None):
        """
        Get account notes
        :param account_id: ID of the account for which to retrieve the note
        For consistency we return a requests.models.Response object
        As we do not want to return the complete host body, we alter the response content
        """
        account = requests.get('{url}/accounts/{id}'.format(url=self.url, id=account_id), headers=self.headers, verify=self.verify)
        if account.status_code == 200:
            account_note = account.json()['note']
            # API endpoint return HTML escaped characters
            account_note = html.unescape(account_note) if account_note else ''
            json_dict = {'status': 'success', 'account_id': str(account_id), 'note': account_note}
            account._content = json.dumps(json_dict).encode('utf-8')
        return account

    # TODO check if PATCH endpoint has been implemented on accounts
    def set_account_note(self, account_id=None, note='', append=False):
        raise NotImplementedError('The PATCH endpoint is not yet implemented on /accounts')

    @request_error_handler
    def get_locked_accounts(self):
        """
        Get list of account locked by Account Lockdown
        """
        return requests.get('{url}/lockdown/account'.format(url=self.url), headers=self.headers, verify=self.verify)

    def get_rules(self, **kwargs):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_rules() which supports pagination')

    def advanced_search(self, stype=None, page_size=50, query=None):
        """
        Advanced search
        :param stype: search type (hosts, detections, accounts)
        :param page_size: number of objects returned per page
        :param advanced query (download the following guide for more details on query language
            https://support.vectranetworks.com/hc/en-us/articles/360003225254-Search-Reference-Guide)
        """
        if stype not in ['hosts', 'detections', 'accounts']:
            raise ValueError("Supported values for stype are hosts, detections or accounts")

        if not query:
            raise ValueError('Query parameter is required')

        params = {
            'page_size': page_size,
            'query_string': query
        }

        resp = requests.get('{url}/search/{stype}'.format(url=self.url, stype=stype), headers=self.headers,
                                params=params, verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url=resp.json()['next'])
            yield resp

    @request_error_handler
    def get_rule_by_id(self, rule_id, **kwargs):
        """
        Get triage rules by id
        :param rule_id: id of triage rule to retrieve
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, additional_conditions, created_timestamp,
            description, detection, detection_category, enabled, id, is_whitelist, last_timestamp,
            priority, source_conditions, template, total_detections, triage_category, url
        """
        if not rule_id:
            raise ValueError('Rule id required')

        return requests.get('{url}/rules/{id}'.format(url=self.url, id=rule_id), headers=self.headers,
                                params=self._generate_rule_by_id_params(kwargs), verify=False)

    def get_rules_by_name(self, triage_category=None, description=None):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_rules with the "contains" query parameter')

    def get_all_rules(self, **kwargs):
        """
        Generator to retrieve all rules page by page - all parameters are optional
        :param contains: search for rules containing this string (substring matching)
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, additional_conditions, created_timestamp,
            description, detection, detection_category, enabled, id, is_whitelist, last_timestamp,
            priority, source_conditions, template, total_detections, triage_category, url
        :param include_templates: include rule templates, default is False
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        resp = requests.get('{url}/rules'.format(url=self.url), headers=self.headers,
                                params=self._generate_rule_params(kwargs), verify=self.verify)
        yield resp
        while resp.json()['next']:
            resp = self._get_request(url = resp.json()['next'])
            yield resp

    @request_error_handler
    def create_rule(self, detection_category=None, detection_type=None, triage_category=None, 
        source_conditions=None, additional_conditions=None, is_whitelist=False, **kwargs):
        """
        Create triage rule
        :param detection_category: detection category to triage
            possible values are: botnet activity, command & control, reconnaissance,
            lateral movement, exfiltration
        :param detection_type: detection type to triage
        :param triage_category: name that will be used for triaged detection
        :param source_conditions: JSON blobs to represent a tree-like conditional structure
            operators for leaf nodes: ANY_OF or NONE_OF
            operators for non-leaf nodes: AND or OR
            possible value for conditions: ip, host, account, sensor
            Here is an example of a payload:
            "sourceConditions": {
                "OR": [
                {
                    "AND": [
                    {
                        "ANY_OF": {
                        "field": "ip",
                        "values": [
                            {
                            "value": "10.45.91.184",
                            "label": "10.45.91.184"
                            }
                        ],
                        "groups": [],
                        "label": "IP"
                        }
                    }
                    ]
                }
                ]
            }
            }
        :param additional_conditions: JSON blobs to represent a tree-like conditional structure
            operators for leaf nodes: ANY_OF or NONE_OF
            operators for non-leaf nodes: AND or OR
            possible value for conditions: remote1_ip, remote1_ip_groups, remote1_proto, remote1_port, 
                remote1_dns, remote1_dns_groups, remote2_ip, remote2_ip_groups, remote2_proto, remote2_port, 
                remote2_dns, remote2_dns_groups, account, named_pipe, uuid, identity, service, file_share, 
                file_extensions, rdp_client_name, rdp_client_token, keyboard_name
            Here is an example of a payload:
            "additionalConditions": {
                "OR": [
                {
                    "AND": [
                    {
                        "ANY_OF": {
                        "field": "remote1_ip",
                        "values": [
                            {
                            "value": "10.1.52.71",
                            "label": "10.1.52.71"
                            }
                        ],
                        "groups": [],
                        "label": "External Target IP"
                        }
                    }
                    ]
                }
                ]
            }
        :param is_whitelist: set to True if rule is a whitelist, opposed to tracking detections without scores (boolean)
        :param description: name of the triage rule - optional
        :param priority: used to determine order of triage filters (int) - optional
        :returns request object
        """
        if not all([detection_category, detection_type, triage_category]):
            raise ValueError('Missing required parameter')
        
        if detection_category.lower() not in ['botnet activity', 'command & control', 'reconnaissance', 'lateral movement', 'exfiltration', 'info']:
            raise ValueError("detection_category not recognized")

        payload = {
            'detection_category': detection_category,
            'detection': detection_type,
            'triage_category': triage_category,
            'is_whitelist': is_whitelist,
            'source_conditions': source_conditions,
            'additional_conditions': additional_conditions
            }

        return requests.post('{url}/rules'.format(url=self.url), headers=self.headers, json=payload,
                             verify=self.verify)

    @request_error_handler
    def update_rule(self, rule_id=None, **kwargs):
        """
        Update triage rule
        :param rule_id: id of rule to update
        :param triage_category: name that will be used for triaged detection
        :param source_conditions: JSON blobs to represent a tree-like conditional structure
            operators for leaf nodes: ANY_OF or NONE_OF
            operators for non-leaf nodes: AND or OR
            possible value for conditions: ip, host, account, sensor
            Here is an example of a payload:
            "sourceConditions": {
                "OR": [
                {
                    "AND": [
                    {
                        "ANY_OF": {
                        "field": "ip",
                        "values": [
                            {
                            "value": "10.45.91.184",
                            "label": "10.45.91.184"
                            }
                        ],
                        "groups": [],
                        "label": "IP"
                        }
                    }
                    ]
                }
                ]
            }
            }
        :param additional_conditions: JSON blobs to represent a tree-like conditional structure
            operators for leaf nodes: ANY_OF or NONE_OF
            operators for non-leaf nodes: AND or OR
            possible value for conditions: remote1_ip, remote1_ip_groups, remote1_proto, remote1_port, 
                remote1_dns, remote1_dns_groups, remote2_ip, remote2_ip_groups, remote2_proto, remote2_port, 
                remote2_dns, remote2_dns_groups, account, named_pipe, uuid, identity, service, file_share, 
                file_extensions, rdp_client_name, rdp_client_token, keyboard_name
            Here is an example of a payload:
            "additionalConditions": {
                "OR": [
                {
                    "AND": [
                    {
                        "ANY_OF": {
                        "field": "remote1_ip",
                        "values": [
                            {
                            "value": "10.1.52.71",
                            "label": "10.1.52.71"
                            }
                        ],
                        "groups": [],
                        "label": "External Target IP"
                        }
                    }
                    ]
                }
                ]
            }
        :param is_whitelist: set to True if rule is a whitelist, opposed to tracking detections without scores (boolean)
        :param description: name of the triage rule - optional
        :param priority: used to determine order of triage filters (int) - optional
        :param enabled: is the rule currently enables (boolean) - optional - Not yet implemented!
        :returns request object
        """

        if rule_id:
            rule = self.get_rule_by_id(rule_id=rule_id).json()
        else:
            raise ValueError("rule id must be provided")
        
        valid_keys = ['description', 'priority', 'enabled', 'triage_category', 
            'is_whitelist', 'source_conditions', 'additional_conditions']

        for k, v in kwargs.items():
            if k in valid_keys:
                rule[k] = v
            else:
                raise ValueError('invalid parameter provided: {}'.format(str(k)))

        return requests.put('{url}/rules/{id}'.format(url=self.url, id=rule['id']), headers=self.headers, json=rule,
                            verify=self.verify)

    def get_groups(self, **kwargs):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_groups() which supports pagination')

    def get_groups_by_name(self, name=None, description=None):
        raise DeprecationWarning('This function has been deprecated in the Vectra API client v2.1. Please use get_all_groups with the "description" query parameter')

    def get_detect_usage(self, **kwargs):
        """
        Get average montly IP count for Detect
        :param start: starting month for the usage statistics - format YYYY-mm
        :param end: end month for the usage statistics - format YYYY-mm
        Default is statistics from last month
        """
        return requests.get('{url}/usage/detect'.format(url=self.url), params=self._generate_detect_usage_params(kwargs), 
            headers=self.headers, verify=self.verify)

    @request_error_handler
    def get_audits(self, start_date=None, end_date=None):
        """
        Get audits between start_date and end_date, inclusive
        :param start_date: start date (datetime.date), GMT, defaults to date.min
        :param end_date: end date (datetime.date), GMT, defaults to date.max
        """
        if start_date is None and end_date is None:
            return requests.get('{url}/audits'.format(url=self.url), headers=self.headers, verify=self.verify)
        elif start_date is None and end_date is not None:
            return requests.get('{url}/audits?end={end}'.format(url=self.url, end=end_date.isoformat()), headers=self.headers, verify=self.verify)
        elif start_date is not None and end_date is None:
            return requests.get('{url}/audits?start={start}'.format(url=self.url, start=start_date.isoformat()), headers=self.headers, verify=self.verify)
        else:
            return requests.get('{url}/audits?start={start}&end={end}'.format(url=self.url, start=start_date.isoformat(), end=end_date.isoformat()), headers=self.headers, verify=self.verify)


class VectraClientV2_2(VectraClientV2_1):

    def __init__(self, url=None, token=None, verify=False):
        """
        Initialize Vectra client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param token: API token for authentication when using API v2*
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(url=url, token=token, verify=verify)
        # Remove potential trailing slash
        url = VectraClient._remove_trailing_slashes(url)
        # Set endpoint to APIv2.1
        self.url = '{url}/api/v2.2'.format(url=url)

    def get_host_note(self, host_id=None):
        """
        Get host notes
        :param host_id: host ID
        """
        if not host_id:
            raise ValueError('Host id required')

        return requests.get('{url}/hosts/{id}/notes'.format(url=self.url, id=host_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def set_host_note(self, host_id=None, note=''):
        """
        Set host note
        :param host_id: host ID
        :param note: content of the note to set
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.post('{url}/hosts/{id}/notes'.format(url=self.url, id=host_id), headers=self.headers, json=payload,
            verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_host_note(self, host_id=None, note_id=None, note=''):
        """
        Set host note
        :param host_id: host ID
        :param note_id: ID of the note to update
        :param note: updated content of the note
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.patch('{url}/hosts/{host_id}/notes/{note_id}'.format(url=self.url, host_id=host_id, note_id=note_id), 
            headers=self.headers, json=payload, verify=self.verify)
    
    @validate_api_v2
    @request_error_handler
    def delete_host_note(self, host_id=None, note_id=None):
        """
        Set host note
        :param host_id: host ID
        :param note_id: ID of the note to delete
        """

        return requests.delete('{url}/hosts/{host_id}/notes/{note_id}'.format(url=self.url, host_id=host_id, note_id=note_id), 
            headers=self.headers, verify=self.verify)

    def get_detection_note(self, detection_id=None):
        """
        Get detection notes
        :param detection_id: detection ID
        """
        if not detection_id:
            raise ValueError('detection id required')

        return requests.get('{url}/detections/{id}/notes'.format(url=self.url, id=detection_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def set_detection_note(self, detection_id=None, note=''):
        """
        Set detection note
        :param detection_id: detection ID
        :param note: content of the note to set
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.post('{url}/detections/{id}/notes'.format(url=self.url, id=detection_id), headers=self.headers, json=payload,
            verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_detection_note(self, detection_id=None, note_id=None, note=''):
        """
        Set detection note
        :param detection_id: detection ID
        :param note_id: ID of the note to update
        :param note: updated content of the note
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.patch('{url}/detections/{detection_id}/notes/{note_id}'.format(url=self.url, detection_id=detection_id, note_id=note_id), 
            headers=self.headers, json=payload, verify=self.verify)
    
    @validate_api_v2
    @request_error_handler
    def delete_detection_note(self, detection_id=None, note_id=None):
        """
        Set detection note
        :param detection_id: detection ID
        :param note_id: ID of the note to delete
        """

        return requests.delete('{url}/detections/{detection_id}/notes/{note_id}'.format(url=self.url, detection_id=detection_id, note_id=note_id), 
            headers=self.headers, verify=self.verify)

    def get_account_note(self, account_id=None):
        """
        Get account notes
        :param account_id: account ID
        """
        if not account_id:
            raise ValueError('account id required')

        return requests.get('{url}/accounts/{id}/notes'.format(url=self.url, id=account_id), headers=self.headers, verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def set_account_note(self, account_id=None, note=''):
        """
        Set account note
        :param account_id: account ID
        :param note: content of the note to set
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.post('{url}/accounts/{id}/notes'.format(url=self.url, id=account_id), headers=self.headers, json=payload,
            verify=self.verify)

    @validate_api_v2
    @request_error_handler
    def update_account_note(self, account_id=None, note_id=None, note=''):
        """
        Set account note
        :param account_id: account ID
        :param note_id: ID of the note to update
        :param note: updated content of the note
        """
        if isinstance(note, str):
            payload = {
                "note": note
            }
        else:
            raise TypeError('Note must be of type str')

        return requests.patch('{url}/accounts/{account_id}/notes/{note_id}'.format(url=self.url, account_id=account_id, note_id=note_id), 
            headers=self.headers, json=payload, verify=self.verify)
    
    @validate_api_v2
    @request_error_handler
    def delete_account_note(self, account_id=None, note_id=None):
        """
        Set account note
        :param account_id: account ID
        :param note_id: ID of the note to delete
        """

        return requests.delete('{url}/accounts/{account_id}/notes/{note_id}'.format(url=self.url, account_id=account_id, note_id=note_id), 
            headers=self.headers, verify=self.verify)
