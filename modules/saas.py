import json
import re
import sys
import time
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("always", ".*", PendingDeprecationWarning)


class HTTPException(Exception):
    def __init__(self, response):
        """
        Custom exception class to report possible API errors
        The body is contructed by extracting the API error code from the requests.Response object
        """
        try:
            r = response.json()
            if "detail" in r:
                detail = r["detail"]
            elif "errors" in r:
                detail = r["errors"][0]["title"]
            elif "_meta" in r:
                detail = r["_meta"]["message"]
            else:
                detail = response.content
        except Exception:
            detail = response.content
        body = f"Status code: {str(response.status_code)} - {detail}"
        super().__init__(body)


class HTTPUnauthorizedException(HTTPException):
    '''Specific Exception'''


class HTTPTooManyRequestsException(HTTPException):
    '''Specific Exception'''


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        elif response.status_code == 401:
            raise HTTPUnauthorizedException(response)
        elif response.status_code == 429:
            raise HTTPTooManyRequestsException(response)
        else:
            raise HTTPException(response)

    return request_handler


def deprecation(message):
    warnings.warn(message, PendingDeprecationWarning)


def param_deprecation(key):
    message = f"{key} will be deprecated with Vectra API which will be annouced in an upcoming release"
    warnings.warn(message, PendingDeprecationWarning)


class VectraSaaSClient(object):
    def __init__(self, url=None, client_id=None, secret_key=None, verify=False):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - requried
        :param secret_key: API Secret Key for authenticaiton - required
        :param verify: Verify SSL (default: False) - optional
        """
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3
        self.url = f"{url}/api/v{self.version}"
        self.verify = verify
        self._access = None

        self.token_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        if client_id and secret_key:
            self.auth = (client_id, secret_key)
        else:
            raise RuntimeError(
                "API Client ID and Secret Key are required for authentication."
            )

    @staticmethod
    def _remove_trailing_slashes(url):
        if ":/" not in url:
            url = "https://" + url
        else:
            url = re.sub("^.*://?", "https://", url)
        url = url[:-1] if url.endswith("/") else url
        return url

    @request_error_handler
    def _request(self, method, url, **kwargs):
        """
        Do a get request on the provided URL
        This is used by paginated endpoints
        :rtype: requests.Response
        """
        self._check_token()
        if method not in ["get", "patch", "put", "post", "delete"]:
            raise ValueError("Invalid requests method provided")

        if "headers" in kwargs:
            headers = kwargs.pop("headers")
        else:
            headers = {
                "Authorization": f"Bearer {self._access}",
                "Content-Type": "application/json",
            }
        return requests.request(
            method=method, url=url, headers=headers, verify=self.verify, **kwargs
        )

    def _sleep(self, timeout):
        time.sleep(timeout)

    def _refresh_token(self):
        if self._refreshTime > int(time.time()):
            data = {"grant_type": "refresh_token", "refresh_token": self._refresh}
            response = requests.post(
                url=f"{self.base_url}/oauth2/token",
                headers=self.token_headers,
                auth=self.auth,
                data=data,
            )
            token_data = response.json()
            self._access = token_data["access_token"]
            self._accessTime = int(time.time()) + token_data["expires_in"] - 100
        else:
            self._get_token()

    def _get_token(self):
        data = {"grant_type": "client_credentials"}
        response = requests.post(
            url=f"{self.base_url}/oauth2/token",
            headers=self.token_headers,
            auth=self.auth,
            data=data,
        )
        token_data = response.json()
        self._access = token_data["access_token"]
        self._refresh = token_data["refresh_token"]
        self._accessTime = int(time.time()) + token_data["expires_in"] - 100
        self._refreshTime = int(time.time()) + token_data["refresh_expires_in"] - 100

    def _check_token(self):
        if not self._access:
            self._get_token()
        if self._accessTime < int(time.time()):
            self._refresh_token()

    @staticmethod
    def _generate_detection_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
                        "c_score",
                        "c_score_gte",
                        "category",
                        "certainty",
                        "certainty_gte",
                        "destination",
                        "detection_category",
                        "detection_type",
                        "fields",
                        "host_id",
                        "id",
                        "is_targeting_key_asset",
                        "last_timestamp",
                        "max_id",
                        "min_id",
                        "note_modified_timestamp_gte",
                        "ordering",
                        "page",
                        "page_size",
                        "proto",
                        "src_account",
                        "src_ip",
                        "state",
                        "t_score",
                        "t_score_gte",
                        "tags",
                        "threat_gte",
                        "threat_score"
                    ]
        deprecated_keys = ["c_score", "c_score_gte", "category", "t_score", "t_score_gte"]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_account_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "all",
            "c_score",
            "c_score_gte",
            "fields",
            "id",
            "max_id",
            "min_id",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "priviledge_category",
            "privilege_level",
            "privilege_level_gte",
            "state",
            "t_score",
            "t_score_gte",
            "tags",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_rule_params(args):
        """
        Generate query parameters for rules based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "contains",
            "fields",
            "include_templates",
            "page",
            "page_size",
            "ordering",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid rule query parameter"
                )
        return params

    @staticmethod
    def _generate_rule_by_id_params(args):
        """
        Generate query parameters for rule based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ["fields"]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid rule query parameter"
                )
        return params

    @staticmethod
    def _generate_assignment_params(args):
        """
        Generate query parameters for assignment queries based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        :param accounts: filter by accounts ([int])
        :param assignees: filter by assignees (int)
        :param created_after: filter by created after timestamp
        :param resolution: filter by resolution (int)
        :param resolved: filters by resolved status (bool)
        """
        params = {}
        valid_keys = [
            "accounts",
            "assignees",
            "created_after",
            "resolution",
            "resolved",
        ]

        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    if isinstance(v, list):
                        # Backend needs list parameters as a comma-separated list
                        str_values = [str(int) for int in v]
                        params[k] = ",".join(str_values)
                    else:
                        params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid assignment query parameter"
                )
        return params

    @staticmethod
    def _generate_resolution_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "accounts",
            "assignees",
            "resolution",
            "resolved",
            "created_after",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_account_event_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ["from", "limit"]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_audit_log_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "event_action",
            "event_object",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "from",
            "limit",
            "user_id",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    # Start SaaS Methods
    def get_all_detections(self, **kwargs):
        """
        Generator to retrieve all detections - all parameters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param category: detection category - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param certainty_gte: certainty score greater than or equal to (int)
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
        resp = self._request(
            method="get",
            url=f"{self.url}/detections",
            params=self._generate_detection_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

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
            raise ValueError("Detection id required")

        return self._request(
            method="get",
            url=f"{self.url}/detections/{detection_id}",
            params=self._generate_detection_params(kwargs),
        )

    def mark_detections_fixed(self, detection_ids=None):
        """
        Mark detections as fixed
        :param detection_ids: list of detections to mark as fixed
        """
        if not isinstance(detection_ids, list):
            raise ValueError("Must provide a list of detection IDs to mark as fixed")
        return self._toggle_detections_fixed(detection_ids, fixed=True)

    def unmark_detections_fixed(self, detection_ids=None):
        """
        Unmark detections as fixed
        :param detection_ids: list of detections to unmark as fixed
        """
        if not isinstance(detection_ids, list):
            raise ValueError("Must provide a list of detection IDs to unmark as fixed")
        return self._toggle_detections_fixed(detection_ids, fixed=False)

    def _toggle_detections_fixed(self, detection_ids, fixed):
        """
        Internal function to mark/unmark detections as fixed
        """
        payload = {"detectionIdList": detection_ids, "mark_as_fixed": str(fixed)}

        return self._request(method="patch", url=f"{self.url}/detections", json=payload)

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
            tags, note, note_modified_by, note_modified_timestamp, privilege_level,
            privilege_category, last_detection_timestamp, detection_set, probable_home
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
        resp = self._request(
            method="get",
            url=f"{self.url}/accounts",
            params=self._generate_account_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_account_by_id(self, account_id=None, **kwargs):
        """
        Get account by id
        :param account_id: account id - required
        :param fields: comma separated string of fields to be filtered and returned - optional
            possible values are id, url, name, state, threat, certainty, severity, account_type,
            tags, note, note_modified_by, note_modified_timestamp, privilege_level,
            privilege_category, last_detection_timestamp, detection_set, probable_home
        """
        if not account_id:
            raise ValueError("Account id required")

        return self._request(
            method="get",
            url=f"{self.url}/accounts/{account_id}",
            params=self._generate_detection_params(kwargs),
        )

    def get_all_rules(self, **kwargs):
        """
        Generator to retrieve all rules page by page - all parameters are optional
        :param contains:
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, all_hosts, category, created_timestamp
            description, enabled, flex1, flex2, flex3, flex4, flex5, flex6, host, host_group,
            id, identity, ip, ip_group, is_whitelist, last_timestamp, priority, remote1_dns,
            remote1_dns_groups, remote1_ip, remote1_ip_groups, remote1_kerb_account,
            remote1_kerb_service, remote1_port, remote1_proto, remote2_dns, remote2_dns_groups,
            remote2_ip, remote2_ip_groups, remote2_port, remote2_proto, sensor_luid, smart_category,
            template, total_detections, type_vname, url
        :param include_templates: include rule templates, default is False
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/rules",
            params=self._generate_rule_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_rule_by_id(self, rule_id, **kwargs):
        """
        Get triage rules by id
        :param rule_id: id of triage rule to retrieve
        :param fields: comma separated string of fields to be filtered and returned
            possible values are: active_detections, all_hosts, category, created_timestamp,
            description, enabled, flex1, flex2, flex3, flex4, flex5, flex6, host, host_group, id,
            identity, ip, ip_group, is_whitelist, last_timestamp, priority, remote1_dns,
            remote1_dns_groups, remote1_ip, remote1_ip_groups, remote1_kerb_account,
            remote1_kerb_service, remote1_port, remote1_proto, remote2_dns, remote2_dns_groups,
            remote2_ip, remote2_ip_groups, remote2_port, remote2_proto, sensor_luid, smart_category,
            template, total_detections, type_vname, url
        """
        if not rule_id:
            raise ValueError("Rule id required")

        # deprecation('Some rules are no longer compatible with the APIv2, please switch to the APIv2.1')

        return self._request(
            method="get",
            url=f"{self.url}/rules/{rule_id}",
            params=self._generate_rule_by_id_params(kwargs),
        )

    def create_rule(
        self,
        detection_category=None,
        detection_type=None,
        triage_category=None,
        source_conditions=None,
        additional_conditions=None,
        is_whitelist=False,
        **kwargs,
    ):
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
        :param additional_conditions: JSON blobs to represent a tree-like conditional structure
            operators for leaf nodes: ANY_OF or NONE_OF
            operators for non-leaf nodes: AND or OR
            possible value for conditions: remote1_ip, remote1_ip_groups, remote1_proto,
                remote1_port, remote1_dns, remote1_dns_groups, remote2_ip, remote2_ip_groups,
                remote2_proto, remote2_port, remote2_dns, remote2_dns_groups, account, named_pipe,
                uuid, identity, service, file_share, file_extensions, rdp_client_name,
                rdp_client_token, keyboard_name
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
            raise ValueError("Missing required parameter")

        if detection_category.lower() not in [
            "botnet activity",
            "command & control",
            "reconnaissance",
            "lateral movement",
            "exfiltration",
        ]:
            raise ValueError("detection_category not recognized")

        detection_types = {
            "command & control": [
                "ad suspicious sign-on",
                "aws root credential usage",
                "aws suspicious credential usage",
                "aws tor activity",
                "azure ad admin account creation",
                "azure ad mfa-failed suspicious sign-on",
                "azure ad redundant access creation",
                "azure ad suspicious oauth application",
                "azure ad tor activity",
                "o365 power automate http flow creation",
                "o365 suspicious power automate flow creation azure",
            ],
            "botnet activity": ["aws cryptomining"],
            "reconnaissance": [
                "aws ec2 enumeration",
                "aws organization discovery",
                "aws s3 enumeration",
                "aws suspect credential access from ec2",
                "aws suspect credential access from ecs",
                "aws suspect credential access from ssm",
                "aws suspect escalation reconnaissance",
                "aws user permission enumeration",
                "o365 suspect ediscovery",
                "o365 suspicious compliance search",
                "o365 unusual ediscovery search",
                "usage",
            ],
            "lateral movement": [
                "aws lambda hijacking aws logging disabled",
                "aws ransomware s3 activity",
                "aws security tools disabled",
                "aws suspect admin privilege granting aws suspect console pivot",
                "aws suspect login profile manipulation aws suspect privilege escalation",
                "aws user hijacking",
                "azure ad change to trusted ip configuration o365 disabling of security tools",
                "azure ad mfa disabled",
                "azure ad newly created admin account o365 ransomware",
                "azure ad privilege operation anomaly",
                "azure ad successful brute-force",
                "azure ad unusual scripting engine usage aws ecr hijacking",
                "o365 attacker tool: ruler",
                "o365 dll hijacking activity",
                "o365 external teams access",
                "o365 internal spearphising",
                "o365 log disabling attempt",
                "o365 malware stage: upload",
                "o365 risky exchange operation",
                "o365 suspicious mailbox manipulation",
                "o365 suspicious sharepoint operation",
                "o365 suspicious teams application",
            ],
            "exfiltration": [
                "aws suspect external access granting aws suspect public ebs change",
                "aws suspect public ec2 change",
                "aws suspect public s3 change",
                "o365 ediscovery exfil",
                "o365 exfiltration before termination",
                "o365 suspect power automate activity o365 suspicious sharing activity",
                "o365 suspicious download activity",
                "o365 suspicious exchange transport rule o365 suspicious mail forwarding",
            ],
        }
        if detection_type.lower() not in detection_types[detection_category]:
            raise ValueError("detection_type not recognized")

        source_conditions = {
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "ip",
                                "values": [
                                    {"value": "10.45.91.184", "label": "10.45.91.184"}
                                ],
                                "groups": [],
                                "label": "IP",
                            }
                        }
                    ]
                }
            ]
        }

        if not source_conditions and not additional_conditions:
            raise ValueError("Cannot have both condition payloads blank.")

        payload = {
            "detection_category": detection_category,
            "detection": detection_type,
            "triage_category": triage_category,
            "is_whitelist": is_whitelist,
            "source_conditions": source_conditions,
            "additional_conditions": additional_conditions,
        }

        return self._request(method="post", url=f"{self.url}/rules", json=payload)

    def update_rule(self, rule_id=None, **kwargs):
        """
        Update triage rule
        :param rule_id: id of rule to update - required
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
            possible value for conditions: remote1_ip, remote1_ip_groups, remote1_proto,
                remote1_port, remote1_dns, remote1_dns_groups, remote2_ip, remote2_ip_groups,
                remote2_proto, remote2_port, remote2_dns, remote2_dns_groups, account, named_pipe,
                uuid, identity, service, file_share, file_extensions, rdp_client_name,
                rdp_client_token, keyboard_name
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

        valid_keys = [
            "description",
            "priority",
            "enabled",
            "triage_category",
            "is_whitelist",
            "source_conditions",
            "additional_conditions",
        ]

        for k, v in kwargs.items():
            if k in valid_keys:
                rule[k] = v
            else:
                raise ValueError(f"invalid parameter provided: {str(k)}")

        return self._request(method="put", url=f"{self.url}/rules/{rule_id}", json=rule)

    def delete_rule(self, rule_id=None, detection_ids=None):
        """
        Delete triage rule
        :param rule_id:
        :param detection_ids: IDs of the detections that the triage rule will be removed from
        detections
        """
        if not rule_id:
            raise ValueError("Rule id required")

        if detection_ids and not isinstance(detection_ids, list):
            detection_ids = detection_ids.split(",")

        params = {"detectionIdList": detection_ids}

        return self._request(
            method="delete", url=f"{self.url}/rules/{rule_id}", params=params
        )

    def get_detection_tags(self, detection_id=None):
        """
        Get detection tags
        :param detection_id: detction ID. required
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        return self._request(
            method="get", url=f"{self.url}/tagging/detection/{detection_id}"
        )

    def set_detection_tags(self, detection_id=None, tags=[], append=False):
        """
        Set  detection tags
        :param detection_id: - required
        :param tags: list of tags to add to detection
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if append and isinstance(tags, list):
            current_list = self.get_detection_tags(detection_id=detection_id).json()[
                "tags"
            ]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch",
            url=f"{self.url}/tagging/detection/{detection_id}",
            json=payload,
        )

    # def bulk_set_detections_tag(self, tag, detection_ids):
    #     """
    #     Set a tag in bulk on multiple detections. Only one tag can be set at a time
    #     :param detection_ids: IDs of the detections for which to set the tag
    #     """
    #     if not isinstance(detection_ids, list):
    #         raise TypeError('Detection IDs must be of type list')

    #     payload = {
    #         'objectIds': detection_ids,
    #         'tag': tag
    #     }
    #     return self._request(method='post', url=f'{self.url}/tagging/detection', json=payload)

    # def bulk_delete_detections_tag(self, tag, detection_ids):
    #     """
    #     Delete a tag in bulk on multiple detections. Only one tag can be deleted at a time
    #     :param detection_ids: IDs of the detections for which to delete the tag
    #     """
    #     if not isinstance(detection_ids, list):
    #         raise TypeError('Detection IDs must be of type list')

    #     payload = {
    #         'objectIds': detection_ids,
    #         'tag': tag
    #     }
    #     return self._request(method='delete', url=f'{self.url}/tagging/detection', json=payload)

    def get_detection_notes(self, detection_id=None):
        """
        Get detection notes
        :param detection_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete detection body, we alter the response content
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        detection = self._request(
            method="get", url=f"{self.url}/detections/{detection_id}/notes"
        )
        if detection.status_code == 200:
            json_dict = {
                "status": "success",
                "detection_id": str(detection_id),
                "notes": detection.json()["notes"],
            }
            detection._content = json.dumps(json_dict).encode("utf-8")
        return detection

    def get_detection_note_by_id(self, detection_id=None, note_id=None):
        """
        Get detection notes
        :param detection_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete detection body, we alter the response content
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        detection = self._request(
            method="get", url=f"{self.url}/detections/{detection_id}/notes/{note_id}"
        )
        return detection

    def set_detection_note(self, detection_id=None, note=""):
        """
        Set detection note
        :param detection_id: - required
        :param note: content of the note to set - required
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")

        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post",
            url=f"{self.url}/detections/{detection_id}/notes",
            json=payload,
        )

    def update_detection_note(
        self, detection_id=None, note_id=None, note="", append=False
    ):
        """
        Set detection note
        :param detection_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_detection_note_by_id(
                detection_id=detection_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/detections/{detection_id}/notes/{note_id}",
            json=payload,
        )

    def delete_detection_note(self, detection_id=None, note_id=None):
        """
        Set detection note
        :param detection_id: - required
        :param note_id - required
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/detections/{detection_id}/notes/{note_id}"
        )

    def get_account_tags(self, account_id=None):
        """
        Get Account tags
        :param account_id: ID of the account for which to retrieve the tags - required
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        return self._request(
            method="get", url=f"{self.url}/tagging/account/{account_id}"
        )

    def set_account_tags(self, account_id=None, tags=[], append=False):
        """
        Set account tags
        :param account_id: ID of the account for which to set the tags - required
        :param tags: list of tags to add to account
        :param append: overwrites existing list if set to False (default), appends to existing tags if set to True
        Set to empty list to clear tags
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if append and isinstance(tags, list):
            current_list = self.get_account_tags(account_id=account_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch", url=f"{self.url}/tagging/account/{account_id}", json=payload
        )

    # def bulk_set_accounts_tag(self, tag, account_ids):
    #     """
    #     Set a tag in bulk on multiple accounts. Only one tag can be set at a time
    #     Note that account IDs in APIv2.1 are not the same IDs as seen in the UI
    #     :param account_ids: IDs of the accounts for which to set the tag
    #     """
    #     if not isinstance(account_ids, list):
    #         raise TypeError('account IDs must be of type list')

    #     payload = {
    #         'objectIds': account_ids,
    #         'tag': tag
    #     }
    #     return self._request(method='post', url=f'{self.url}/tagging/account', json=payload)

    # @request_error_handler
    # def bulk_delete_accounts_tag(self, tag, account_ids):
    #     """
    #     Delete a tag in bulk on multiple accounts. Only one tag can be deleted at a time
    #     Note that account IDs in APIv2.1 are not the same IDs as seen in the UI
    #     :param account_ids: IDs of the accounts on which to delete the tag
    #     """
    #     if not isinstance(account_ids, list):
    #         raise TypeError('account IDs must be of type list')

    #     payload = {
    #         'objectIds': account_ids,
    #         'tag': tag
    #     }
    #     return self._request(method='delete', url=f'{self.url}/tagging/account',  json=payload)

    def get_account_notes(self, account_id=None):
        """
        Get account notes
        :param account_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete account body, we alter the response content
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        account = self._request(
            method="get", url=f"{self.url}/accounts/{account_id}/notes"
        )
        if account.status_code == 200:
            # account_note = account.json()['note']
            # API endpoint return HTML escaped characters
            # account_note = html.unescape(account_note) if account_note else ''
            json_dict = {
                "status": "success",
                "account_id": str(account_id),
                "notes": account.json()["notes"],
            }
            account._content = json.dumps(json_dict).encode("utf-8")
        return account

    def get_account_note_by_id(self, account_id=None, note_id=None):
        """
        Get account notes
        :param account_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete account body, we alter the response content
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        account = self._request(
            method="get", url=f"{self.url}/accounts/{account_id}/notes/{note_id}"
        )
        return account

    def set_account_note(self, account_id=None, note=""):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        """
        if not account_id:
            raise ValueError("Must provide account_id.")

        if isinstance(note, str):
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str")

        return self._request(
            method="post", url=f"{self.url}/accounts/{account_id}/notes", json=payload
        )

    def update_account_note(self, account_id=None, note_id=None, note="", append=False):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        :param append: overwrites existing note if set to False, appends if set to True
        Set to empty note string to clear account note
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_account_note_by_id(
                account_id=account_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str):
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str")

        return self._request(
            method="patch",
            url=f"{self.url}/accounts/{account_id}/notes/{note_id}",
            json=payload,
        )

    def delete_account_note(self, account_id=None, note_id=None):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/accounts/{account_id}/notes/{note_id}"
        )
        pass

    def get_all_assignments(self, **kwargs):
        """
        Generator to retrieve all assignments - all parameters are optional
        :param accounts: filter by accounts ([int])
        :param assignees: filter by assignees (int)
        :param created_after: filter by created after timestamp
        :param resolution: filter by resolution (int)
        :param resolved: filters by resolved status (bool)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/assignments",
            params=self._generate_assignment_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def create_account_assignment(self, assign_account_id, assign_to_user_id):
        """
        Create new assignment
        :param assign_account_id: ID of the account to assign
        :param assign_to_user_id: ID of the assignee
        """
        payload = {
            "assign_account_id": assign_account_id,
            "assign_to_user_id": assign_to_user_id,
        }
        return self._request(method="post", url=f"{self.url}/assignments", json=payload)

    def update_assignment(self, assignment_id=None, assign_to_user_id=None):
        """
        Update an existing assignment
        :param assignment_id: ID of the assigbment to update
        :param assign_to_user_id: ID of the assignee
        """
        if not assignment_id:
            raise ValueError("Must provide assignment_id.")
        if not assign_to_user_id:
            raise ValueError("Must provide user_id for assignment.")
        payload = {"assign_to_user_id": assign_to_user_id}
        return self._request(
            method="put", url=f"{self.url}/assignments/{assignment_id}", json=payload
        )

    def delete_assignment(self, assignment_id):
        """
        Delete assignment
        :param assignment_id: assignment ID
        """
        if not assignment_id:
            raise ValueError("Must provide assignment_id.")
        return self._request(
            method="delete", url=f"{self.url}/assignments/{assignment_id}"
        )

    def set_assignment_resolved(
        self,
        assignment_id=None,
        detection_ids=[],
        outcome=None,
        note="",
        mark_as_fixed=False,
        triage_as=None,
    ):
        """
        Set an assignment as resolved
        :param outcome: integer value corresponding to the following:
            1: benign_true_positive
            2: malicious_true_positive
            3: false_positive
        :param note: Note to add to fixed/triaged detections
        :param triage_as: One-time triage detection(s) and rename as (str).
        :param mark_as_fixed: mark the detection(s) as fixed (bool). Custom triage_as and mark_as_fixed are mutually exclusive.
        :param detection_ids: list of detection IDs to fix/triage
        """
        if not triage_as and not mark_as_fixed:
            raise ValueError("Either triage_as or mark_as_fixed are requited")

        payload = {
            "outcome": outcome,
            "note": note,
            "mark_as_fixed": mark_as_fixed,
            "triage_as": triage_as,
            "detection_ids": detection_ids,
        }
        return self._request(
            method="put",
            url=f"{self.url}/assignments/{assignment_id}/resolve",
            json=payload,
        )

    def get_all_assignment_outcomes(self):
        """
        Get all outcomes
        """
        resp = self._request(method="get", url=f"{self.url}/assignment_outcomes")
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_assignment_outcome_by_id(self, outcome_id=None):
        """
        Describe an existing Assignment Outcome
        """
        if not outcome_id:
            raise ValueError("Must provide outcome_id.")
        return self._request(
            method="get", url=f"{self.url}/assignment_outcomes/{outcome_id}"
        )

    def create_assignment_outcome(self, title="", category=""):
        """
        Create a new custom Assignment Outcome
        :param tile: title of the new Assignment Outcome to create.
        :param category: one of benign_true_positive, malicious_true_positive or false_positive
        """
        if category not in [
            "benign_true_positive",
            "malicious_true_positive",
            "false_positive",
        ]:
            raise ValueError("Invalid category provided")

        if title == "":
            raise ValueError("Title cannot be empty.")
        payload = {"title": title, "category": category}
        return self._request(
            method="post", url=f"{self.url}/assignment_outcomes", json=payload
        )

    def update_assignment_outcome(self, outcome_id=None, title="", category=""):
        """
        Update an existing custom Assignment Outcome
        :param outcome_id:
        :param tile: title of the new Assignment Outcome to create.
        :param category: one of benign_true_positive, malicious_true_positive or false_positive
        """
        if category not in [
            "benign_true_positive",
            "malicious_true_positive",
            "false_positive",
        ]:
            raise ValueError("Invalid category provided")

        if title == "":
            raise ValueError("Title cannot be empty.")

        payload = {"title": title, "category": category}
        return self._request(
            method="put",
            url=f"{self.url}/assignment_outcomes/{outcome_id}",
            json=payload,
        )

    def delete_assignment_outcome(self, outcome_id=None):
        """
        Delete an existing custom Assignment Outcome
        :param outcome_id: ID of the Assignment Outcome to delete
        """
        if not outcome_id:
            raise ValueError("Must provide outcome_id.")
        return self._request(
            method="delete", url=f"{self.url}/assignment_outcomes/{outcome_id}"
        )

    def get_account_scoring(self, **kwargs):
        """
        Get account scoring
        :param from:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/account_scoring",
            params=self._generate_account_event_params(kwargs),
        )

    def get_account_detection(self, **kwargs):
        """
        Get account detection
        :param from:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/account_detection",
            params=self._generate_account_event_params(kwargs),
        )

    def get_audits(self, **kwargs):
        """
        Requires certain privs - Handle the error
        Get audit events
        :param event_timestamp_gte:
        :param event_timestamp_lte:
        :param from:
        :param user_id:
        :param event_object:
        :param event_action:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/audits",
            params=self._generate_audit_log_params(kwargs),
        )


class VectraSaaSClientV3_1(VectraSaaSClient):
    def __init__(self, url=None, client_id=None, secret_key=None, verify=False):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - requried
        :param secret_key: API Secret Key for authenticaiton - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url, client_id=client_id, secret_key=secret_key, verify=verify
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.1
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_entity_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "entity_type",
            "is_prioritized",
            "last_detection_timestamp_gte",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "state",
            "tags",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_entity_scoring_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "entity_type",
            "event_timestamp_gte",
            "from",
            "include_score_decreases",
            "limit",
            "type",
        ]
        deprecated_keys = ["entity_type"]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    def get_all_entities(self, **kwargs):
        """
        Generator to retrieve all entities - all parameters are optional
        :param is_prioritized',
        :param entity_type', "account","host","account,host"
        :param ordering',
        :param last_detection_timestamp_gte',
        :param name',
        :param note_modified_timestamp_gte',
        :param page',
        :param page_size',
        :param state:
        :param tags:
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/entities",
            params=self._generate_entity_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp
        url = f"{self.url}/entities"
        pass

    def get_entity_by_id(self, entity_id=None, **kwargs):
        """
        :param is_prioritized',
        :param entity_type', "account","host","account,host" - required
        :param ordering',
        :param last_detection_timestamp_gte',
        :param name',
        :param note_modified_timestamp_gte',
        :param page',
        :param page_size',
        :param state:
        :param tags:
        """
        params = self._generate_entity_params(kwargs)
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if "entity_type" not in params:
            raise ValueError("Must provide entity_type.")

        return self._request(
            method="get", url=f"{self.url}/entities/{entity_id}", params=params
        )

    def get_entity_scoring(self, **kwargs):
        """
        :param include_score_decreases:
        :param from:
        :param limit:
        :param event_timestamp_gte:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/entity_scoring",
            params=self._generate_entity_scoring_params(kwargs),
        )


class VectraSaaSClientV3_2(VectraSaaSClientV3_1):
    def __init__(self, url=None, client_id=None, secret_key=None, verify=False):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - requried
        :param secret_key: API Secret Key for authenticaiton - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url, client_id=client_id, secret_key=secret_key, verify=verify
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.2
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "account_ids",
            "account_names",
            "description",
            "importance",
            "last_modified_by",
            "last_modified_timestamp",
            "name",
            "page_size",
            "type",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    def get_all_groups(self, **kwargs):
        """
        Generator to retrieve all groups - all parameters are optional
        :param account_ids
        :param account_names
        :param importance
        :param description
        :param last_modified_timestamp
        :param last_modified_by
        :param name:
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/groups",
            params=self._generate_group_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_group_by_id(self, group_id=None, **kwargs):
        """
        Get groups by id
        :param rule_id: id of group to retrieve
        """
        if not group_id:
            raise ValueError("Must provide group_id.")
        return self._request(
            method="get",
            url=f"{self.url}/groups/{group_id}",
            params=self._generate_group_params(kwargs),
        )

    def get_group_by_name(self, name=None, description=None):
        """
        Get groups by name or description
        :param name: Name of group*
        :param description: Description of the group*
        *params are to be read as OR
        """
        if name and description:
            raise Exception("Can only provide a name OR a description")
        if name:
            response = next(self.get_all_groups(name=name, type="account"))
        elif description:
            response = next(
                self.get_all_groups(description=description, type="account")
            )
        return response.json()["results"]

    def create_group(
        self, name=None, description="", type='', members=[], importance='Medium', **kwargs
    ):
        """
        Create group
        :param name: name of the group to create
        :param description: description of the group
        :param type: type of the group to create (domain/host/ip)
        :param members: list of account ids to add to group
        :param importance: importance of the entities in this list [high,medium,low]
        :param rules: list of triage rule ids to add to group
        :rtype requests.Response:
        """
        #TODO: validate type
        #TODO: convert importance from string to int
        #TODO: validate k,v
        if not name:
            raise ValueError("missing required parameter: name")
        if not isinstance(members, list):
            raise TypeError("members must be type: list")
        if not importance:
            raise ValueError("missing required parameter: importance")

        payload = {
            "name": name,
            "description": description,
            "type": type,
            "members": members,
            "importance": importance,
        }

        for k, v in kwargs.items():
            if not isinstance(v, list):
                raise TypeError(f"{k} must be of type: list")
            payload[k] = v

        return self._request(method="post", url=f"{self.url}/groups", json=payload)

    def update_group(
        self, group_id, name=None, description=None, members=[], append=False
    ):
        """
        Update group
        :param group_id: id of group to update
        :param name: name of group
        :param description: description of the group
        :param members: list of host ids to add to group
        :param append: set to True if appending to existing list (boolean)
        """

        if not isinstance(members, list):
            raise TypeError("members must be type: list")

        group = self.get_group_by_id(group_id=group_id).json()
        try:
            id = group["id"]
        except KeyError:
            raise KeyError(f"Group with id {str(group_id)} was not found")

        # Transform existing members into flat list as API returns dicts for host & account groups
        if append:
            for member in group["members"]:
                members.append(member["id"])
        # Ensure members are unique
        members = list(set(members))

        name = name if name else group["name"]
        description = description if description else group["description"]

        payload = {"name": name, "description": description, "members": members}
        return self._request(
            method="patch", url=f"{self.url}/groups/{id}", json=payload
        )

    def delete_group(self, group_id=None):
        """
        Delete group
        :param group_id:
        detections
        """
        if not group_id:
            raise ValueError("Must provide group_id.")
        return self._request(method="delete", url=f"{self.url}/groups/{group_id}")


class VectraSaaSClientV3_3(VectraSaaSClientV3_2):
    def __init__(self, url=None, client_id=None, secret_key=None, verify=False):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - requried
        :param secret_key: API Secret Key for authenticaiton - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url, client_id=client_id, secret_key=secret_key, verify=verify
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.3
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "c_score",
            "c_score_gte",
            "certainty",
            "key_asset",
            "last_detection_timestamp",
            "last_source",
            "mac_address",
            "max_id",
            "min_id",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "privilege_category",
            "privilege_level",
            "privilege_level_gte",
            "state",
            "t_score",
            "t_score_gte",
            "tags",
            "threat",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid hosts query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_account_event_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ["from", "limit"]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_vectramatch_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "desired_state",
            "device_serial",
            "device_serials",
            "file",
            "notes",
            "uuid",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    @staticmethod
    def _generate_detection_events_params(args):
        """
        Generate query parameters for detection events based on provided args
        :param from:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        params = {}
        valid_keys = [
            "detection_id",
            "entity_type",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "from",
            "include_info_category",
            "include_triaged",
            "limit",
            "type",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    def get_vectramatch_enablement(self, **kwargs):
        """
        Determine enablement state of desired device
        :param device_serial: serial number of device (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "device_serial" not in params:
            raise ValueError("Device serial number is required.")
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/enablement", params=params
        )
        return resp

    def set_vectramatch_enablement(self, **kwargs):
        """
        Set desired enablement state of device
        :param device_serial: serial number of device (required)
        :param desired_state: boolean True or False (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "device_serial" not in params:
            raise ValueError("Device serial number is required.")

        if "desired_state" not in params:
            raise ValueError("Desired state is required (boolean).")
        resp = self._request(
            method="post", url=f"{self.url}/vectra-match/enablement", json=params
        )
        return resp

    def get_vectramatch_stats(self, **kwargs):
        """
        Retrieve vectra-match stats
        :param device_serial: serial number of device (optional)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/vectra-match/stats",
            params=self._generate_vectramatch_params(kwargs),
        )
        return resp

    def get_vectramatch_status(self, **kwargs):
        """
        Retrieve vectra-match status
        :param device_serial: serial number of device (optional)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/vectra-match/status",
            params=self._generate_vectramatch_params(kwargs),
        )
        return resp

    def get_vectramatch_available_devices(self):
        """
        Retrieve devices that can be enabled for vectra-match
        """
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/available-devices"
        )
        return resp

    def get_vectramatch_rules(self, **kwargs):
        """
        Retrieve vectra-match rules
        :param uuid: uuid of an uploaded ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Ruleset uuid must be provided.")
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/rules", params=params
        )
        return resp

    def upload_vectramatch_rules(self, **kwargs):
        """
        Upload vectra-match rules
        :param file: name of ruleset desired to be uploaded (required)
        :param notes: notes about the uploaded file (optional)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "file" not in params:
            raise ValueError("A ruleset filename is required.")
        if "notes" not in params:
            params["notes"] = ""
        headers = {"Authorization": self.headers["Authorization"]}
        resp = self._request(
            method="post",
            url=f"{self.url}/vectra-match/rules",
            headers=headers,
            files={"file": open(f"{params['file']}", "rb")},
            data={"notes": params["notes"]},
        )
        return resp

    def delete_vectramatch_rules(self, **kwargs):
        """
        Retrieve vectra-match rules
        :param uuid: uuid of an uploaded ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError(
                "Must provide the uuid of the desired ruleset to be deleted."
            )
        resp = self._request(
            method="delete", url=f"{self.url}/vectra-match/rules", json=params
        )
        return resp

    def get_vectramatch_assignment(self):
        """
        Retrieve ruleset assignments for vectra-match
        """
        resp = self._request(method="get", url=f"{self.url}/vectra-match/assignment")
        return resp

    def set_vectramatch_assignment(self, **kwargs):
        """
        Assign ruleset to device
        :param uuid: uuid of the ruleset to be assigned (required)
        :param device_serials: list of devices to assign the ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Must provide the ruleset uuid")
        if "device_serials" not in params:
            raise ValueError(
                "Must provide the serial number(s) of the device(s) to be assigned."
            )
        elif not isinstance(params["device_serials"], list):
            params["device_serials"] = params["device_serials"].split(",")
        resp = self._request(
            method="post", url=f"{self.url}/vectra-match/assignment", json=params
        )
        return resp

    def delete_vectramatch_assignment(self, **kwargs):
        """
        Assign ruleset to device
        :param uuid: uuid of the ruleset to be assigned (required)
        :param device_serial: serial of device (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Must provide the ruleset uuid")
        if "device_serial" not in params:
            raise ValueError("Must provide the device serial number.")
        resp = self._request(
            method="delete", url=f"{self.url}/vectra-match/assignment", json=params
        )
        return resp

    def get_all_hosts(self, **kwargs):
        """
        Generator to retrieve all hosts - all parameters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param last_detection_timestamp: timestamp of last activity on hosts (datetime)
        :param max_id: maximum ID of hosts returned
        :param min_id: minimum ID of hosts returned
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in repsonse (int)
        :param state: state of hosts (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param tags: tags assigned to hosts; this uses substring matching
        :param key_asset: key asset (bool) - will be removed with deprecation of v1 of api
        :param threat: threat score (int)
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/hosts",
            params=self._generate_host_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_hosts_by_id(self, hosts_id=None, **kwargs):
        """
        Get hosts by id
        :param hosts_id: hosts id - required
        """
        if not hosts_id:
            raise ValueError("hosts id required")

        return self._request(
            method="get",
            url=f"{self.url}/hosts/{hosts_id}",
            params=self._generate_host_params(kwargs),
        )

    def get_entity_tags(self, entity_id=None, entity_type=None, type=None):
        """
        Get entity tags
        :param entity_id: detction ID. required
        :param entity_type: depracated for type
        :param type: "account","host","account,host"
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )

        params = {"entity_type": entity_type, "type": type}
        return self._request(
            method="get", url=f"{self.url}/tagging/entity/{entity_id}", params=params
        )

    def set_entity_tags(
        self, entity_id=None, entity_type=None, type=None, tags=[], append=False
    ):
        """
        Set  entity tags
        :param entity_id: - required
        :param entity_type or type: -required
        :param tags: list of tags to add to entity
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if append and isinstance(tags, list):
            current_list = self.get_entity_tags(entity_id=entity_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch",
            url=f"{self.url}/tagging/entity/{entity_id}",
            json=payload,
            params=params,
        )

    def get_hosts_tags(self, hosts_id=None):
        """
        Get hosts tags
        :param hosts_id: detction ID. required
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        return self._request(method="get", url=f"{self.url}/tagging/host/{hosts_id}")

    def set_hosts_tags(self, hosts_id=None, tags=[], append=False):
        """
        Set  hosts tags
        :param hosts_id: - required
        :param tags: list of tags to add to hosts
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        if append and isinstance(tags, list):
            current_list = self.get_hosts_tags(hosts_id=hosts_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch", url=f"{self.url}/tagging/host/{hosts_id}", json=payload
        )

    def get_hosts_notes(self, hosts_id=None):
        """
        Get hosts notes
        :param hosts_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete hosts body, we alter the response content
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        hosts = self._request(method="get", url=f"{self.url}/hosts/{hosts_id}/notes")
        if hosts.status_code == 200:
            json_dict = {
                "status": "success",
                "hosts_id": str(hosts_id),
                "notes": hosts.json()["notes"],
            }
            hosts._content = json.dumps(json_dict).encode("utf-8")
        return hosts

    def get_hosts_note_by_id(self, hosts_id=None, note_id=None):
        """
        Get hosts notes
        :param hosts_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete hosts body, we alter the response content
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        hosts = self._request(
            method="get", url=f"{self.url}/hosts/{hosts_id}/notes/{note_id}"
        )
        return hosts

    def set_hosts_note(self, hosts_id=None, note=""):
        """
        Set hosts note
        :param hosts_id: - required
        :param note: content of the note to set - required
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")

        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post", url=f"{self.url}/hosts/{hosts_id}/notes", json=payload
        )

    def update_hosts_note(self, hosts_id=None, note_id=None, note="", append=False):
        """
        Set hosts note
        :param hosts_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_hosts_note_by_id(
                hosts_id=hosts_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/hosts/{hosts_id}/notes/{note_id}",
            json=payload,
        )

    def delete_hosts_note(self, hosts_id=None, note_id=None):
        """
        Set hosts note
        :param hosts_id: - required
        :param note_id - required
        """
        if not hosts_id:
            raise ValueError("Must provide hosts_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/hosts/{hosts_id}/notes/{note_id}"
        )

    def get_entity_notes(self, entity_id=None, entity_type=None, type=None):
        """
        Get entity notes
        :param entity_id:
        :param entity_type or type:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete entity body, we alter the response content
        """
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        entity = self._request(
            method="get", url=f"{self.url}/entities/{entity_id}", params=params
        )
        if entity.status_code == 200:
            json_dict = {
                "status": "success",
                "entity_id": str(entity_id),
                "notes": entity.json()["notes"],
            }
            entity._content = json.dumps(json_dict).encode("utf-8")
        return entity

    def get_entity_note_by_id(
        self, entity_id=None, entity_type=None, type=None, note_id=None
    ):
        """
        Get entity notes
        :param entity_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete entity body, we alter the response content
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        entity = self._request(
            method="get",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            params=params,
        )
        return entity

    def set_entity_note(self, entity_id=None, entity_type=None, type=None, note=""):
        """
        Set entity note
        :param entity_id: - required
        :param note: content of the note to set - required
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post",
            url=f"{self.url}/entities/{entity_id}/notes",
            json=payload,
            params=params,
        )

    def update_entity_note(
        self,
        entity_id=None,
        entity_type=None,
        type=None,
        note_id=None,
        note="",
        append=False,
    ):
        """
        Set entity note
        :param entity_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_entity_note_by_id(
                entity_id=entity_id, note_id=note_id, entity_type=entity_type, type=type
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            json=payload,
            params=params,
        )

    def delete_entity_note(
        self, entity_id=None, entity_type=None, type=None, note_id=None
    ):
        """
        Set entity note
        :param entity_id: - required
        :param note_id - required
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            params=params,
        )

    def get_account_scoring(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_entity_scoring()"
        )

    def get_account_detection(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_detection_events()"
        )

    def get_detection_events(self, **kwargs):
        """
        Get detection events
        :param from:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/detections",
            params=self._generate_detection_events_params(kwargs),
        )

    def get_lockdown(self, **kwargs):
        params = {}
        valid_keys = ["type", "entity_type"]
        deprecated_keys = ["entity_type"]
        for k, v in kwargs.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid campaign query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return self._request(method="get", url=f"{self.url}/lockdown", params=params)

    def get_health(self, cache=True, v_lans=True):
        """
        :param cache: (bool)
        :param v_lans: (bool)
        """
        return self._request(
            method="get",
            url=f"{self.url}/health",
            params={"cache": cache, "v_lans": v_lans},
        )

    def get_health_check(self, check=None):
        """
        Get health statistics for the appliance
        :param check: specific check to run - optional
            possible values are: cpu, disk, hostid, memory, network, power, sensors, system
        """
        if not check:
            return self._request(method="get", url=f"{self.url}/health")
        else:
            if not isinstance(check, str):
                raise ValueError("check need to be a string")
            return self._request(method="get", url=f"{self.url}/health/{check}")

    def get_users(self, username=None, role=None, last_login_gte=None):
        """
        :param username:
        :param role:
        :param last_login_gte:
        """
        params = {}
        if username:
            params["username"] = username
        if role:
            params["role"] = role
        if last_login_gte:
            params["last_login_gte"] = last_login_gte
        return self._request(method="get", url=f"{self.url}/users", params=params)


def parse_args(args):
    """Parse CLI arguments"""
    parser.add_argument(
        "--cognito_url",
        type=str,
        help="URL of brain to process. If omitted it will be asked for",
    )
    parser.add_argument(
        "--client_id",
        type=str,
        help="Client ID for the SaaS API. If omitted it will be asted for.",
    )
    parser.add_argument(
        "--secret_key",
        type=str,
        help="Secret Key for the SaaS API. If omitted it will be asted for.",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    parser = parse_args(sys.argv[1:])

    def write_tokens(client):
        with open(".tokens", "w") as f:
            f.write(f"_access:{client._access}\n")
            f.write(f"_accessTime:{client._accessTime}\n")
            f.write(f"_refresh:{client._refresh}\n")
            f.write(f"_refreshTime:{client._refreshTime}")

    def open_tokens(client):
        with open(".tokens", "r") as f:
            tokens = f.read()
        token = dict(x.split(":") for x in tokens.splitlines())
        client._access = token["_access"]
        client._accessTime = int(token["_accessTime"])
        client._refresh = token["_refresh"]
        client._refreshTime = int(token["_refreshTime"])

    saasClient = VectraSaaSClient(
        url=parser.cognito_url, client_id=parser.client_id, secret_key=parser.secret_key
    )

    if Path(".tokens").is_file():
        open_tokens(saasClient)
    else:
        saasClient._get_token()
        write_tokens(saasClient)
