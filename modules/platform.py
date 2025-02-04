import concurrent.futures
import copy
import json
import time
import warnings
from pathlib import Path

import requests

from vat.vectra import (
    VectraClientV2_5,
    _generate_params,
)

warnings.filterwarnings("always", ".*", PendingDeprecationWarning)


def validate_lte_api_v3_4(func):
    def api_validator(self, *args, **kwargs):
        if self.version < 3.4:
            return func(self, *args, **kwargs)
        else:
            raise NotImplementedError("Method is not accessible via v3.4+ of API")

    return api_validator


class VectraPlatformClientV3(VectraClientV2_5):
    VERSION3 = 3
    VERSION2 = None
    VERSION1 = None

    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )

    def yield_event_results(self, resp, method, **kwargs):
        params = kwargs.get("params", {})
        if self.threads == 1:
            while resp.json()["remaining_count"] > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                resp = self._request(
                    method=method,
                    url=resp.url.split("?")[0],
                    params=params,
                )
                yield resp
        else:
            count = resp.json()["remaining_count"]
            if count > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                yield from self.get_threaded_events(
                    resp.url.split("?")[0], count, **kwargs
                )

    @staticmethod
    def _generate_detection_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "fields",
            "page",
            "page_size",
            "ordering",
            "min_id",
            "max_id",
            "state",
            "category",
            "detection_type",
            "detection_category",
            "src_ip",
            "t_score",
            "t_score_gte",
            "threat_score",
            "threat_gte",
            "c_score",
            "c_score_gte",
            "certainty",
            "certainty_gte",
            "last_timestamp",
            "last_timestamp_gte",
            "last_timestamp_lte",
            "host_id",
            "tags",
            "destination",
            "proto",
            "is_targeting_key_asset",
            "is_triaged",
            "note_modified_timestamp_gte",
            "src_account",
            "id",
        ]
        deprecated_keys = [
            "c_score",
            "c_score_gte",
            "category",
            "t_score",
            "t_score_gte",
        ]

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_account_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "fields",
            "page",
            "page_size",
            "ordering",
            "name",
            "state",
            "t_score",
            "t_score_gte",
            "c_score",
            "c_score_gte",
            "tags",
            "all",
            "min_id",
            "max_id",
            "note_modified_timestamp_gte",
            "privilege_level",
            "privilege_level_gte",
            "privilege_category",
            "id",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

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
        valid_keys = [
            "accounts",
            "assignees",
            "created_after",
            "resolution",
            "resolved",
        ]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_resolution_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "accounts",
            "assignees",
            "resolution",
            "resolved",
            "created_after",
        ]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_account_event_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = ["checkpoint", "limit"]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_audit_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "event_timestamp_gte",
            "event_timestamp_lte",
            "checkpoint",
            "user_id",
            "event_object",
            "event_action",
            "limit",
        ]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    def get_threaded_events(self, resp, count, **kwargs):
        """
        Threaded generator to retrieve all events
        :param url: Brain URL
        :param checkpoint: Event ID from which to start the query
        :param count: Total number of events to retrieve
        :param limit: Number of events to retrieve per request
        :rtype: json object
        """
        limit = int(kwargs.pop("limit", 500))
        checkpoint = int(kwargs.pop("checkpoint", 0))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads, thread_name_prefix="Get All Generator"
        ) as executor:
            try:
                results = {
                    executor.submit(
                        self._request,
                        method="get",
                        url=resp.url.split("?")[0]
                        + f"?from={next_checkpoint}&limit={limit}",
                        params=kwargs,
                    ): next_checkpoint
                    for next_checkpoint in range(checkpoint, count + limit, limit)
                }
                for result in concurrent.futures.as_completed(results):
                    yield result.result()
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)

    # Start Platform Methods
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

        return self._request(
            method="get", url=f"{self.url}/detections/{detection_id}/notes/{note_id}"
        )

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

        return self._request(
            method="get", url=f"{self.url}/accounts/{account_id}/notes/{note_id}"
        )

    def get_account_scoring(self, **kwargs):
        """
        Get account scoring
        :param checkpoint:
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
        :param checkpoint:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/account_detection",
            params=self._generate_account_event_params(kwargs),
        )

    def get_all_audits(self, **kwargs):
        """
        Get audits
        :param event_timestamp_gte:
        :param event_timestamp_lte:
        :param checkpoint:
        :param user_id:
        :param event_object:
        :param event_action:
        :param limit:
        :param ordering:
        """
        try:
            limit = int(kwargs.pop("limit", 500))
        except KeyError:
            limit = 500

        if limit >= 1000:
            limit = 1000
        elif limit <= 0:
            limit = 1

        kwargs["limit"] = limit
        method = "get"
        resp = self._request(
            method=method,
            url=f"{self.url}/events/audits",
            params=self._generate_audit_params(kwargs),
        )
        yield resp

        yield from self.yield_event_results(resp, method, **kwargs)

    def get_audits(self, **kwargs):
        """
        Get audits
        :param event_timestamp_gte:
        :param event_timestamp_lte:
        :param checkpoint:
        :param user_id:
        :param event_object:
        :param event_action:
        :param limit:
        :param ordering:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/audits",
            params=self._generate_audit_params(kwargs),
        )


class VectraPlatformClientV3_1(VectraPlatformClientV3):
    VERSION3 = 3.1
    VERSION2 = None
    VERSION1 = None

    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )

    @staticmethod
    def _generate_entity_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "is_prioritized",
            "entity_type",
            "type",
            "ordering",
            "last_detection_timestamp_gte",
            "name",
            "note_modified_timestamp_gte",
            "page",
            "page_size",
            "state",
            "tags",
        ]

        deprecated_keys = ["entity_type"]

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_entity_scoring_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "type",
            "entity_type",
            "include_score_decreases",
            "checkpoint",
            "limit",
            "event_timestamp_gte",
        ]

        deprecated_keys = ["entity_type"]

        return _generate_params(args, valid_keys, deprecated_keys)

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
        url = f"{self.url}/entities"
        params = self._generate_entity_params(kwargs)
        method = "get"
        resp = self._request(
            method=method,
            url=url,
            params=params,
        )
        yield resp

        yield from self.yield_results(resp, method, params=params)

    def get_entity_by_id(self, entity_id=None, **kwargs):
        """
        :param is_prioritized',
        :param entity_type', "account","host","account,host" - required - deprecated for type
        :param type', "account","host","account,host" - required
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
        if "entity_type" not in params and "type" not in params:
            raise ValueError(
                "Must provide entity_type or type=('account','host', or 'account,host')."
            )

        return self._request(
            method="get", url=f"{self.url}/entities/{entity_id}", params=params
        )

    def get_entity_scoring(self, **kwargs):
        """
        :param include_score_decreases:
        :param checkpoint:
        :param limit:
        :param event_timestamp_gte:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/entity_scoring",
            params=self._generate_entity_scoring_params(kwargs),
        )


class VectraPlatformClientV3_2(VectraPlatformClientV3_1):
    VERSION3 = 3.2
    VERSION2 = None
    VERSION1 = None

    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """

        valid_keys = [
            "account_ids",
            "account_names",
            "importance",
            "description",
            "last_modified_timestamp",
            "last_modified_by",
            "name",
            "page_size",
            "type",
        ]

        deprecated_keys = []

        params = _generate_params(args, valid_keys, deprecated_keys)
        params = {"type": "account"}
        return params


class VectraPlatformClientV3_3(VectraPlatformClientV3_2):
    VERSION3 = 3.3
    VERSION2 = None
    VERSION1 = None

    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "fields",
            "page",
            "page_size",
            "ordering",
            "name",
            "state",
            "last_source",
            "threat",
            "threat_gte",
            "t_score",
            "t_score_gte",
            "certainty",
            "certainty_gte",
            "c_score",
            "c_score_gte",
            "last_detection_timestamp",
            "tags",
            "key_asset",
            "min_id",
            "max_id",
            "mac_address",
            "note_modified_timestamp_gte",
            "privilege_level",
            "privilege_level_gte",
            "privilege_category",
        ]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """

        valid_keys = [
            "account_ids",
            "account_names",
            "host_ids",
            "importance",
            "description",
            "last_modified_timestamp",
            "last_modified_by",
            "name",
            "page_size",
            "type",
        ]

        deprecated_keys = []

        params = _generate_params(args, valid_keys, deprecated_keys)
        return params

    @staticmethod
    def _generate_match_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "device_serial",
            "device_serials",
            "desired_state",
            "uuid",
            "file_path",
            "notes",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_detection_events_params(args):
        """
        Generate query parameters for detection events based on provided args
        :param checkpoint:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        valid_keys = [
            "checkpoint",
            "limit",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "type",
            "entity_type",
            "include_info_category",
            "include_triaged",
            "detection_id",
            "ordering",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_feed_params(args):
        """
        valid_keys = [
            "category",
            "certainty",
            "expiration",
            "lastUpdated",
            "lastUpdatedBy",
            "name",
            "ordering",
            "page",
            "page_size",
        ]

        Args:
            args (_type_): _description_
        """

    def get_entity_tags(self, entity_id=None, **kwargs):
        """
        Get entity tags
        :param entity_id: detection ID. required
        :param entity_type: deprecated for type
        :param type: "account","host","account,host"
        """
        params = self._generate_entity_params(kwargs)
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if "entity_type" in params:
            params["type"] = params["entity_type"]
            params.pop("entity_type")
        elif "type" not in params:
            raise ValueError("Must provide type=('account','host', or 'account,host').")

        return self._request(
            method="get", url=f"{self.url}/tagging/entity/{entity_id}", params=params
        )

    def set_entity_tags(self, entity_id=None, tags=None, append=False, **kwargs):
        """
        Set  entity tags
        :param entity_id: - required
        :param entity_type or type: -required
        :param tags: list of tags to add to entity
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if tags is None:
            tags = []
        params = self._generate_entity_params(kwargs)
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if "entity_type" in params:
            params["type"] = params["entity_type"]
            params.pop("entity_type")
        elif "type" not in params:
            raise ValueError("Must provide type=('account','host', or 'account,host').")

        if append and isinstance(tags, list):
            current_list = self.get_entity_tags(
                entity_id=entity_id,
                type=params["type"],
            ).json()["tags"]
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

    def get_entity_note(self, entity_id=None, **kwargs):
        """
        Get entity notes
        :param entity_id:
        :param entity_type or type:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete entity body, we alter the response content
        """
        params = self._generate_entity_params(kwargs)
        if "entity_type" or "type" not in params:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )

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

    @validate_lte_api_v3_4
    def get_account_scoring(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_entity_scoring()"
        )

    @validate_lte_api_v3_4
    def get_account_detection(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_detection_events()"
        )

    def get_all_detection_events(self, **kwargs):
        """
        Get detection events
        :param checkpoint:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        try:
            limit = int(kwargs.pop("limit", 500))
        except KeyError:
            limit = 500

        if limit >= 1000:
            limit = 1000
        elif limit <= 0:
            limit = 1

        params = params = self._generate_detection_events_params(kwargs)
        kwargs["limit"] = limit
        method = "get"
        resp = self._request(
            method=method,
            url=f"{self.url}/events/detections",
            params=params,
        )
        yield resp

        yield from self.yield_event_results(resp, method, params=params)

    def get_detection_events(self, **kwargs):
        """
        Get detection events
        :param checkpoint:
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
        """ """
        valid_keys = ["type", "entity_type"]
        deprecated_keys = ["entity_type"]

        return self._request(
            method="get",
            url=f"{self.url}/lockdown",
            params=_generate_params(kwargs, valid_keys, deprecated_keys),
        )

    def download_vectra_ruleset(self, filename=None):
        if filename is None:
            filename = "curated.rules"
        elif not isinstance(filename, str):
            filename = "curated.rules"
            raise TypeError(
                "Filename must be of type str. File is being named 'curated.rules'."
            )

        p = Path(filename)
        p.parent.mkdir(parents=True, exist_ok=True)

        resp = self._request(
            method="get", url=self.url + "/vectra-match/download-vectra-ruleset"
        )

        resp = requests.get(url=resp.json()["download_url"])

        with open(str(filename), "wb") as file:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
        return resp

    def upload_match_ruleset(self, **kwargs):
        """
        Upload vectra-match rules
        :param file: name of ruleset desired to be uploaded (required)
        :param notes: notes about the uploaded file (optional)
        """
        file_path = kwargs.get("file_path", False)
        if not file_path:
            raise ValueError("A ruleset filename is required.")
        notes = kwargs.get("notes", "")
        headers = {"Authorization": self.headers["Authorization"]}

        # Get the upload url
        resp = self._request(
            method="post",
            url=f"{self.url}/vectra-match/rules/upload/",
            headers=headers,
            json={"file_name": file_path, "notes": notes},
        )

        upload_url = resp.json()["urls"][0]
        upload_id = resp.json()["id"]

        # Upload the file to the provided url
        payload = open(f"{file_path}", "rb")
        resp = requests.put(upload_url, data=payload)

        if resp.status_code == 200:
            # Patch the request
            resp = self._request(
                method="patch",
                url=f"{self.url}/vectra-match/rules/upload/{upload_id}",
                json={"upload_status": "completed"},
            )

        if resp.status_code == 200:
            while True:
                resp = self._request(
                    method="get",
                    url=f"{self.url}/vectra-match/rules/upload/{upload_id}",
                )
                if resp.json()["external_task_status"] != "in_progress":
                    break
                time.sleep(5)

        return resp

    def get_feeds(self, **kwargs):
        """
        Gets list of currently configured threat feeds
        :param category: category that detection will register. supported values are lateral, exfil, and cnc
        :param certainty: certainty applied to detection. Supported values are Low, Medium, High
        :param expiration: Date feed expires ISO8601
        :param lastUpdated: Date feed last updated ISO8601
        :param lastUpdatedBy: By whom feed was last updated
        :param name: name of threat feed
        :param ordering: field to use to order response
        :param page: Which page to return in multipage requests
        :param page_size: How many items to return to page
        """

        params = self._generate_feed_params(kwargs)
        return self._request(method="get", url=f"{self.url}/threatFeeds", params=params)

    def get_feed_by_name(self, name=None):
        """
        Gets configured threat feed by name
        :param name: name of threat feed
        """
        return self.get_feeds(name=name)

    def update_feed(self, name, **kwargs):
        """
        Update threat feed
        ***Values for category, type, and certainty are case sensitive***
        ***STIX files must already be uploaded***
        :param feed_id: id of the feed to update
        :param name: name of threat feed
        :param category: category that detection will register. supported values are lateral, exfil, and cnc
        :param certainty: certainty applied to detection. Supported values are Low, Medium, High
        :param itype: indicator type - supported values are Anonymize, Exfiltration, Malware Artifacts, and Watchlist
        :param duration: days that the threat feed will be applied
        :param replace_filename: Name of uploaded STIX file to update on Threat feed
        :param filename: Name of STIX file to be replaced on Threat feed
        :returns: request object
        """
        feed_to_update = self.get_feed_by_name(name=name)

        feed_id = feed_to_update["id"]

        category = kwargs.get("category", feed_to_update["category"])
        certainty = kwargs.get("certainty", feed_to_update["certainty"])
        itype = kwargs.get("itype", feed_to_update["itype"])
        duration = kwargs.get("duration", feed_to_update["duration"])
        replace_filename = kwargs.get("replace_filename", None)
        filename = kwargs.get("filename", None)

        if replace_filename is None or filename is None:
            raise ValueError(
                "Must provide 'replace_filename' and 'filename' to update threat feed"
            )

        if category not in ["lateral", "exfil", "cnc"]:
            raise ValueError(f"Invalid category provided: {category}")

        if certainty not in ["Low", "Medium", "High"]:
            raise ValueError(f"Invalid certainty provided: {str(certainty)}")

        if itype not in [
            "Anonymize",
            "Exfiltration",
            "Malware Artifacts",
            "Watchlist",
            "C2",
        ]:
            raise ValueError(f"Invalid itype provided: {str(itype)}")

        if not isinstance(duration, int):
            raise ValueError(
                "Invalid duration provided, duration must be an integer value"
            )

        payload = {
            "threatFeed": {
                "name": name,
                "defaults": {
                    "category": category,
                    "certainty": certainty,
                    "indicatorType": itype,
                    "duration": duration,
                },
                "upload": {"replace_filename": replace_filename, "filename": filename},
            }
        }

        return self._request(
            method="post", url=f"{self.url}/threatFeeds/{feed_id}", json=payload
        )

    def post_stix_file(self, feed_id=None, stix_file=None):
        """
        Uploads STIX file to new threat feed or overwrites STIX file in existing threat feed
        :param feed_id: id of threat feed
        :param stix_file: stix filename
        """
        headers = copy.deepcopy(self.headers)
        headers.pop("Content-Type", None)
        headers.update({"User-agent": "Mozilla/5.0"})
        return self._request(
            method="post",
            url=f"{self.url}/threatFeeds/{feed_id}",
            headers=headers,
            files={"file": open(stix_file, "rb")},
        )


class VectraPlatformClientV3_4(VectraPlatformClientV3_3):
    VERSION3 = 3.4
    VERSION2 = None
    VERSION1 = None

    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )

    @staticmethod
    def _generate_entity_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "is_prioritized",
            "type",
            "ordering",
            "last_detection_timestamp_gte",
            "name",
            "note_modified_timestamp_gte",
            "page",
            "page_size",
            "state",
            "tags",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_entity_scoring_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "type",
            "include_score_decreases",
            "checkpoint",
            "limit",
            "event_timestamp_gte",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_detection_events_params(args):
        """
        Generate query parameters for detection events based on provided args
        :param checkpoint:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        valid_keys = [
            "checkpoint",
            "limit",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "type",
            "include_info_category",
            "include_triaged",
            "detection_id",
            "ordering",
        ]

        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_detection_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        valid_keys = [
            "fields",
            "page",
            "page_size",
            "ordering",
            "min_id",
            "max_id",
            "state",
            "detection_type",
            "detection_category",
            "src_ip",
            "threat_score",
            "threat_gte",
            "certainty",
            "certainty_gte",
            "last_timestamp",
            "last_timestamp_gte",
            "last_timestamp_lte",
            "host_id",
            "tags",
            "destination",
            "proto",
            "is_targeting_key_asset",
            "is_triaged",
            "note_modified_timestamp_gte",
            "src_account",
            "id",
        ]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_user_params(args):
        valid_keys = ["page", "page_size", "email", "role", "last_login_gte"]
        deprecated_keys = []

        return _generate_params(args, valid_keys, deprecated_keys)

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """

        valid_keys = [
            "account_ids",
            "account_names",
            "host_ids",
            "importance",
            "description",
            "last_modified_timestamp",
            "last_modified_by",
            "name",
            "page_size",
            "type",
            "is_regex",
            "is_membership_evaluation_ongoing",
            "include_members",
        ]

        deprecated_keys = []

        params = _generate_params(args, valid_keys, deprecated_keys)
        return params

    def create_group(self, **kwargs):
        if not (name := kwargs.get("name")):
            raise ValueError("Missing required parameter: name")

        members = kwargs.get("members", [])
        regex = kwargs.get("regex", None)
        type = kwargs.get("type", "")

        if members != [] and regex is not None:
            raise ValueError("Members cannot be specified when creating a regex group.")
        elif members != []:
            regex = None
        elif regex is not None:
            members = []

        importance = kwargs.get("importance", "medium")
        description = kwargs.get("description", "")

        if regex is None and type not in [
            "host",
            "domain",
            "ip",
            "account",
        ]:
            raise ValueError(
                'parameter type must have value "account", "domain", "ip" or "host"'
            )
        elif regex is not None and type not in ["host", "account"]:
            raise ValueError('parameter type must have value "account" or "host"')
        rules = kwargs.get("rules", [])
        if not isinstance(members, list):
            raise TypeError("members must be type: list")
        if not isinstance(rules, list):
            raise TypeError("rules must be type: list")

        if regex is None:
            # Static POST body
            payload = {
                "name": name,
                "description": description,
                "type": type,
                "members": members,
                "importance": importance,
            }
        else:
            # Dynamic POST body
            payload = {
                "name": name,
                "description": description,
                "type": type,
                "importance": importance,
                "regex": regex,
            }

        return self._request(
            method="post",
            url=f"{self.url}/groups",
            headers=self.headers,
            json=payload,
        )

    def update_group(self, group_id=None, **kwargs):
        group = self.get_group_by_id(group_id=group_id).json()

        if members := kwargs.get("members", []):
            if kwargs.get("regex"):
                raise ValueError(
                    "Members cannot be specified when updating a regex group."
                )
            else:
                regex = None
        elif regex := kwargs.get("regex"):
            pass
        else:
            members = copy.deepcopy(group.get("members", []))
            regex = None

        name = kwargs.get("name", group["name"])
        description = kwargs.get("description", group["description"])
        importance = kwargs.get("importance", group["importance"])

        # Transform existing members into flat list as API returns dicts for host & account groups
        if kwargs.get("append", False):
            if group["type"] in ["domain", "ip"]:
                for member in group["members"]:
                    members.append(member)
            else:
                for member in group["members"]:
                    members.append(member["id"])
        # Ensure members are unique
        members = list(set(members))

        if regex is None:
            # Static POST body
            payload = {
                "name": name,
                "description": description,
                "members": members,
                "importance": importance,
            }
        else:
            # Dynamic POST body
            payload = {
                "name": name,
                "description": description,
                "importance": importance,
                "regex": regex,
            }

        return self._request(
            method="patch",
            url=f"{self.url}/groups/{group_id}",
            headers=self.headers,
            json=payload,
        )

    def get_health_check(self, check=None, cache=True, vlans=True):
        """
        Get health statistics for the appliance
        :param check: specific check to run - optional
            possible values are: cpu, disk, hostid, memory, network, power, sensors, system
        :param cache: (bool) - optional
        :param vlans: (bool) - optional
        """

        if check is None:
            return self._request(
                method="get",
                url=f"{self.url}/health",
                params={"cache": cache, "vlans": vlans},
            )
        else:
            if check not in [
                "network",
                "system",
                "memory",
                "sensors",
                "hostid",
                "disk",
                "cpu",
                "power",
                "connectivity",
                "trafficdrop",
                "detection",
                "external_connectors",
                "external_connectors/details",
                "edr",
                "edr/details",
                "network_brain/ping",
            ]:
                raise ValueError("Invalid check argument")
            return self._request(method="get", url=f"{self.url}/health/{check}")

    def get_user_roles(self):
        return self._request(
            method="get",
            url=f"{self.url}/users/roles",
        )

    def get_user_by_name(self, username=None, **kwargs):
        """
        :param username: Value contained in the name field.
        :rtype: dict
        """
        if username is None:
            raise ValueError("Must provide a name.")
        for users in self.get_all_users():
            for user in users.json()["results"]:
                if username == user["name"]:
                    return user
        return {}

    def get_user_by_email(self, email=None, **kwargs):
        """
        :param email: The email to be queried
        :rtype: dict
        """
        if email is None:
            raise ValueError("Must provide an email.")
        params = self._generate_user_params(kwargs)
        return self._request(
            method="get",
            url=f"{self.url}/users",
            params=params,
        )

    def create_user(self, **kwargs):
        roles = self.get_user_roles()
        standardized_names = [x["standardized_name"] for x in roles.json()]

        if not (name := kwargs.get("name")):
            raise ValueError(
                "Must provide a name to create a user. The name field requires space separated first and last name."
            )
        if not (role := kwargs.get("role")) and role not in standardized_names:
            raise ValueError("Must provide a valid role to create a user.")
        if not (email := kwargs.get("email")):
            raise ValueError("Must provide an email to create a user.")

        payload = {
            "name": name,
            "role": role,
            "email": email,
        }

        return self._request(method="post", url=f"{self.url}/users", json=payload)

    def update_user(self, user_id=None, **kwargs):
        roles = self.get_user_roles()
        standardized_names = [x["standardized_name"] for x in roles.json()]
        user = self.get_user_by_id(user_id=user_id).json()

        if (
            role := kwargs.get("role", user["role"])
        ) and role not in standardized_names:
            raise ValueError("Role is not valid.")

        if (
            not (name := kwargs.get("name", user["name"]))
            and not isinstance(name, str)
            and not len(name.split(" ")) == 2
        ):
            raise ValueError(
                "Must provide a name to create a user. The name field requires space separated first and last name."
            )

        payload = {
            "name": name,
            "role": role,
        }

        return self._request(
            method="patch", url=f"{self.url}/users/{user_id}", json=payload
        )

    def delete_user(self, user_id=None):
        return self._request(method="delete", url=f"{self.url}/users/{user_id}")

    def get_lockdown(self, **kwargs):
        """ """
        valid_keys = ["type"]
        deprecated_keys = []

        return self._request(
            method="get",
            url=f"{self.url}/lockdown",
            params=_generate_params(kwargs, valid_keys, deprecated_keys),
        )


class ClientV3_latest(VectraPlatformClientV3_4):
    def __init__(
        self,
        user=None,
        password=None,
        token=None,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Platform client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            token=token,
            verify=verify,
        )
