import concurrent.futures
import json
import logging
import sys
import time
import warnings
from pathlib import Path

import backoff
import requests
from vat.vectra import (
    HTTPException,
    VectraClientV2_5,
    _generate_params,
)

warnings.filterwarnings("always", ".*", PendingDeprecationWarning)


class CustomException(Exception):
    "Custom Exception raised while failure occurs."
    pass


class TooManyRequestException(Exception):
    "Custom Exception raised while requests exceeds."
    pass


def kill_process_and_exit(e):
    logging.error("Exiting current process.")
    sys.exit()


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
        self.token_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self._access = False
        self._check_token()
        self.verify = verify
        self.headers = {
            "Authorization": f"Bearer {self._access}",
            "Content-Type": "application/json",
        }

    def _sleep(self, timeout):
        time.sleep(timeout)

    @backoff.on_exception(
        backoff.expo,
        (
            requests.exceptions.RequestException,
            TooManyRequestException,
            requests.exceptions.HTTPError,
            CustomException,
        ),
        max_tries=3,
        on_giveup=kill_process_and_exit,
        max_time=30,
    )
    def _refresh_token(self):
        """Generate access token for API authentication.
        Returns:
            str: Access Token
        """
        resp = {}
        logging.info("Generating access token using refresh token.")
        try:
            resp = requests.post(
                url=f"{self.base_url}/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": f"{self._refresh}",
                },
                headers=self.token_headers,
                verify=self.verify,
            )
            if resp.status_code == 401:
                raise CustomException("Retrying to generate access token")
            if resp.status_code == 429:
                raise TooManyRequestException("Too many requests.")
            resp.raise_for_status()
            logging.info("Access token is generated using refresh token.")
            self._access = resp.json().get("access_token")
            self._accessTime = int(time.time()) + resp.json().get("expires_in") - 100
        except CustomException as e:
            logging.error(f"Error occurred: {e}")
            self._get_token()
            raise CustomException
        except TooManyRequestException as e:
            logging.info(
                f"{e}. Retrying after {int(resp.headers.get('Retry-After'))} seconds."
            )
            time.sleep(int(resp.headers.get("Retry-After")))
            raise TooManyRequestException from e
        except requests.exceptions.HTTPError:
            logging.error("Vectra API server is down. Retrying after 10 seconds.")
            time.sleep(10)
            raise requests.exceptions.HTTPError
        except requests.exceptions.RequestException as req_exception:
            logging.error(f"Retrying. An exception occurred: {req_exception}")
            raise requests.exceptions.RequestException from req_exception
        except Exception as e:
            logging.error(f"An exception occurred: {e}")

    @backoff.on_exception(
        backoff.expo,
        (
            requests.exceptions.RequestException,
            TooManyRequestException,
            requests.exceptions.HTTPError,
            CustomException,
        ),
        max_tries=3,
        on_giveup=kill_process_and_exit,
        max_time=30,
    )
    def _get_token(self):
        """Generate access token for API authentication.

        Returns:
            str: Access Token
        """
        resp = {}

        logging.info("Generating access token.")
        try:

            resp = requests.post(
                f"{self.base_url}/oauth2/token",
                auth=self.auth,
                headers=self.token_headers,
                data={"grant_type": "client_credentials"},
                verify=self.verify,
            )
            if resp.status_code == 401:
                raise CustomException(
                    f"Status-code {resp.status_code} Exception: Client ID or Client Secret is incorrect."
                )
            if resp.status_code == 405:
                redirect = resp.request.url
                self.base_url = "https://" + redirect.strip().split("/")[2]
                self.url = f"{self.base_url}/api/v{self.VERSION3}"
                self._get_token()
            if resp.status_code == 429:
                raise TooManyRequestException("Too many requests.")
            if resp.status_code == 200:
                logging.info("Access token is generated.")
                self._access = resp.json().get("access_token")
                self._refresh = resp.json().get("refresh_token")
                self._accessTime = (
                    int(time.time()) + resp.json().get("expires_in") - 100
                )
                self._refreshTime = (
                    int(time.time()) + resp.json().get("refresh_expires_in") - 100
                )
        except CustomException as e:
            logging.error(f"Error occurred: {e}")
        except TooManyRequestException as e:
            logging.info(
                f"{e}. Retrying after {int(resp.headers.get('Retry-After'))} seconds."
            )
            time.sleep(int(resp.headers.get("Retry-After")))
            raise TooManyRequestException from e
        except requests.exceptions.HTTPError as e:
            print(e)
            logging.error("Vectra API server is down. Retrying after 10 seconds.")
            time.sleep(10)
            raise requests.exceptions.HTTPError
        except requests.exceptions.RequestException as req_exception:
            logging.error(f"Retrying. An exception occurred: {req_exception}")
            raise requests.exceptions.RequestException from req_exception
        except Exception as e:
            logging.error(f"An exception occurred: {e}")

    def _check_token(self):
        if not self._access:
            self._get_token()
        elif self._accessTime < int(time.time()):
            self._refresh_token()

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

    def get_threaded_events(self, url, count, **kwargs):

        limit = kwargs.pop("limit")
        checkpoint = kwargs.pop("checkpoint")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads, thread_name_prefix="Get All Generator"
        ) as executor:
            try:
                results = {
                    executor.submit(
                        self._request,
                        method="get",
                        url=url + f"?from={next_checkpoint}&limit={limit}",
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
            limit = kwargs.pop("limit")
        except KeyError:
            limit = 500

        if limit >= 1000:
            limit = 1000
        elif limit <= 0:
            limit = 1

        kwargs["limit"] = limit
        resp = self.get_audits(**kwargs)
        yield resp

        if self.threads == 1:
            while resp.json()["remaining_count"] > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                resp = self.get_audits(**kwargs)
                yield resp
        else:
            count = resp.json()["remaining_count"]
            if count > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                yield from self.get_threaded_events(
                    f"{self.url}/events/audits", count, **kwargs
                )

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
        resp = self._request(
            method="get",
            url=url,
            params=params,
        )
        yield resp
        if self.threads == 1:
            while resp.json()["next"]:
                resp = self._request(method="get", url=resp.json()["next"])
                yield resp
        else:
            count = resp.json()["count"]
            yield from self.get_threaded(url, count, params=params)

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

    def set_entity_tags(self, entity_id=None, tags=[], append=False, **kwargs):
        """
        Set  entity tags
        :param entity_id: - required
        :param entity_type or type: -required
        :param tags: list of tags to add to entity
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
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
            limit = kwargs.pop("limit")
        except KeyError:
            limit = 500

        if limit >= 1000:
            limit = 1000
        elif limit <= 0:
            limit = 1

        kwargs["limit"] = limit
        resp = self._request(
            method="get",
            url=f"{self.url}/events/detections",
            params=self._generate_detection_events_params(kwargs),
        )
        yield resp
        if self.threads == 1:
            while resp.json()["remaining_count"] > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                resp = self._request(
                    method="get",
                    url=f"{self.url}/events/detections",
                    params=self._generate_detection_events_params(kwargs),
                )
                yield resp
        else:
            count = resp.json()["remaining_count"]
            if count > 0:
                kwargs["checkpoint"] = resp.json()["next_checkpoint"]
                yield from self.get_threaded_events(
                    f"{self.url}/events/detections", count, **kwargs
                )

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
        params = self._generate_vectramatch_params(kwargs)
        if not params.get("file_path"):
            raise ValueError("A ruleset filename is required.")
        params["notes"] = params.get("notes", "")
        headers = {"Authorization": self.headers["Authorization"]}

        # Get the upload url
        resp = self._request(
            method="post",
            url=f"{self.url}/vectra-match/rules/upload/",
            headers=headers,
            json={"file_name": params["file"], "notes": params["notes"]},
        )

        upload_url = resp.json()["urls"][0]
        upload_id = resp.json()["id"]

        # Upload the file to the provided url
        payload = open(f"{params['file']}", "rb")
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

        if "members" in kwargs and "regex" in kwargs:
            raise ValueError("Members cannot be specified when creating a regex group.")
        elif members := kwargs.get("members"):
            regex = None
        elif regex := kwargs.get("regex"):
            members = []
        else:
            members = []
            regex = None

        importance = kwargs.get("importance", "medium")
        description = kwargs.get("description", "")

        if regex is None and (type := kwargs.get("type", "")) not in [
            "host",
            "domain",
            "ip",
            "account",
        ]:
            raise ValueError(
                'parameter type must have value "account", "domain", "ip" or "host"'
            )
        elif (type := kwargs.get("type", "")) not in ["host", "account"]:
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

        if members := kwargs.get("members"):
            if kwargs.get("regex"):
                raise ValueError(
                    "Members cannot be specified when creating a regex group."
                )
            else:
                regex = None
        elif regex := kwargs.get("regex"):
            pass
        else:
            members = group["members"]
            regex = None

        name = kwargs.get("name", group["name"])
        description = kwargs.get("description", group["description"])
        importance = kwargs.get("importance", group["importance"])

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
