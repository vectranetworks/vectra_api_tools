"""
Setup testing environment
"""
import pytest
import requests

from ..modules import platform
from ..modules import vectra

VectraClient = {
    # Vectra Detect client implementations
    "1": vectra.VectraBaseClient,
    "2.1": vectra.VectraClientV2_1,
    "2.2": vectra.VectraClientV2_2,
    "2.4": vectra.VectraClientV2_4,
    "2.5": vectra.VectraClientV2_5,
    # Vectra Platform client implementations
    "3": platform.VectraPlatformClientV3,
    "3.1": platform.VectraPlatformClientV3_1,
    "3.2": platform.VectraPlatformClientV3_2,
    "3.3": platform.VectraPlatformClientV3_3,
    "3.4": platform.VectraPlatformClientV3_4,
}


def pytest_addoption(parser):
    """
    Add Parameters
    """
    parser.addoption("--url", action="store", help="url or ip of vectra brain")
    parser.addoption("--client_id", help="client_id")
    parser.addoption("--secret_key", help="secret_key")
    parser.addoption("--user", help="username")
    parser.addoption("--password", help="password")
    parser.addoption("--token", help="token")
    parser.addoption("--client_ver", help='|'.join(VectraClient.keys()))


@pytest.fixture(scope="module")
def vc(request):
    """
    Create Vectra Client object
    """
    requests.packages.urllib3.disable_warnings()

    client_ver = float(request.config.getoption("--client_ver"))
    if client_ver == 2:
        raise ValueError(f"--client-ver must be one of {', '.join(VectraClient.keys())}")

    if client_ver < 2:
        brain = request.config.getoption("--url")
        username = request.config.getoption("--user")
        passwd = request.config.getoption("--password")

        return vectra.VectraBaseClient(url=brain, user=username, password=passwd)

    if 2 < client_ver < 3:
        version = request.config.getoption("--client_ver")
        brain = request.config.getoption("--url")
        token = request.config.getoption("--token")

        return VectraClient[version](url=brain, token=token)

    if client_ver >= 3:
        version = request.config.getoption("--client_ver")
        brain = request.config.getoption("--url")
        client_id = request.config.getoption("--client_id")
        secret_key = request.config.getoption("--secret_key")

        return VectraClient[version](
            url=brain, client_id=client_id, secret_key=secret_key
        )

    return False
