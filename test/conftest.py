import pytest

import vat.platform as platform
import vat.vectra as vectra


def pytest_addoption(parser):
    parser.addoption("--url", action="store", help="url or ip of vectra brain")
    parser.addoption("--client_id", help="client_id")
    parser.addoption("--secret_key", help="secret_key")
    parser.addoption("--user", help="username")
    parser.addoption("--password", help="password")
    parser.addoption("--token", help="token")
    parser.addoption("--client_ver", help="1, 2.1, 2.2, 2.4, 2.5, 3, 3.1, 3.2, 3.3")


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
}


@pytest.fixture(scope="module")
def vc(request):
    if float(request.config.getoption("--client_ver")) < 2:
        brain = request.config.getoption("--url")
        username = request.config.getoption("--user")
        passwd = request.config.getoption("--password")

        return vectra.VectraBaseClient(url=brain, user=username, password=passwd)

    elif 2 < float(request.config.getoption("--client_ver")) < 3:
        version = request.config.getoption("--client_ver")
        brain = request.config.getoption("--url")
        token = request.config.getoption("--token")

        return VectraClient[version](url=brain, token=token)

    elif float(request.config.getoption("--client_ver")) >= 3:
        version = request.config.getoption("--client_ver")
        brain = request.config.getoption("--url")
        client_id = request.config.getoption("--client_id")
        secret_key = request.config.getoption("--secret_key")

        return VectraClient[version](
            url=brain, client_id=client_id, secret_key=secret_key
        )

    else:
        return False
