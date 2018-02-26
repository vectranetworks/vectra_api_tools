import pytest
import vat.vectra as vectra

def pytest_addoption(parser):
    parser.addoption('--url', action='store', help='url or ip of vectra brain')
    parser.addoption('--user', help='username')
    parser.addoption('--password', help='password')
    parser.addoption('--token', help='token')

@pytest.fixture
def vc_v1(request):
    brain = request.config.getoption('--url')
    username = request.config.getoption('--user')
    passwd = request.config.getoption('--password')
    return vectra.VectraClient(url=brain, user=username, password=passwd)

@pytest.fixture
def vc_v2(request):
    brain = request.config.getoption('--url')
    token = request.config.getoption('--token')
    return vectra.VectraClient(url=brain, token=token)