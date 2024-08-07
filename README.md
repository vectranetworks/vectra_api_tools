### Introduction
_Vectra API Tools_ is set of resources that is designed to save time and repetitive work by providing a python library that simplifies interaction with the Vectra API, scripts that can be run from the command-line, and additional resources that can help with the Vectra API. It was built to be a project to allow not only Vectra, but the Vectra community to contribute to the success of its customers.

The current repository is broken down into the following:
* _modules_ - this directory contains the modules associated with the VAT library
* _scripts_ - collection of scripts to interact with the Vectra api. These scripts can be used as-is or as a reference on how to leverage the VAT library
* _test_ - collection of tests that can be used to validate the VAT library

**Wiki**  
https://github.com/vectranetworks/vectra_api_tools/wiki

**Current versions**  
2.5
3.3

**License**  
Apache 2

**Installation**  
pip install from pypi:  
```
pip install vectra_api_tools
```
pip install from github:
```
pip install git+https://github.com/vectranetworks/vectra_api_tools.git
```
source:
```
python setup.py install
```

**Instantiation**
* For v2
```
from vat.vectra import ClientV2_latest
vectra_client = ClientV2_latest(url="",token="")
```
* For v3
```
from vat.platform import ClientV3_latest
vectra_client = ClientV3_latest(url="",client_id="",secret_key="")
```
