from setuptools import setup

long_desc="""
_Vectra API Tools_ is set of resources that is designed to save time and repetitive work by providing a python library that simplifies interaction with the Vectra API. Current modules available:  
    - _cli.py_ is a set of common parameters which can be imported into scripts which are designed to be run from the command line
    - _stix_taxii.py_ is a module that provides a taxii client to ingest threat feeds and write to STIX file
    - _vectra.py_ is module that provides methods that simplify interaction with the Vectra API. There are methods to support most entities including hosts, detections, and advance search.
"""

setup(
    name='vectra-api-tools',
    description='Vectra API client library',
    long_description=long_desc,
    version='1.0rc6',
    author='Vectra',
    author_email='tme@vectra.ai',
    url='https://github.com/vectranetworks/vectra_api_tools',
    license='Apache 2.0',
    package_dir={
        'vat': 'modules'
    },
    packages=['vat'],
    install_requires=['requests', 'pytz', 'cabby', 'stix'],
    python_requires='>=2.6, !=3.0.*, !=3.1.*, !=3.2.*, <4',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Topic :: Utilities'
    ]
)
