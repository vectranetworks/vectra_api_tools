from setuptools import setup

setup(
    name='vectra-api-tools',
    version='1.0rc4',
    author='Vectra',
    author_email='cjohnson@vectra.ai',
    url='https://github.com/vectranetworks/vectra_api_tools',
    license='Apache 2.0',
    package_dir={
        'vat': 'modules'
    },
    packages=['vat'],
    install_requires=['requests', 'pytz', 'cabby', 'stix']
)
