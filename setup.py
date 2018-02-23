from setuptools import setup

setup(
    name='vectra-api-tools',
    version='1.0rc1',
    author='Vectra',
    author_email='cjohnson@vectra.ai',
    package_dir={
        'vat': 'modules'
    },
    packages=['vat'],
    install_requires=['requests', 'pytz', 'cabby', 'stix']
)
