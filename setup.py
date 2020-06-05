from setuptools import setup

with open('README.md', 'r') as fh:
    long_desc = fh.read()

setup(
    name='vectra-api-tools',
    description='Vectra API client library',
    long_description=long_desc,
    long_description_content_type='text/markdown',
    version='2.0rc1',
    author='Vectra',
    author_email='tme@vectra.ai',
    url='https://github.com/vectranetworks/vectra_api_tools',
    license='Apache 2.0',
    package_dir={
        'vat': 'modules'
    },
    packages=['vat'],
    install_requires=['requests', 'pytz', 'cabby', 'stix'],
    python_requires='>=3.4',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Utilities'
    ]
)
