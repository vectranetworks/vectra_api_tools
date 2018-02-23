# Vectra API Tools

Vectra API Tools is a lib that is designed  to save time and repetitive work by providing modules that interact with the Vectra API


* __modules__ - this directory contains the modules associated with the vectra-api-tools lib
    * cli.py is a set of common parameters which can be imported into scripts which are designed to be run from the command line
    * stix_taxii.py is a module that provides a taxii client to ingest threat feeds and write to STIX file
    * vectra.py is module that provides methods that simplify interaction with the Vectra API. There are methods to support most activities including hosts, detections, threat feeds, etc. This module is well documented.

* __scripts__ - collection of scripts to interact with the Vectra api. These scripts can also be used as a reference on how to leverage the VAT lib
    * dest_ip.py provides a list of destination IPs sorted by total number of detections or on a per detection basis
    * dest_ports.py provies a list of ports sorted based on number of detections
    * detection_counts.py provides a list of detection types sorted based on count
    * detections.py retrieves, filter, and sort detections from the command line
    * hosts.py retrieves, filters, and sorts detections from the command line
    * key_assets.py (un)sets key assets using hostname, id, or a list provided by the user. The list file requires one hostname per line
    * src_ip.py provides a list of source IPs sorted by total number of detections
    * threat_feed.py provides a programatic way of managing threat feeds via the api.

* __Vectra\_APIv1.postman\_collection__ is a collection of queries for Postman. It has all of the current endpoints and and associated parameters for each endpoint

### Current version
1.0rc1

### Getting started
This library is designed to be imported into your python interpreter. To avoid conflict or risk of impacting your existing python deployment, it is recommended to install this in a [virtual environment](https://virtualenv.pypa.io/en/stable/).

Installation:
```
python setup.py install
```

Importing module:
Vectra API Tools module is named vat. To import, add the following import statement:
```
import vat
```

Scripts can be run with the with the following syntax:
```
python <script>
```

There is help available for each script with the -h or --help flag

### Module: vectra
Create client:
```python
import vat.vectra as vectra

# client for v1 api
vc = vectra.VectraClient(url='https://www.example.com', user='foo', password='bar', verify=False)

# client for v2 api
vc = vectra.VectraClient(url='https://www.example.com', token='auipvauineiqubvadsnqveru', verify=False)
```
> Parameters
>* user: username for basic authentication - will be removed with deprecation of v1 of api
>* password: password for basic authentication - will be removed with deprecation of v1 of api
>* token: api token
>* verify: verify ssl certificates (default: False) - optional

Get hosts:

This method has a page_size limit of 5000 objects and should be used when response does not exceed this limit. If response exceeds 5000 objects, use get_all_hosts(). Use of parameters is recommended
```python
vc.get_host()
```

>All paramters are optional
>* active_traffic: host has active traffic (bool)
>* c_score: certainty score (int) - will be removed with deprecation of v1 of api
>* c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
>* certainty: certainty score (int)
>* certainty_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
>* fields: comma spearated string of fields to be filtered and returned
>* has_active_traffic: host has active traffic (bool)
>* include_detection_summaries: include detection summary in response (bool)
>* is_key_asset: host is key asset (bool)
>* is_targeting_key_asset: host is targeting key asset (bool)
>* key_asset: host is key asset (bool) - will be removed with deprecation of v1 of api
>* last_source: registered ip address of host
>* mac_address: registered mac address of host
>* name: registered name of host
>* ordering: field to use to order response
>* page: page number to return (int)
>* page_size: number of object to return in repsonse (int)
>* state: state of host (active/inactive)
>* t_score: threat score (int) - will be removed with deprecation of v1 of api
>* t_score_gte: threat score greater than or equal to (int) - will be removed with deprection of v1 of api
>* tags: tags assigned to host
>* targets_key_asset: host is targeting key asset (bool)
>* threat: threat score (int)
>* threat_gte: threat score greater than or equal to (int)

Get all hosts:

This method is a generator and should be used when the response exceeds the limit of 5000 objects. When using this method, you must instantiate the generator and then call next(), or iterate over the generator.

```python
host_generator = vc.get_all_hosts()
next(host_generator)
or
for page in host_generator:
    print page
```

> Parameters used with get_detections() can be used and are optional

Get host by id:
```python
vc.get_host_by_id(host_id=1)
```

> Parameters
>* host_id: host id - required
>* fields: comma separated string of fields to be filtered and returned - optional

Set host as key asset:
```python
vc.set_key_asset(host_id=1)
```

> Parameters
>* id: id of host needing to be set - required
>* set: set flag to False if unsetting host as key asset (bool)

Get detections:

This method has a page_size limit of 5000 objects and should be used when response does not exceed this limit. If response exceeds 5000 objects, use get_all_detections(). Use of parameters is recommended.
```python
vc.get_detections()
```

> All parameters are optional
>* c_score: certainty score (int) - will be removed with deprecation of v1 of api
>* c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
>* category: detection category - will be removed with deprecation of v1 of api
>* certainty: certainty score (int)
>* certainty_gte: certainty score greater than or equal to (int)
>* detection:
>* detection_type: detection type
>* detection_category: detection category
>* fields: comma separated string of fields to be filtered and returned
>* host_id: detection id (int)
>* is_targeting_key_asset: detection is targeting key asset (bool)
>* is_triaged: detection is triaged
>* ordering: field used to sort response
>* src_ip: source ip address of host attributed to detection
>* state: state of detection (active/inactive)
>* t_score: threat score (int) - will be removed with deprecation of v1 of api
>* t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
>* tags: tags assigned to detection
>* targets_key_asset: detection targets key asset (bool) - will be removed with deprecation of v1 of api
>* threat: threat score (int)
>* threat_gte threat score is greater than or equal to (int)

Get all detections:

This method is a generator and should be used when the response exceeds the limit of 5000 objects. When using this method, you must instantiate the generator and then call next, or iterate over the generator.

```python
detection_generator = vc.get_all_detections()
next(detection_generator)
or
for page in detection_generator:
    print page
```

> Parameters used with get_detections() can be used and are optional

Get detections by id:
```python
vc.get_detections_by_id(detection_id=1)
```

> Parameters
>* det_id: detection id - required
>* fields: comma separated string of fields to be filtered and returned

Create threat feed:
```python
vc.create_feed(name='sample', category='exfil', certainty='Medium', itype='Exfiltration', duration=14)
```

> Parameters
>* name: name of threat feed
>* category: category that detection will register. supported values are lateral, exfil, and cnc
>* certainty: certainty applied to detection. Supported values are Low, Medium, High
>* itype: indicator type - supported values are Anonymize, Exfiltration, Malware Artifacts, and Watchlist
>* duration: days that the threat feed will be applied
>* **_Values for category, itype, and certainty are case sensitive_**

Delete threat feed:
```python
vc.delete_feed(feed_id=1)
```

> Parameters
>* feed_id: id of threat feed (returned by get_feed_by_name())

List threat feeds:
```python
vc.get_feeds()
```

> No parameters

Get threat feed by name:
```python
vc.get_feed_by_name(name='sample')
```

> Parameters
>* name: name of threat feed

Post stix file:
```python
vc.post_stix_file(feed_id=1, stix_file='stix.xml')
```

> Parameters
>* feed_id: id of threat feed (returned by get_feed_by_name())
>* stix_file: stix filename

Access custom endpoint:
```python
vc.custom_endpoint(path='/health')
```

> Parameters
>* path: path of the api endpoint