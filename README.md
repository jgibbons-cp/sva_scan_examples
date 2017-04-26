The project shows an SVA API example using the Halo Python SDK

API Setup
---------

A) Install the CloudPassage SDK
1) Type: pip install cloudpassage

2) Configure the SDK
1) Type: sudo vi /etc/cloudpassage.yaml

defaults:  
  key_id: <key>  
  secret_key: <secret>  
  api_hostname: api.cloudpassage.com  
  api_port: 443  

or

export HALO_API_KEY=<key>  
export HALO_API_SECRET_KEY=<secret>  
export HALO_API_HOSTNAME=api.cloudpassage.com

Dependencies
------------

gitpython - execute the following command to get the module:

sudo pip install gitpython  


Project Configuration
---------------------

app/sva_scan_examples/config_helper.py stores the configuration for the project.

Project Execution
-----------------

In the project root type the following command: python app/runner.py

Project Classes
---------------

1) ConfigHelper - location: app/sva_scan_examples/config_helper.py

This is the project configuration as noted above in section "Project Configuration"

2) SVA_ScanExamples - location: app/sva_scan_examples/sva_scan_examples.py

This includes Halo SVA scan examples.

A) Get a server IP  
B) Get the Halo ID  
C) Do a scan  
D) Get the results  
E) Print them (see sample_json.json)


Tests
-----

1) Unit


2) Style

A) pep8 checking - localtion: location: sva_scan_examples/app/test/style/test_style_flake8.py

Checks code for pep8 issues
