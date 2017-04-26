The project shows SVA API examples using the Halo Python SDK

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

gitpython and json2html - execute the following commands to get the module:

sudo pip install gitpython  
sudo pup install json2html  

Project Configuration
---------------------

app/sva_scan_examples/config_helper.py stores the configuration for the project.  
  
1) SCAN_RESULTS_DIRECTORY: an environment variable that controls where the scan results are stored.
  The default is /tmp/scan_results/
   
Project Execution
-----------------

In the project root type the following command: python app/runner.py

Sample output:  

$ python app/runner.py
Command status is queued... waiting for next heartbeat...
Command status is queued... waiting for next heartbeat...

Completed scans on host.  To look at the scan results in the portal search for hostname ip-10-10-12-239.  To look at the results in JSON and HTML look at the reports in /tmp/scan_results/  

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
E) Write the results to a JSON file (see sva_scan_results_1493240247.json)  
F) Write the results to an HTML file (see sva_report_1493240247.html)  
G) Get the first findings detail - note this is no different than in the finding
section of the the scan results  
H) Write the results to a JSON file (see sva_finding_results_1493240247.json)    
I) Write the results to an HTML file (see sva_finding_report_1493240247.html)  
J) Get the scan details - for an SVA scan these are the same as the scan results  
K) Write the results to a JSON file (see sva_scan_details_1493240247.json)  
L) Write the results to an HTML file (see sva_details_report_1493240247.html)  


Tests
-----

1) Style

A) pep8 checking - localtion: location: sva_scan_examples/app/test/style/test_style_flake8.py

Checks code for pep8 issues
