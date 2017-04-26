import calendar
import os
import stat
import sys
import json
from json2html import *
import time


class SVA_ScanExamples(object):
    """
       This class shows an SVA scan example.
    """
    def __init__(self, halo):
        self.halo = halo
        self.configure_scan_results_diretory()

        # get a scan object
        self.halo_scan_obj = self.halo.get_scan_obj()

        # run the examples
        self.halo_sva_scan_examples()

    def halo_sva_scan_examples(self):

        # get the IP of a server to scan
        server_ip = self.get_a_server_ip(self.halo)

        # can't do magic
        if server_ip == 0:
            print "No server to use... exiting...\n"
            sys.exit(1)

        # get Halo server ID
        server_id = self.get_server_id(self.halo, server_ip)

        # scan for vulnerabilities
        scan_results = self.scan_server(server_id)

        # to individualize the resulting files
        secs_since_cur_epoch = self.get_secs_since_cur_epoch()

        # write result json to file
        file_name = "sva_scan_results"
        self.write_json_to_file(scan_results, file_name, secs_since_cur_epoch)

        # write HTML report of scan
        file_name = "sva_report"
        self.write_scan_report(scan_results, file_name, secs_since_cur_epoch)

        # same for finding - this lists the first one.  This simply pulls it
        # out and reports it alone
        finding_detail = self.get_scan_finding(scan_results)

        file_name = "sva_finding_results"
        self.write_json_to_file(finding_detail, file_name, secs_since_cur_epoch)

        file_name = "sva_finding_report"
        self.write_scan_report(finding_detail, file_name, secs_since_cur_epoch)

        # scan details - for SVA they is no extra information
        scan_details = self.get_scan_details(scan_results)

        file_name = "sva_scan_details"
        self.write_json_to_file(scan_details, file_name, secs_since_cur_epoch)

        file_name = "sva_details_report"
        self.write_scan_report(scan_details, file_name, secs_since_cur_epoch)

    ###
    #
    #   Create a directory to store the scan results if it does not exist
    #   parameters:
    #       cls (class) - the class
    #
    ###

    @classmethod
    def configure_scan_results_diretory(cls):
        scan_results_dir = os.getenv("SCAN_RESULTS_DIRECTORY")

        if os.path.exists(scan_results_dir) is False:
            os.mkdir(scan_results_dir)
            os.chmod(scan_results_dir, stat.S_IRWXU)

    ###
    #
    #   Get the IP of a server
    #   parameters:
    #       cls (class) - the class
    #       halo (object) - the object to access the wrapper class
    #
    #   return:
    #       server_ip (str)
    ###

    @classmethod
    def get_a_server_ip(cls, halo):
        FIRST = 0
        SERVER_IP = "connecting_ip_address"

        # get a halo server object and list all servers
        halo_server_obj = halo.get_server_obj()
        servers = halo_server_obj.list_all()

        # if there are servers in the account get the IP of of the first
        if len(servers) == 0:
            server_ip = 0
        else:
            server_ip = servers[FIRST][SERVER_IP]

        return server_ip

    ###
    #
    #   Get the Halo ID of a server
    #   parameters:
    #       cls (class) - the class
    #       halo (object) - the object to access the wrapper class
    #       server_ip (str)
    #
    #   return:
    #       server_id (str)
    ###

    @classmethod
    def get_server_id(cls, halo, server_ip):
        http_helper_obj = halo.get_http_helper_obj()
        server_id = halo.get_server_id_for_ip(http_helper_obj, server_ip)

        return server_id

    ###
    #
    #   Scan the server

    #   parameters:
    #       self (object)
    #       server_id (str)
    #
    #   return:
    #       scan_results (dict)
    ###

    def scan_server(self, server_id):
        scan_type = "sva"

        response = self.halo.scan_server(self.halo_scan_obj, server_id, scan_type)

        self.halo.process_api_request(server_id, response)

        scan_results = self.halo.get_last_scan_results(self.halo_scan_obj,
                                                       server_id, scan_type)

        return scan_results

    ###
    #
    #   Get seconds since current epoch
    #
    #   return secs_since_cur_epoch (str)
    #
    ###

    @classmethod
    def get_secs_since_cur_epoch(cls):
        cur_epoch = time.gmtime()
        secs_since_cur_epoch = calendar.timegm(cur_epoch)
        secs_since_cur_epoch = str(secs_since_cur_epoch)

        return secs_since_cur_epoch

    ###
    #
    #   Write the scan results JSON to a file
    #   paramaters:
    #       cls (class)
    #       json_data (dict) - scan results
    #       file_name (str) - name for reports
    #       secs_since_cur_epoch (str) - file uniqueness
    #
    ###

    @classmethod
    def write_json_to_file(cls, json_data, file_name, secs_since_cur_epoch):
        indention = 4

        file_path = os.getenv("SCAN_RESULTS_DIRECTORY")

        file = "%s%s_%s.json" % (file_path, file_name,
                                 secs_since_cur_epoch)
        mode = "w"

        with open(file, mode) as json_file:
            json.dump(json_data, json_file, indent=indention)

    ###
    #
    #   Convert the scan results JSON to HTML and write to a file
    #   paramaters:
    #       cls (class)
    #       json_data (dict) - scan results
    #       file_name (str) - name for reports
    #       secs_since_cur_epoch (str) - file uniqueness
    #
    ###

    @classmethod
    def write_scan_report(cls, json_data, file_name, secs_since_cur_epoch):
        file_path = os.getenv("SCAN_RESULTS_DIRECTORY")

        scan_data_html = json2html.convert(json=json_data)

        scan_report = "%s%s_%s.html" % (file_path, file_name,
                                        secs_since_cur_epoch)

        sva_report_handle = open(scan_report, "w")
        sva_report_handle.write(scan_data_html)
        sva_report_handle.close()

    ###
    #
    #   Get the first scan finding
    #   paramaters:
    #       self (object)
    #       scan_results (dict) - scan results
    #
    #   return
    #       finding_detail (dict)
    #
    ###

    def get_scan_finding(self, scan_results):
        SCAN = "scan"
        ID = "id"
        FINDINGS = "findings"
        INDEX = 0

        finding_detail = \
            self.halo.get_scan_findings(
                self.halo_scan_obj,
                scan_results[SCAN][ID],
                scan_results[SCAN][FINDINGS][INDEX][ID])

        return finding_detail

    ###
    #
    #   Get the scan details
    #   paramaters:
    #       self (object)
    #       scan_results (dict) - scan results
    #
    #   return
    #       scan_details (dict)
    #
    ###

    def get_scan_details(self, scan_results):
        SCAN = "scan"
        ID = "id"

        scan_details = self.halo.get_scan_details(self.halo_scan_obj,
                                                  scan_results[SCAN][ID])

        return scan_details

