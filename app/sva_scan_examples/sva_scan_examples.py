import sys
import json


class SVA_ScanExamples(object):
    """
       This class shows an SVA scan example.
    """
    def __init__(self, halo):
        self.halo = halo

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

        # print them out
        self.json_pretty_print(scan_results)

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

        halo_scan_obj = self.halo.get_scan_obj()
        response = self.halo.scan_server(halo_scan_obj, server_id, scan_type)

        self.halo.process_api_request(server_id, response)

        scan_results = self.halo.get_last_scan_results(halo_scan_obj,
                                                       server_id, scan_type)

        return scan_results

    ###
    #
    #   Print results
    #   parameters:
    #       cls (class) - the class
    #       scan_results (dict)
    #
    ###

    @classmethod
    def json_pretty_print(cls, scan_results):
        indention_len = 4

        json_data = json.dumps(scan_results, indent=indention_len,
                               sort_keys=True)
        print json_data
