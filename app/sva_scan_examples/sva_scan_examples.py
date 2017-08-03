import calendar
import datetime
import json
from json2html import * # NOQA
import os
import stat
import sys
import time
import urllib
import urllib2
from get_alas_links import GetAlasLinks


class SVA_ScanExamples(object):
    """
       This class shows an SVA scan example.
    """
    def __init__(self, halo):
        NO_SERVERS = 0

        self.halo = halo
        self.configure_scan_results_directory()
        self.file_path = os.getenv("SCAN_RESULTS_DIRECTORY")

        # get a server object
        self.halo_server_obj = self.halo.get_server_obj()

        # get a scan object
        self.halo_scan_obj = self.halo.get_scan_obj()

        servers = self.halo.list_all_servers(self.halo_server_obj)

        if len(servers) == NO_SERVERS:
            print "No server to use... exiting...\n"
            sys.exit(1)

        secs_since_cur_epoch = self.get_secs_since_cur_epoch()

        for server in servers:
            # run the examples
            server_ip = server["connecting_ip_address"]

            unit_tests = os.getenv("UNIT_TESTS")

            if unit_tests == "no_unit_tests":
                self.halo_sva_scan_examples(server_ip, secs_since_cur_epoch)

    def halo_sva_scan_examples(self, server_ip, secs_since_cur_epoch):
        SCAN = "scan"
        ID = "id"
        TRUE = "True"

        # get Halo server ID
        server_id = self.get_server_id(self.halo, server_ip)

        # execute scan examples as well as Qualys comparative report
        scan_examples = os.getenv("SCAN_EXAMPLES")

        if scan_examples == TRUE and server_id is not None:
            # scan the server
            scan_results = self.scan_server(server_id)

            # write result json to file
            file_name = "sva_scan_results"
            self.write_json_to_file(scan_results, file_name,
                                    secs_since_cur_epoch)

            # write HTML report of scan
            file_name = "sva_report"
            self.write_scan_report(scan_results, file_name,
                                   secs_since_cur_epoch)

            # same for finding - this lists the first one.  This simply pulls
            # it out and reports it alone
            finding_detail = self.get_scan_finding(scan_results)

            file_name = "sva_finding_results"
            self.write_json_to_file(finding_detail, file_name,
                                    secs_since_cur_epoch)

            file_name = "sva_finding_report"
            self.write_scan_report(finding_detail, file_name,
                                   secs_since_cur_epoch)

            # scan details - for SVA there is no extra information
            scan_id = scan_results[SCAN][ID]

            scan_details = self.get_scan_details(scan_id)

            file_name = "sva_scan_details"
            self.write_json_to_file(scan_details, file_name,
                                    secs_since_cur_epoch)

            file_name = "sva_details_report"
            self.write_scan_report(scan_details, file_name,
                                   secs_since_cur_epoch)

        if server_id is not None:
            module = "svm"

            # use scan results from x days ago
            days_ago = os.getenv("DAYS_FOR_SCAN_AGE")
            days_ago = int(days_ago)

            scan_ids = \
                self.halo.get_last_scan_before_date(self.halo_scan_obj,
                                                    server_id, module,
                                                    days_ago)

            NO_SCAN_IDS = 0
            NONE = 0
            FIRST = 0
            SCAN = "scan"

            # if there is a historical scan use it else scan.
            # if there are issues create a report
            if len(scan_ids) == NO_SCAN_IDS and scan_examples == "False":
                # scan the server
                scan_results = self.scan_server(server_id)
                scan_id = scan_results[SCAN][ID]
            else:
                scan_ids = \
                    self.halo.get_last_scan_before_date(
                        self.halo_scan_obj, server_id, module, days_ago)
                scan_id = scan_ids[FIRST][ID]

            scan_details = self.get_scan_details(scan_id)
            critical_finds_count = scan_details["critical_findings_count"]
            non_critical_finds_count = \
                scan_details["non_critical_findings_count"]

            if critical_finds_count != NONE or \
                    non_critical_finds_count != NONE:
                self.write_qualys_comparison_report(
                    scan_details, server_id, secs_since_cur_epoch)

    ###
    #
    #   Create a directory to store the scan results if it does not exist
    #   parameters:
    #       self (object)
    #
    ###

    def configure_scan_results_directory(self):
        scan_results_dir = os.getenv("SCAN_RESULTS_DIRECTORY")

        if os.path.exists(scan_results_dir) is False:
            os.mkdir(scan_results_dir)
            os.chmod(scan_results_dir, stat.S_IRWXU)

    ###
    #
    #   Get the Halo ID of a server
    #   parameters:
    #       self (object)
    #       halo (object) - the object to access the wrapper class
    #       server_ip (str)
    #
    #   return:
    #       server_id (str)
    ###

    def get_server_id(self, halo, server_ip):
        http_helper_obj = halo.get_http_helper_obj()
        server_id = halo.get_server_id_for_ip(http_helper_obj, server_ip)

        return server_id

    ###
    #
    #   Scan the server
    #
    #   parameters:
    #       self (object)
    #       server_id (str)
    #
    #   return:
    #       scan_results (dict)
    ###

    def scan_server(self, server_id):
        scan_results = []
        scan_type = "sva"

        response = self.halo.scan_server(self.halo_scan_obj, server_id,
                                         scan_type)

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

    def write_json_to_file(self, json_data, file_name, secs_since_cur_epoch):
        indention = 4

        file = "%s%s_%s.json" % (self.file_path, file_name,
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

        scan_data_html = json2html.convert(json=json_data) # NOQA

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
        finding_detail = []
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

    def get_scan_details(self, scan_id):
        scan_details = []

        scan_details = self.halo.get_scan_details(self.halo_scan_obj,
                                                  scan_id)

        return scan_details

    ###
    #
    #   Create a csv sva report using Halo, ALAS and RHEL data
    #
    #   paramaters:
    #       self (object)
    #       scan_details (dict) - details of last scan
    #       server_id (str) - server ID
    #       secs_since_cur_epoch (str) - timestamp for filename uniqueness
    #
    ###

    def write_qualys_comparison_report(self, scan_details, server_id,
                                       secs_since_cur_epoch):
        server_data = \
            self.halo.describe_server(self.halo_server_obj, server_id)

        server_ip = server_data["connecting_ip_address"]
        hostname = scan_details["server_hostname"]
        print "Creating a report for IP: %s hostname: %s." % (server_ip,
                                                              hostname)

        # report start time
        start = datetime.datetime.now()

        halo_http_helper_obj = self.halo.get_http_helper_obj()

        # get the OS information
        operating_system = "%s %s %s %s" % (server_data["platform"].title(),
                                            server_data["platform_version"],
                                            server_data["kernel_name"],
                                            server_data["os_version"])

        try:
            # get the AWS instance ID
            instance_id = server_data["aws_ec2"]["ec2_instance_id"]
        except KeyError:
            instance_id = "Not AWS"

        # server state (active, retired etc.)
        server_state = server_data["state"]

        # this will be when the agent was last started
        last_state_change = server_data["last_state_change"]

        time_of_last_heartbeat = self.get_last_hearbeat_time(server_data)

        header = "IP, DNS Name or NETBios, OS, Instance ID, Instance Status" \
                 ", Last State Change, Last Time Agent Checked In"

        report_data = "%s, %s, %s, %s, %s, %s, %s," \
                      % (server_ip, hostname, operating_system, instance_id,
                         server_state, last_state_change,
                         time_of_last_heartbeat)

        scan_findings = scan_details["findings"]

        # get the high, medium and low cve's by year
        cve_ranges_by_year = \
            self.create_yearly_cve_range_table(scan_findings)

        header = "%s, CVE Ranges by Year" % header

        counter = 0
        INCREMENT = 1
        max = len(cve_ranges_by_year)

        while counter < max:
            cve_ranges = "Year: %s Low: %s Medium %s High: %s" \
                         % (cve_ranges_by_year[counter]["year"],
                            cve_ranges_by_year[counter]["low"],
                            cve_ranges_by_year[counter]["medium"],
                            cve_ranges_by_year[counter]["high"])

            report_data = "%s %s" \
                          % (report_data, cve_ranges)
            counter = counter + INCREMENT

        counter = 0
        paramaters_init = False
        data_init = False
        finding_status = "bad"

        for finding in scan_findings:
            if finding["status"] == finding_status:

                # formatting for cve part of the report
                if data_init is True:
                    report_data = ",,,,,,,"

                # the Halo vulnerability ID, package name and version for CVE
                vulnerability_id =\
                    scan_details["findings"][counter]["id"]
                package_name = \
                    scan_details["findings"][counter]["package_name"]
                package_version = \
                    scan_details["findings"][counter]["package_version"]

                header = "%s, Vulnerability ID, Vulnerability Title, Port" \
                         % header
                report_data = "%s, %s, Package: %s version: %s, N/A " \
                              "- based on package" \
                              % (report_data, vulnerability_id, package_name,
                                 package_version)

                cve_entries = finding["cve_entries"]

                data_init = True

                for cve_entry in cve_entries:

                    # the CVE ID
                    cve_id = cve_entry["cve_entry"]

                    header = "%s, CVE ID" \
                             % header
                    report_data = "%s, %s" % (report_data, cve_id)

                    # the CVSS v2 base score
                    cvss2_base_score = cve_entry["cvss_score"]

                    cve_details = \
                        self.halo.get_cve_details(halo_http_helper_obj,
                                                  cve_id)

                    # Vulnerability type - access vector and complexity,
                    # authentication
                    header = "%s, Vulnerability Type" % header
                    access_vector = \
                        cve_details["CVSS Metrics"]["access_vector"]

                    access_vector = access_vector.capitalize()
                    access_complexity = \
                        cve_details["CVSS Metrics"]["access_complexity"]
                    access_complexity = access_complexity.capitalize()
                    authentication = \
                        cve_details["CVSS Metrics"]["authentication"]
                    authentication = authentication.capitalize()

                    report_data = "%s, %s vulnerability with %s access " \
                                  "complexity requiring athentication level" \
                                  " %s" \
                                  % (report_data, access_vector,
                                     access_complexity, authentication)

                    header = "%s, Vulnerability Severity" % header

                    cp_critical = finding["critical"]

                    if cp_critical is True:
                        cp_critical = "is"
                    else:
                        cp_critical = "is not"

                    separator = '-'
                    index = 1
                    cve_year = cve_id.split(separator)[index].strip()
                    cve_qualitative_severity_ranking = \
                        self.get_cve_qualitative_severity_ranking(
                            cvss2_base_score)

                    vendor_references = cve_details["References"]

                    # whether something is critical or not is based on a Halo
                    # setting (default > 5.0) so this notes it and also
                    # provides the severity by PCI guidelines
                    report_data = "%s, Based on the Halo account settings " \
                                  "the vulnerability %s critical.  It is a " \
                                  "CVE from %s and its qualitative severity" \
                                  " ranking (based on PCI guidelines) is %s" \
                                  % (report_data, cp_critical, cve_year,
                                     cve_qualitative_severity_ranking)

                    header = "%s, Vendor References" % header

                    consolidated = ""
                    bugtraq_id = ""
                    securityfocus = "securityfocus"
                    bid = "/bid/"

                    # get the bugtraq IDs if they exist
                    for vendor_reference in vendor_references:

                        consolidated = "%s %s" % (consolidated,
                                                  vendor_reference)
                        if securityfocus in vendor_reference and bid in \
                                vendor_reference:
                            bugtraq_id = "%s %s" % (bugtraq_id,
                                                    vendor_reference)

                    COMMA = ","
                    NOTHING = ""
                    consolidated = consolidated.replace(COMMA, NOTHING)
                    report_data = "%s, %s" % (report_data,
                                              consolidated)
                    header = "%s, Bugtraq ID" % header

                    report_data = "%s, %s" % (report_data,
                                              bugtraq_id)

                    header = "%s, CVSS2 Base, CVSS2 Temporal, CVSS3 Base," \
                             "CVSS3 Temporal" % header

                    report_data = "%s, %s, RFE, RFE, RFE" % \
                                  (report_data, cvss2_base_score)

                    header = "%s, Threat" % header

                    report_data = "%s, %s vulnerability with %s access " \
                                  "complexity requiring athentication level" \
                                  " %s" \
                                  % (report_data, access_vector,
                                     access_complexity, authentication)

                    header = "%s, Impact" % header

                    availability_impact = \
                        cve_details["CVSS Metrics"]["availability_impact"]
                    availability_impact = availability_impact.capitalize()

                    confidentiality_impact = \
                        cve_details["CVSS Metrics"]["confidentiality_impact"]
                    confidentiality_impact = \
                        confidentiality_impact.capitalize()

                    integrity_impact = \
                        cve_details["CVSS Metrics"]["integrity_impact"]
                    integrity_impact = integrity_impact.capitalize()

                    NEWLINE = "\n"

                    # cve summary
                    cve_summary = cve_details["summary"]
                    cve_summary = cve_summary.replace(COMMA, NOTHING)
                    cve_summary = cve_summary.replace(NEWLINE, NOTHING)

                    report_data = "%s, The availability impact is %s. The " \
                                  "confidentiality impact is %s. The " \
                                  "integrity impact is %s" \
                                  % (report_data, availability_impact,
                                     confidentiality_impact, integrity_impact)

                    header = "%s, Vulnerable packages" % header

                    report_data = "%s, Patch vulnerable package %s: " \
                                  "%s. Refer to references %s" \
                                  % (report_data, package_name, cve_summary,
                                     consolidated)

                    alas_links = ""
                    amazon = "Amazon"
                    linux = "Linux"
                    alas_feed = "/tmp/alas.rss"

                    if amazon in operating_system and \
                            linux in operating_system:
                        self.download_alas_rss(alas_feed)
                        alas_ob = GetAlasLinks()
                        alas_links = alas_ob.run(alas_feed, cve_id)
                    else:
                        alas_links = "N/A"

                    header = "%s, ALAS Link" % header

                    report_data = "%s, %s" \
                                  % (report_data, alas_links)

                    # get RHEL CVE data from
                    # https://access.redhat.com/labs/securitydataapi
                    header = "%s, RHEL CVE Data" % header

                    if "Redhat" in operating_system:
                        rhel_data = self.get_rhel_cve_data(cve_id)

                        # get the RHEL bugzilla description and strip newlines
                        bugzilla_description = \
                            rhel_data["bugzilla"]["description"]
                        bugzilla_description = \
                            bugzilla_description.replace(NEWLINE, NOTHING)

                        # get the RHEL bugzilla ID and URL
                        bugzilla_id = rhel_data["bugzilla"]["id"]
                        bugzilla_url = rhel_data["bugzilla"]["url"]

                        # RHEL details stripping out comma's and newlines
                        details = ""
                        for detail in details:
                            details = "%s %s" % (details, detail)
                        details = details.replace(COMMA, NOTHING)
                        details = details.replace(NEWLINE, NOTHING)

                        if details == NOTHING:
                            details = "N/A"

                        # get the RHEL statement (if exists) stripping comma's
                        # and newlines
                        try:
                            statement = rhel_data["statement"]
                            statement = statement.replace(NEWLINE, NOTHING)
                            statement = statement.replace(",", NOTHING)
                        except KeyError:
                            statement = "N/A"

                        # get the affected releases data
                        affected_releases = ""
                        product_name = ""
                        for release in rhel_data["affected_release"]:
                            # get product name if it exists
                            try:
                                product_name = "%s %s" % \
                                               (product_name,
                                                release["product_name"])
                            except TypeError:
                                for release in release["product_name"]:
                                    product_name = "%s %s" % (product_name,
                                                              release)

                            release_date = release["release_date"]
                            advisory = release["advisory"]
                            package = release["package"]
                            cpe = release["cpe"]

                            affected_releases = "%s Product name: %s Release "\
                                                "date: %s Advisory: %s " \
                                                "Package: %s CPE: %s" \
                                                % (affected_releases,
                                                   product_name, release_date,
                                                   advisory, package, cpe)

                        affected_releases = affected_releases.replace(COMMA,
                                                                      NOTHING)

                        # get RHEL package state data (if exists)
                        try:
                            package_state = ""
                            for state in rhel_data["package_state"]:
                                try:
                                    product_name = state["product_name"]
                                    fix_state = state["fix_state"]
                                    package_name = state["package_name"]
                                    cpe = state["cpe"]
                                except TypeError:
                                    product_name = "N/A"
                                    fix_state = "N/A"
                                    package_name = "N/A"
                                    cpe = "N/A"

                                package_state = "%s Product name: %s Fix " \
                                                "state: %s Package name: " \
                                                "%s CPE: %s" \
                                                % (package_state,
                                                   product_name, fix_state,
                                                   package_name, cpe)
                                package_state = package_state.replace(COMMA,
                                                                      NOTHING)
                        except KeyError:
                            package_state = "N/A"

                        report_data = "%s, Threat severity is %s | Public " \
                                      "date %s | Bugzilla description %s " \
                                      "Bugzilla ID %s Bugzilla URL %s | CVSS" \
                                      " v3 base score of %s with a %s " \
                                      "status | Details: %s | Statement: " \
                                      "%s | Affected releases: %s | Package " \
                                      "State: %s" \
                                      % (report_data,
                                         rhel_data["threat_severity"],
                                         rhel_data["public_date"],
                                         bugzilla_description, bugzilla_id,
                                         bugzilla_url,
                                         rhel_data["cvss3"]["cvss3_base_score"], # NOQA
                                         rhel_data["cvss3"]["status"],
                                         details, statement,
                                         affected_releases, package_state)
                    else:
                        report_data = "%s," % report_data

                    # get the exploitability data
                    header = "%s, Exploitability" % header

                    report_data = "%s, %s vulnerability with %s access " \
                                  "complexity requiring athentication level" \
                                  " %s" \
                                  % (report_data, access_vector,
                                     access_complexity, authentication)

                    # we don't provide this - related to website attacks
                    header = "%s, Associated Malware" % header

                    report_data = "%s, N/A" % report_data

                    # PCI severity and compliance status 0-3.9 low, 4-6.9
                    # medium and 7-10 is high.  4 and above is a fail
                    header = "%s, PCI Severity and Compliance Status" % header

                    pci_compliance_status = \
                        self.get_pci_compliance_status(
                            cve_qualitative_severity_ranking)

                    report_data = "%s, %s %s," % \
                                  (report_data,
                                   cve_qualitative_severity_ranking,
                                   pci_compliance_status)

                    # OS CPE's
                    header = "%s, OS CPE(s)" % header

                    os_cpes = cve_details["Vulnerable packages"]

                    for os_cpe in os_cpes:
                        report_data = "%s %s" % (report_data, os_cpe)

                    header = "%s, Vulnerability Category" % header

                    report_data = "%s, %s" % (report_data, access_vector)

                    # everything we show in Linux is patchable
                    header = "%s, Patchable\n" % header

                    patchable = self.get_patchable_status(operating_system)

                    report_data = "%s, %s" % (report_data, patchable)

                    # open file and write header if needed
                    if paramaters_init is False:
                        mode = "a"
                        file_name = "%shalo_sva_report_%s.csv" % \
                                    (self.file_path, secs_since_cur_epoch)
                        file_object = open(file_name, mode)
                        file_object.write(header)
                        paramaters_init = True

                    # write data
                    report_data = "%s\n" % report_data
                    file_object.write(report_data)
                    report_data = ",,,,,,,,,,"

                # cycle through the findings
                counter = counter + INCREMENT

        # time to run report
        finish = datetime.datetime.now()
        total_time = finish - start
        print "Report completed in %s" % total_time

    ###
    #   the time of the agent's last heartbeat
    #
    #   parameters:
    #      self (obj)
    #       server_data (dict) - data about workload
    #
    #   return:
    #      time_of_last_heartbeat (str)
    #
    ###

    def get_last_hearbeat_time(self, server_data):
        HEARTBEAT_FREQUENCY = 60

        now = time.time()

        last_state_change = server_data["last_state_change"]
        last_state_change = time.strptime(last_state_change,
                                          '%Y-%m-%dT%H:%M:%S.%fZ')
        last_state_change = time.mktime(last_state_change)

        diff = now - last_state_change

        seconds_since_last_heartbeat = diff % HEARTBEAT_FREQUENCY

        time_of_last_heartbeat = now - seconds_since_last_heartbeat

        time_of_last_heartbeat = \
            time.strftime('%Y-%m-%dT%H:%M:%S.%fZ',
                          time.gmtime(time_of_last_heartbeat))

        return time_of_last_heartbeat

    ###
    #
    #   Get the low, medium, or high PCI ranking for the CVE
    #
    #   Parameters:
    #       self (obj)
    #       cvss2_base (float) - the CVSS v2 base score for the CVE
    #
    #   Return:
    #
    #     cve_qualitative_severity_ranking (str) - based on PCI guidelines
    #
    ###

    def get_cve_qualitative_severity_ranking(self, cvss2_base):
        # from page 21 of
        # https://www.pcisecuritystandards.org/pdfs/asv_program_guide_v1.0.pdf
        low_min = 0.0
        low_max = 3.9
        medium_min = 4.0
        medium_max = 6.9
        high_min = 7.0
        high_max = 10.0

        if cvss2_base < low_min or cvss2_base > high_max:
            cve_qualitative_severity_ranking = "invalid"
        elif cvss2_base >= low_min and cvss2_base <= low_max:
            cve_qualitative_severity_ranking = "low"
        elif cvss2_base >= medium_min and cvss2_base <= medium_max:
            cve_qualitative_severity_ranking = "medium"
        elif cvss2_base >= high_min and cvss2_base <= high_max:
            cve_qualitative_severity_ranking = "high"

        return cve_qualitative_severity_ranking

    ###
    #   Report if the CVE failure causes a pass or fail for PCI
    #
    #   Parameters:
    #       self (obj)
    #       cve_qualitative_severity_ranking (str) - high, medium or low
    #
    #   Return:
    #       pci_compliance_status (str) - pass or fail
    #
    ###

    def get_pci_compliance_status(self, cve_qualitative_severity_ranking):
        LOW = "low"
        pci_compliance_status = "Fail"

        if cve_qualitative_severity_ranking == LOW:
            pci_compliance_status = "Pass"

        return pci_compliance_status

    ###
    #
    #   Get the status of a patch for the CVE
    #
    #   Parameters:
    #       self (obj)
    #       operating_system (str) - OS information
    #
    #   Return:
    #       patchable (str) - True or Unknown
    #
    ###

    def get_patchable_status(self, operating_system):
        windows_os = "windows"
        operating_system = operating_system.lower()
        patchable = "True"

        if windows_os in operating_system:
            patchable = "Unknown"

        return patchable

    ###
    #   Create a table that provides CVE's by year and PCI rankings of high,
    #   medium or low
    #
    #   Parameters:
    #       self (obj)
    #       scan_findings (dict) - findings from last scan in range
    #
    #   Return:
    #       cve_ranges_by_year (str) - e.g. Year: 2017 Low: 6 Medium 14
    #       High: 23
    #
    ###

    def create_yearly_cve_range_table(self, scan_findings):
        separator = "-"
        index = 1

        cve_years = ["0"]
        cve_year_populated = False
        counter = 0
        INCREMENT = 1

        for finding in scan_findings:
            # we only care about non-critical and critical issues
            if finding["status"] == "bad":
                cve_entries = finding["cve_entries"]

                # populate the years
                for cve_entry in cve_entries:
                    cve_id = cve_entry["cve_entry"]
                    cve_year = cve_id.split(separator)[index].strip()

                    for year in cve_years:
                        if cve_year in year:
                            cve_year_populated = True
                            break

                    if cve_year_populated is False:
                        cve_years.append(cve_year)

                    cve_year_populated = False

            counter = counter + INCREMENT

        # get rid of the default and sort the years
        del cve_years[0]
        cve_years.sort()

        counter = 0
        cve_ranges_by_year = {}
        NONE = 0

        for year in cve_years:
            cve_ranges_by_year[counter] = {"year": year, "low": NONE,
                                           "medium": NONE, "high": NONE,
                                           "invalid": NONE}

            counter = counter + INCREMENT

        for finding in scan_findings:
            if finding["status"] == "bad":
                cve_entries = finding["cve_entries"]

                # populate the low, medium, and high CVEs for the years
                for cve_entry in cve_entries:
                    cve_id = cve_entry["cve_entry"]
                    cve_year = cve_id.split(separator)[index].strip()
                    cve_cvss2_base = cve_entry["cvss_score"]

                    severerity_ranking =\
                        self.get_cve_qualitative_severity_ranking(
                            cve_cvss2_base)

                    counter = 0
                    INCREMENT = 1
                    items = len(cve_ranges_by_year)

                    while counter < items:
                        if cve_ranges_by_year[counter]["year"] == cve_year:
                            cve_ranges_by_year[counter][severerity_ranking] = \
                                cve_ranges_by_year[counter][severerity_ranking] + INCREMENT # NOQA
                        counter = counter + INCREMENT

        return cve_ranges_by_year

    ###
    #   Pull the RHEL CVE data from their endpoint
    #
    #   Paramaters:
    #       self (obj)
    #       cve_id (str) - CVE ID
    #
    #   Return:
    #       cve_data (dict) - CVE data in JSON
    #
    ###

    def get_rhel_cve_data(self, cve_id):
        api_url = "https://access.redhat.com/labs/securitydataapi/cve/"
        data_format_extension = ".json"
        api_url = "%s%s%s" % (api_url, cve_id, data_format_extension)

        # get data and make it useable
        cve_data = urllib2.urlopen(api_url).read()
        cve_data = json.loads(cve_data)

        return cve_data

    ###
    #   Check if the ALAS feed is older than a day
    #
    #   Parameters:
    #       self (obj)
    #       alas_feed (str) - fq path to file
    #
    #   Return:
    #       older (bool)
    #
    ###

    def file_older_than_a_day(self, alas_feed):
        day = 86400
        older = False

        now = time.time()
        alas_feed_mtime = os.path.getmtime(alas_feed)
        alas_feed_age = now - alas_feed_mtime

        if alas_feed_age > day:
            older = True

        return older

    ###
    #   Download the ALAS feed if it does not exist or is older than a day
    #
    #   Parameters:
    #       self (obj)
    #       alas_feed (str) - fq path to file
    #
    ###

    def download_alas_rss(self, alas_feed):
        alas_feed_url = \
            "https://alas.aws.amazon.com/alas.rss"

        try:
            feed_exists = os.path.exists(alas_feed)
            older = self.file_older_than_a_day(alas_feed)
        except OSError:
            feed_exists = False

        if not feed_exists or older:
            urllib.urlretrieve(alas_feed_url, alas_feed)
