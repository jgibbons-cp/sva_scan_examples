import os
import sys
import imp
import time
from datetime import datetime
import unittest


# import modules
here_dir = os.path.dirname(os.path.abspath(__file__))

module_name = 'config_helper'
module_path = os.path.join(here_dir, '../../sva_scan_examples')
sys.path.append(module_path)
fp, pathname, description = imp.find_module(module_name)
config = imp.load_module(module_name, fp, pathname, description)

module_name = 'halo_general'
module_path = os.path.join(here_dir, './halo_general')
sys.path.append(module_path)
fp, pathname, description = imp.find_module(module_name)
halo_general = imp.load_module(module_name, fp, pathname, description)

module_name = 'sva_scan_examples'
module_path = os.path.join(here_dir,
                           '../../sva_scan_examples/sva_scan_examples')
sys.path.append(module_path)
fp, pathname, description = imp.find_module(module_name)
sva_scan_examples = imp.load_module(module_name, fp, pathname, description)


class Test_SVA_ScanExamples(unittest.TestCase):
    '''
           Test the scan examples
    '''

    # get a config and halo object
    halo_config = config.ConfigHelper()
    halo = halo_general.HaloGeneral(halo_config)

    # flag so sva_scan_examples in init only runs if it is not unit testing
    os.environ["UNIT_TESTS"] = "True"
    unit_tests = os.getenv("UNIT_TESTS")
    host_ip = os.getenv("SERVER_IP")

    # location of alas feed
    alas_feed = "/tmp/alas.rss"

    # init class object
    sva_scan_examples_obj = sva_scan_examples.SVA_ScanExamples(halo)

    # get server ID and scan results - here
    server_id = \
        sva_scan_examples_obj.get_server_id(halo, host_ip)
    scan_results = sva_scan_examples_obj.scan_server(server_id)

    def setUp(self):
        pass

    def test_download_alas_rss(self):
        '''
            Test downloading of rss feed for ALAS
        '''

        self.sva_scan_examples_obj.download_alas_rss(self.alas_feed)
        self.assertTrue(os.path.exists(self.alas_feed))

    def test_sva_scan_examples(self):
        '''
            Test sva scan examples
        '''

        test_file = "./halo_sva_report_test.csv"
        test_string = "test"

        self.sva_scan_examples_obj.halo_sva_scan_examples(self.host_ip,
                                                          test_string)

        # success if the file is created - then removed
        self.assertTrue(os.path.exists(test_file))
        os.remove(test_file)

    def test_sva_scan_examples_fake_ip(self):
        '''
            Test with a fake IP
        '''

        ip_address = "1.1.1.1"
        test_file = "./halo_sva_report_test.csv"
        test_string = "test"

        self.sva_scan_examples_obj.halo_sva_scan_examples(ip_address,
                                                          test_string)

        # succeeds if file was not created
        self.assertFalse(os.path.exists(test_file))

    def test_sva_scan_examples_no_agent(self):
        '''
            Test with a workload with no agent
        '''
        test_file = "./halo_sva_report_test.csv"
        test_string = "test"
        ip_address = "8.8.8.8"

        self.sva_scan_examples_obj.halo_sva_scan_examples(ip_address,
                                                          test_string)

        # succcess if false
        self.assertFalse(os.path.exists(test_file))

    def test_configure_scan_results_directory(self):
        '''
            Test to ensure the scan results directory is created and there
        '''

        self.sva_scan_examples_obj.configure_scan_results_directory()

        # succeeds if it exists
        scan_results_dir = os.getenv("SCAN_RESULTS_DIRECTORY")
        self.assertTrue(os.path.exists(scan_results_dir))

    def test_get_server_id(self):
        '''
            Test that can grab server ID
        '''

        server_id = None

        server_id = \
            self.sva_scan_examples_obj.get_server_id(self.halo,
                                                     self.host_ip)

        # succeeds if ID is populated
        self.assertIsNotNone(server_id)

    def test_get_server_id_fake_ip(self):
        '''
            Test that can grab server ID
        '''
        server_id = None
        server_ip = "1.1.1.1"

        server_id = \
            self.sva_scan_examples_obj.get_server_id(self.halo, server_ip)

        # succeeds if not populated
        self.assertIsNone(server_id)

    def test_get_server_id_no_agent(self):
        '''
            Test with a host with no agent
        '''
        server_id = None
        ip_address = "1.1.1.1"
        server_id = \
            self.sva_scan_examples_obj.get_server_id(self.halo, ip_address)

        # success if not populated
        self.assertIsNone(server_id)

    def test_scan_server(self):
        '''
            Confirm get scan results
        '''

        self.assertIsNot(self.scan_results, [])

    def test_get_scan_findings(self):
        '''
            Confirm get scan details
        '''

        SCAN = "scan"
        ID = "id"
        FINDINGS = "findings"

        # scan details
        scan_id = self.scan_results[SCAN][ID]

        scan_details = self.sva_scan_examples_obj.get_scan_details(scan_id)

        scan_findings = scan_details[FINDINGS]

        # success if populated
        self.assertIsNot(scan_findings, [])

    def test_get_scan_details(self):
        '''
            Confirm get details
        '''
        SCAN = "scan"
        ID = "id"

        # scan details
        scan_id = self.scan_results[SCAN][ID]

        scan_details = self.sva_scan_examples_obj.get_scan_details(scan_id)

        # confirm is populated
        self.assertIsNot(scan_details, [])

    def test_get_last_hearbeat_time(self):
        run = False
        if run:
            heartbeat_interval = os.getenv("HEARTBEAT_INTERVAL")
            heartbeat_interval = int(heartbeat_interval)

            # get a server object and server data
            halo_server_obj = self.halo.get_server_obj()

            server_id = \
                self.sva_scan_examples_obj.get_server_id(self.halo,
                                                         self.host_ip)
            server_data = \
                self.halo.describe_server(halo_server_obj, server_id)

            # get time now and subtract time of last heartbeat
            now = datetime.utcnow()
            time_of_last_heartbeat = \
                self.sva_scan_examples_obj.get_last_hearbeat_time(server_data)

            time_of_last_heartbeat = \
                time.strptime(time_of_last_heartbeat,
                              '%Y-%m-%dT%H:%M:%S.fZ')

            time_of_last_heartbeat = \
                datetime.fromtimestamp(time.mktime(time_of_last_heartbeat))
            time_since_last_heartbeat = \
                ((now - time_of_last_heartbeat)).total_seconds()

            # fails if greater than heartbeat interval
            if time_since_last_heartbeat > heartbeat_interval:
                raise ValueError("Invalid response from get_last_heartbeat")
        else:
            pass

    def test_get_cve_qualitative_severity_ranking(self):
        '''
            Tests PCI low, medium and high CVSS rankings
        '''
        cve_qualitative_severity_ranking = ""

        # test for invalid
        cvss2_base = -0.1
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "invalid")

        # test for low
        cvss2_base = 0.0
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "low")

        cvss2_base = 3.9
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "low")

        # test for medium
        cvss2_base = 4.0
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "medium")

        cvss2_base = 6.9
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "medium")

        # test for high
        cvss2_base = 7.0
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "high")

        cvss2_base = 10.0
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "high")

        # test for invalid
        cvss2_base = 10.1
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_cve_qualitative_severity_ranking(
                cvss2_base)
        self.assertIs(cve_qualitative_severity_ranking, "invalid")

    def test_get_pci_compliance_status(self):
        '''
            Test for PCI failure
        '''

        # should pass only when low
        cve_qualitative_severity_ranking = "low"
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_pci_compliance_status(
                cve_qualitative_severity_ranking)
        self.assertIs(cve_qualitative_severity_ranking, "Pass")

        cve_qualitative_severity_ranking = "high"
        cve_qualitative_severity_ranking = \
            self.sva_scan_examples_obj.get_pci_compliance_status(
                cve_qualitative_severity_ranking)
        self.assertIs(cve_qualitative_severity_ranking, "Fail")

    def test_get_patchable_status(self):
        '''
            Test patchable - all Linux CVE's have patches we don't know for
            Windows
        '''
        operating_system = "Windows"
        patchable = \
            self.sva_scan_examples_obj.get_patchable_status(operating_system)
        self.assertIs(patchable, "Unknown")

        operating_system = "Linux"
        patchable = \
            self.sva_scan_examples_obj.get_patchable_status(operating_system)
        self.assertIs(patchable, "True")

    def test_create_yearly_cve_range_table(self):
        # test scan findings
        scan_findings = [{
                            "status": "bad",
                            "package_name": "git.x86_64",
                            "url": "https://api.cloudpassage.com",
                            "package_version": "2.7.4-1.47.amzn1",
                            "cpe": "not_found",
                            "critical": "true",
                            "cve_entries": [
                                {
                                    "cve_entry": "CVE-2017-8386",
                                    "cvss_score": 6.5,
                                    "suppressed": "false"
                                }
                            ],
                            "id": "f8b9ac46770911e7bae17b4f949c8942"
                        },
                        {
                            "status": "bad",
                            "package_name": "glibc-common.x86_64",
                            "url": "https://api.cloudpassage.com",
                            "package_version": "2.17-157.169.amzn1",
                            "cpe": "not_found",
                            "critical": "true",
                            "cve_entries": [
                                {
                                    "cve_entry": "CVE-2017-1000366",
                                    "cvss_score": 7.2,
                                    "suppressed": "false"
                                }
                            ],
                            "id": "f85c9092770911e7bae17b4f949c8942"
                        },
                        {
                            "status": "bad",
                            "package_name": "glibc-devel.x86_64",
                            "url": "https://api.cloudpassage.com",
                            "package_version": "2.17-157.169.amzn1",
                            "cpe": "not_found",
                            "critical": "true",
                            "cve_entries": [
                                {
                                    "cve_entry": "CVE-2016-1000366",
                                    "cvss_score": 7.2,
                                    "suppressed": "false"
                                }
                            ],
                            "id": "f8aa9b20770911e7bae17b4f949c8942"
                        },
                        {
                            "status": "bad",
                            "package_name": "glibc-headers.x86_64",
                            "url": "https://api.cloudpassage.com",
                            "package_version": "2.17-157.169.amzn1",
                            "cpe": "not_found",
                            "critical": "true",
                            "cve_entries": [
                                {
                                    "cve_entry": "CVE-2014-1000366",
                                    "cvss_score": 7.2,
                                    "suppressed": "false"
                                }
                            ],
                            "id": "f8df90c8770911e7bae17b4f949c8942"
                        },
                        {
                            "status": "bad",
                            "package_name": "glibc.x86_64",
                            "url": "https://api.cloudpassage.com",
                            "package_version": "2.17-157.169.amzn1",
                            "cpe": "not_found",
                            "critical": "true",
                            "cve_entries": [
                                {
                                    "cve_entry": "CVE-2014-1000366",
                                    "cvss_score": 7.2,
                                    "suppressed": "false"
                                }
                            ],
                            "id": "f819e0f8770911e7bae17b4f949c8942"
                        }]

        cve_ranges_by_year = \
            self.sva_scan_examples_obj.create_yearly_cve_range_table(
                scan_findings)

        counter = 0
        INCREMENT = 1
        max = len(cve_ranges_by_year)
        cve_ranges = ""

        while counter < max:
            cve_ranges += "Year: %s Low: %s Medium %s High: %s " \
                         % (cve_ranges_by_year[counter]["year"],
                            cve_ranges_by_year[counter]["low"],
                            cve_ranges_by_year[counter]["medium"],
                            cve_ranges_by_year[counter]["high"])

            cve_ranges = "%s" % cve_ranges
            counter = counter + INCREMENT

        # will test if data comes back as expected
        expected_response = "Year: 2014 Low: 0 Medium 0 High: 2 Year: 2016 " \
                            "Low: 0 Medium 0 High: 1 Year: 2017 Low: 0 " \
                            "Medium 1 High: 1 "
        self.assertEqual(cve_ranges, expected_response)

    def test_get_rhel_cve_data(self):
        '''
            confirm RHEL data populates
        '''
        cve_id = "CVE-2017-7895"

        rhel_cve_data = self.sva_scan_examples_obj.get_rhel_cve_data(cve_id)
        rhel_cve_data = str(rhel_cve_data)

        self.assertIsNot(rhel_cve_data, [])

    def file_older_than_a_day(self):
        '''
            Confirm the test file reports as not older than a day
        '''
        older = \
            self.sva_scan_examples_obj.file_older_than_a_day(self.alas_feed)

        self.assertFalse(older)


if __name__ == '__main__':
    unittest.main()
