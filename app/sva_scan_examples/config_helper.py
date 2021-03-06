import os
import sys


class ConfigHelper():
    """
        Manage all configuration information for the application
    """
    def __init__(self):
        TRUE = "True"
        FALSE = "False"
        ERROR = 1

        self.halo_key = os.getenv("HALO_API_KEY")
        self.halo_secret = os.getenv("HALO_API_SECRET_KEY")

        # get the results directory and create it if it does not exist
        scan_results_directory = os.environ["SCAN_RESULTS_DIRECTORY"] = \
            "/tmp/scan_results/"
        path_exists = os.path.exists(scan_results_directory)

        if not path_exists:
            try:
                os.mkdir(scan_results_directory)
                path_exists = os.path.exists(scan_results_directory)
            except OSError:
                pass

        days_for_scan_age = os.environ["DAYS_FOR_SCAN_AGE"] = "0"
        days_for_scan_age = int(days_for_scan_age)
        days_string_is_int_value = isinstance(days_for_scan_age, int)

        os.environ["HALO_SERVER_GROUP"] = "Git"

        scan_examples = os.environ["SCAN_EXAMPLES"] = "False"
        heartbeat_interval = os.environ["HEARTBEAT_INTERVAL"] = "60"
        heartbeat_interval = int(heartbeat_interval)
        hi_string_is_int_value = isinstance(heartbeat_interval, int)

        # for unit tests Travis populates the IP
        server_ip = "<server_ip>"
        os.environ["SERVER_IP"] = server_ip

        unit_tests = os.environ["UNIT_TESTS"] = "no_unit_tests" # NOQA

        if self.halo_key is None or self.halo_secret is None \
            or not os.path.exists(scan_results_directory) or not path_exists \
                or days_string_is_int_value == "False" \
                or hi_string_is_int_value == "False" \
                or scan_examples != TRUE and scan_examples != FALSE:
                        print "Configuration validation failed... exiting...\n"
                        sys.exit(ERROR)
