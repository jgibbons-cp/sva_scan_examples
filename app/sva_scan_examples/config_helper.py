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
        string_is_int_value = isinstance(days_for_scan_age, int)

        scan_examples = os.environ["SCAN_EXAMPLES"] = "False"

        if self.halo_key is None or self.halo_secret is None \
            or not os.path.exists(scan_results_directory) or not path_exists \
                or string_is_int_value == "False" \
                or scan_examples != TRUE and scan_examples != FALSE:
                    sys.exit(ERROR)
