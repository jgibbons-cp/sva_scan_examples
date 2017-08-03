from git import Repo
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

        # pull down the Halo API wrapper and manage module path
        halo_general_repo = "https://github.com/jgibbons-cp/halo_general.git"
        cwd = os.getcwd()
        repo_dir = "%s/halo_general" % cwd
        sys.path.append(repo_dir)

        # clone it if we don't have it
        if os.path.exists(repo_dir) is False:
            Repo.clone_from(halo_general_repo, repo_dir)

        try:
            from halo_general import HaloGeneral  # NOQA
        except ImportError as e:
            print "Error: %s\n" % e
            sys.exit(ERROR)

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

        days_for_scan_age = os.environ["DAYS_FOR_SCAN_AGE"] = "7"
        days_for_scan_age = int(days_for_scan_age)
        days_string_is_int_value = isinstance(days_for_scan_age, int)

        scan_examples = os.environ["SCAN_EXAMPLES"] = "False"
        heartbeat_interval = os.environ["HEARTBEAT_INTERVAL"] = "60"
        heartbeat_interval = int(heartbeat_interval)
        hi_string_is_int_value = isinstance(heartbeat_interval, int)

        # for unit tests Travis populates the IP
        server_ip = "<server_ip>"
        os.environ["SERVER_IP"] = server_ip

        os.environ["UNIT_TESTS"] = "no_unit_tests"

        if self.halo_key is None or self.halo_secret is None \
            or not os.path.exists(scan_results_directory) or not path_exists \
                or days_string_is_int_value == "False" \
                or hi_string_is_int_value == "False" \
                or scan_examples != TRUE and scan_examples != FALSE \
                or server_ip != server_ip:

                    sys.exit(ERROR)
