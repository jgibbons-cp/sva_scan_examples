import os


class ConfigHelper():
    """
        Manage all configuration information for the application
    """
    def __init__(self):

        self.halo_key = os.getenv("HALO_API_KEY")
        self.halo_secret = os.getenv("HALO_API_SECRET_KEY")

        os.environ["SCAN_RESULTS_DIRECTORY"] = "/tmp/scan_results/"
