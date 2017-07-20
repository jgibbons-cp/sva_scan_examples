import os
import sys
import imp
import unittest

# import modules
here_dir = os.path.dirname(os.path.abspath(__file__))

module_name = 'config_helper'
module_path = os.path.join(here_dir, '../../sva_scan_examples')
sys.path.append(module_path)
fp, pathname, description = imp.find_module(module_name)
config = imp.load_module(module_name, fp, pathname, description)


class TestConfigHelper(unittest.TestCase):
    '''
           Test the configuration
    '''
    def setUp(self):
        pass

    def test_server_group_config(self):
        '''
            Test if the variable is set
        '''

        # error if the configuration is not set
        with self.assertRaises(SystemExit):
            config.ConfigHelper()


if __name__ == '__main__':
    unittest.main()
