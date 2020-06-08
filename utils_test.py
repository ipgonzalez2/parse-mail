import unittest
import utils
import ConfigParser


class TestUtils(unittest.TestCase):


    # Initial configuration
    def setUp(self):
        print("Setting up context...")
        self.config = ConfigParser.RawConfigParser()
        self.config2 = ConfigParser.RawConfigParser()

        self.config.read('test/filters_test_add.cfg')
        for section in self.config.sections()[1:]:
            self.config.remove_section(section)
        with open('test/filters_test_add.cfg', 'wb') as configfile:
            self.config.write(configfile)

        self.config2.read('test/filters_test_delete.cfg')
        for section in self.config2.sections()[1:]:
            self.config2.remove_section(section)
        self.config2.add_section('Filter0')
        self.config2.set('Filter0', 'program', 'filter0.c')
        self.config2.set('Filter0', 'function', 'mail_filter_0')
        self.config2.set('Filter0', 'hash', '510676b179b68c5ffd5c9106f31f3ef584139b243ad8b00b4de25bd9ad84e105')
        with open('test/filters_test_delete.cfg', 'wb') as configfile:
            self.config2.write(configfile)



    # Test for spams with character's array of len < 30 and total size < 15000
    def test_add_1(self):
        numCaracteres1, caracteres1 = utils.addFilter('test/file_test1', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres1, 14)
        self.assertEqual(caracteres1, ['-','_','t','e','r','\n','g','I','C','W','2','J','u','B'])
        self.config.read('test/filters_test_add.cfg')
        self.assertTrue(len(self.config.sections()) == 2)


    # Test for spams with total size > 15000 and character's array of len > 30
    def test_add_2(self):
        numCaracteres, caracteres = utils.addFilter('test/file_test2', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres, 30)
        self.assertEqual(caracteres, [' ','n','\xfa',' ',' ',' ',' ','b','/','V','x','9','H','v','j','f','w','E','3','a','p','2','M','t','p','g','O','d','7','y'])
        self.config.read('test/filters_test_add.cfg')
        self.assertTrue(len(self.config.sections()) == 2)


    # Test for invalid input (anything but a mail)
    def test_add_3(self):
        numCaracteres, caracteres = utils.addFilter('test/file_test3', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres, -1)
        self.assertEqual(caracteres, [])
        self.config.read('test/filters_test_add.cfg')
        self.assertTrue(len(self.config.sections()) == 1)
    

"""
    # Test that deletes file defined
    def test_delete_1(self):
        utils.removeFilter('test/file_test1', 'test/filters_test_delete.cfg')
        self.config.read('test/filters_test_delete.cfg')
        for section in self.config.sections()[1:]:
            print(section)
        self.assertTrue(len(self.config.sections()) == 1)


    # Test that deletes file undefined
    def test_delete_2(self):
        utils.removeFilter('test/file_test2', 'test/filters_test_delete.cfg')
        self.config.read('test/filters_test_delete.cfg')
        self.assertTrue(len(self.config.sections()) == 2)

"""

    def tearDown(self):
        print("Destroying context...")


if __name__ == '__main__':
    unittest.main() 