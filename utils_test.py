import unittest
import utils
import ConfigParser


class TestUtils(unittest.TestCase):
    def setUp(self):
        print("Preparando el contexto")
        self.config = ConfigParser.RawConfigParser()
        self.config.read('test/filters_test_add.cfg')
        for section in self.config.sections()[1:]:
            self.config.remove_section(section)
        with open('test/filters_test_add.cfg', 'wb') as configfile:
            self.config.write(configfile)


    # Test for spams with array of size < 30 and size > 15000
    def test_add(self):
        numCaracteres1, caracteres1 = utils.addFilter('test/file_test1', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres1, 14)
        self.assertEqual(caracteres1, ['-','_','t','e','r','\n','g','I','C','W','2','J','u','B'])
        numCaracteres2, caracteres2 = utils.addFilter('test/file_test2', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres2, 30)
        self.assertEqual(caracteres2, [' ','n','\xfa',' ',' ',' ',' ','b','/','V','x','9','H','v','j','f','w','E','3','a','p','2','M','t','p','g','O','d','7','y'])
        self.config.read('test/filters_test_add.cfg')
        self.assertTrue(len(self.config.sections()) == 3)


    def tearDown(self):
        print("Destruyendo el contexto")


if __name__ == '__main__':
    unittest.main() 