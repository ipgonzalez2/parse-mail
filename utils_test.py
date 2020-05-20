import unittest
import utils
import ConfigParser


class TestUtils(unittest.TestCase):
    def setUp(self):
        print("Preparando el contexto")
        self.config = ConfigParser.RawConfigParser()


    # Test for spams with array of size < 30
    def test_add_1(self):
        numCaracteres, caracteres = utils.addFilter('test/file_test1', 'test/filters_test_add.cfg')
        self.assertEqual(numCaracteres, 14)
        self.assertEqual(caracteres, ['-','_','t','e','r','\n','g','I','C','W','2','J','u','B'])
        self.config.read('test/filters_test_add.cfg')
        self.assertTrue(len(self.config.sections()) == 2)



    def tearDown(self):
        print("Destruyendo el contexto")


if __name__ == '__main__':
    unittest.main() 