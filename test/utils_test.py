import unittest
import utils


class TestUtils(unittest.TestCase):
    def setUp(self):
        print("Preparando el contexto")
        self.spam = open("file_test", "r")


    # Test for spams with array of size < 30
    def test_add_1(self):
        numCaracteres, caracteres = utils.addFilter('file_test_1', 'filters_test_add.cfg')
        self.assertEqual(numCaracteres, 14)
        self.assertEqual(caracteres, [])


    def tearDown(self):
        print("Destruyendo el contexto")
        self.spam.close()


if __name__ == '__main__':
    unittest.main() 