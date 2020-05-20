import unittest
import utils


class TestUtils(unittest.TestCase):
    def setUp(self):
        print("Preparando el contexto")
        self.spam = open("file_test", "r")


    def tearDown(self):
        print("Destruyendo el contexto")
        self.spam.close()


if __name__ == '__main__':
    unittest.main() 