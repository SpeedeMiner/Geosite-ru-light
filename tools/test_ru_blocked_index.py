import unittest
from ru_blocked_index import DirectPrefixIndex, normalize_domain


class Tests(unittest.TestCase):
    def test_normalization_and_validation(self):
        self.assertEqual(normalize_domain(' \u041f\u0420\u0418\u041c\u0415\u0420.\u0420\u0424. '), 'xn--e1afmkfd.xn--p1ai')
        for invalid in ('a', 'bad..example', '-a.example', 'http://x.example', 'x_.example', 'xn--.example'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_domain(invalid)

    def test_membership_and_public_address_filter(self):
        idx = DirectPrefixIndex(['8.8.8.0/24', '8.8.8.128/25', '1.1.1.0/24', '2001:4860::/32', '10.0.0.0/8'])
        self.assertTrue(idx.contains('8.8.8.8'))
        self.assertTrue(idx.contains('2001:4860:4860::8888'))
        self.assertFalse(idx.contains('8.8.9.1'))
        self.assertFalse(idx.contains('10.0.0.1'))
        self.assertFalse(idx.contains('127.0.0.1'))


if __name__ == '__main__':
    unittest.main()

