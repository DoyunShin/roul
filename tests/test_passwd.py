import random
import string
import unittest
from unittest.mock import patch

from roul import passwd


class PasswordTest(unittest.TestCase):
    def test_generate_uses_expected_length_and_characters(self) -> None:
        password = passwd.generate(64)

        self.assertEqual(len(password), 64)
        self.assertTrue(set(password) <= set(string.ascii_letters + string.digits))

    def test_generate_hard_uses_expected_length_and_characters(self) -> None:
        password = passwd.generate_hard(64)

        self.assertEqual(len(password), 64)
        self.assertTrue(set(password) <= set(string.ascii_letters + string.digits + string.punctuation))

    def test_generators_do_not_use_global_random_state(self) -> None:
        random.seed(42)
        initial_state = random.getstate()

        with patch("random.choice", side_effect=AssertionError("random.choice called")):
            passwd.generate(16)
            passwd.generate_hard(16)

        self.assertEqual(random.getstate(), initial_state)


if __name__ == "__main__":
    unittest.main()
