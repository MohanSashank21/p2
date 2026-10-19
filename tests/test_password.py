import unittest

from app.utils.password import hash_password, verify_password


class PasswordTests(unittest.TestCase):
  def test_hash_password_does_not_return_plain_password(self):
    password = "correct horse battery staple"

    hashed_password = hash_password(password)

    self.assertNotEqual(hashed_password, password)
    self.assertTrue(verify_password(password, hashed_password))

  def test_verify_password_rejects_wrong_password(self):
    hashed_password = hash_password("correct horse battery staple")

    self.assertFalse(verify_password("incorrect password", hashed_password))

  def test_hash_password_rejects_empty_password(self):
    with self.assertRaises(ValueError):
      hash_password("")

  def test_verify_password_rejects_empty_inputs(self):
    self.assertFalse(verify_password("", "some-hash"))
    self.assertFalse(verify_password("some-password", ""))


if __name__ == "__main__":
  unittest.main()
