import unittest

from app.client import Client
from app.utils import  decrypt_AES, encrypt_AES

class TestClient(unittest.TestCase):
    def setUp(self):
        self.client = Client()

    def test_gen_AES_key(self):
        # Test if the generated AES key is of correct length
        key = Client.gen_AES_key(2)
        self.assertEqual(len(key), 32)

    def test_key_property(self):
        # Test if the key property returns the correct AES key
        self.assertEqual(self.client.key, self.client._AES_key)

    def test_encrypt_msg(self):
        # Test if the encryption of message using AES key is correct
        nonce, tag, ciphertext = self.client.encrypt_msg(b"Test message")
        self.assertEqual(decrypt_AES(self.client.key, nonce, tag, ciphertext), b"Test message")


if __name__ == "__main__":
    unittest.main()