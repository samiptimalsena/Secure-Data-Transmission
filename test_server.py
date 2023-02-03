import os
import unittest

from Crypto.PublicKey import RSA

from app.utils import encrypt_RSA, decrypt_RSA, load_RSA_key, save_RSA_key
from app.server import Server


class TestServer(unittest.TestCase):
    def setUp(self):
        self.server = Server()

    def tearDown(self):
        # Remove RSA keys from disk after each test
        os.remove("app/keys/RSA/private.pem")
        os.remove("app/keys/RSA/public.pem")

    def test_gen_RSA_key(self):
        pr_key, pb_key = self.server.gen_RSA_key()
        save_RSA_key(pr_key, "app/keys/RSA/private.pem")
        save_RSA_key(pb_key, "app/keys/RSA/public.pem")
        pr_key = load_RSA_key("app/keys/RSA/private.pem")
        pb_key = load_RSA_key("app/keys/RSA/public.pem")

        self.assertIsInstance(pr_key, RSA.RsaKey)
        self.assertIsInstance(pb_key, RSA.RsaKey)


    def test_public_key(self):
        pb_key = self.server.public_key
        self.assertIsInstance(pb_key, RSA.RsaKey)

    def test_get_AES(self):
        # Generate an AES key and encrypt it with the server public key
        AES_key = os.urandom(16)
        enc_AES = encrypt_RSA(self.server.public_key, AES_key)
        # Decrypt the AES key using the server private key
        decrypted_AES = self.server.get_AES(enc_AES)
        self.assertEqual(AES_key, decrypted_AES)

if __name__ == '__main__':
    unittest.main()