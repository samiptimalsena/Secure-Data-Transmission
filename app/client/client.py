from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from glob import glob

from app.utils import encrypt_AES, decrypt_AES,save_AES_key, load_AES_key, encrypt_RSA

class Client:
    """
    A Mock client
    """
    def __init__(self, key_size:int = 2):
        if not glob("app/keys/AES/*.pem"):
            # If the key is not already present inside keys direction, it is generated here.
            print("New aes key generated")
            self._AES_key = self.gen_AES_key(key_size)
            # cipher = AES.new(self._AES_key, AES.MODE_EAX)
            save_AES_key(self._AES_key, "app/keys/AES/key.pem")
        else:
            # Loading the saved key
            self._AES_key = load_AES_key("app/keys/AES/key.pem")
    
    @classmethod
    def gen_AES_key(cls, key_size):
        key = get_random_bytes(AES.key_size[key_size])
        return key

    @property
    def key(self):
        return self._AES_key

    def encrypt_msg(self, msg:bytes) -> None:
        """
        Encryping the messaage using AES key

        Args:
            msg: Message to encrypt
        Returns:
            None
        """
        nonce, tag, ciphertext = encrypt_AES(self.key, msg)
        return nonce, tag, ciphertext 
    
    def encrypt_key(self, pb_key:str) -> str:
        """
        Encrypting the AES key using the server's public key

        Args:
            pb_key: Public key of the server

        Returns:
            key_enc: Encoded AES key
        """
        key_enc = encrypt_RSA(pb_key, self.key)
        return key_enc

    def call_server(self, server, msg, enc_aes_key, nonce, tag):
        """
        Calling the server for the response
        """
        nonce_r, tag_r, ciphertext_r = server.reply(msg, enc_aes_key, nonce, tag)
        reply_msg = decrypt_AES(self._AES_key, nonce_r, tag_r, ciphertext_r)
        return reply_msg
