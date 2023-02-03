from glob import glob
from app.utils import generate_RSA_key, encrypt_RSA, decrypt_RSA, load_RSA_key, save_RSA_key, decrypt_AES, encrypt_AES

class Server:
    """
    A Mock server
    """
    def __init__(self):
        if not glob("app/keys/RSA/*.pem"):
            # If the key is not already present inside keys direction, it is generated here.
            print("New rsa key generated")
            pr_key, pb_key = self.gen_RSA_key()
            save_RSA_key(pr_key, "app/keys/RSA/private.pem")
            save_RSA_key(pb_key, "app/keys/RSA/public.pem")

        # Loading the saved key
        self._pr_key = load_RSA_key("app/keys/RSA/private.pem")
        self._pb_key = load_RSA_key("app/keys/RSA/public.pem")

    @classmethod
    def gen_RSA_key(cls):
        pr_key, pb_key = generate_RSA_key()
        return pr_key, pb_key
    
    @property
    def public_key(self):
        return self._pb_key

    def get_AES(self, enc_AES:str) -> str:
        """
        Decrypting the AES key which has been encrpted using server public key

        Args:
            enc_AES: encoded AES key

        Returns:
            Decrypted AES key using server private key
        """
        AES_key = decrypt_RSA(self._pr_key, enc_AES)
        return AES_key
    
    def reply(self, ciphertext, enc_aes_key, nonce, tag):
        """
        Response from the server.
        """
        reply_dict = {
            "Who are you?": "I am secure data transmission service.",
            "What algorithms do you use?": "I use AES and RSA for encryption and decryption",
        }
        AES_key = self.get_AES(enc_aes_key)
        actual_message = decrypt_AES(AES_key, nonce, tag, ciphertext)
        reply_msg = actual_message + b" ==> " + bytes(reply_dict.get(actual_message.decode(), "Sorry, unable to answer this question."), encoding="utf-8")
        nonce_r, tag_r, ciphertext_r =  encrypt_AES(AES_key, reply_msg)
        return nonce_r, tag_r, ciphertext_r

