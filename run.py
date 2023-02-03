import argparse
from app.client import Client
from app.server import Server

def main():
    parser = argparse.ArgumentParser(description='Safe Data Transmission Service')
    parser.add_argument('-m','--message', help='Message to pass to the server', required=True)
    args = vars(parser.parse_args())

    # Getting message from argument parser and converting it to bytes format
    msg = bytes(args.get("message"), encoding="utf-8")

    # Initializing mock client and server
    client = Client()
    server = Server()

    # Encypting message to pass
    nonce, tag, ciphertext = client.encrypt_msg(msg)

    # Encrypting AES Key of Client using public key of the server. 
    enc_aes_key = client.encrypt_key(server.public_key)

    # Now the message encrypted with AES key and the encryped AES key with public key of server is passed to the server for reply
    # The reply is as follow:
    #  "Who are you?": "I am secure data transmission service.",
    #  "What algorithms do you use?": "I use AES and RSA for encryption and decryption",x
    # For other question asked the server replies: "Sorry, unable to answer this question."
    server_response = client.call_server(server, ciphertext, enc_aes_key, nonce, tag)
    print("\nResponse: ")
    print(server_response)
    print()

if __name__ == "__main__":
    main()

    """
    Example:
    python run.py -m "Who are you?" 
    -> b'Who are you? ==> I am secure data transmission service.'

    python run.py -m "What algorithms do you use?"
    -> b'What algorithms do you use? ==> I use AES and RSA for encryption and decryption'

    python run.py -m "Who am I?"
    -> b'Who am I? ==> Sorry, unable to answer this question.'
    """
