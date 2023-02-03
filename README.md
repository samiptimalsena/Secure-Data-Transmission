# Secure-Data-Transmission
COMP-492 assignment that demonstrates the use of AES and RSA algorithms for secure data sharing between client and server.

**AES** is used to encrypt the actual data and **RSA** is used to encrypt the AES key that is securely transferred between client and server along with the encrypted data.
The encryption of AES key is done using the public key of the server so that later the server is able to decrypt it using its own private key.

## Usage 
```
$ python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt
$ python run.py -m $MESSAGE
```

**Note**<br/>
The message passed and the response to get for successfull secure transmission is as below:
```python
   {
    "Who are you?": "I am secure data transmission service.",
    "What algorithms do you use?": "I use AES and RSA for encryption and decryption"
    }
```

For all other message passed, we get a same response as `Sorry, unable to answer this question.`
