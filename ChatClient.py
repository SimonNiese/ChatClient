import errno
import json
import os.path
import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class PublicKey:
    def __init__(self, username, public_key):
        self.username = username
        self.publicKey = public_key


class ChatMessage:
    def __init__(self, sender, recipient, message, signature):
        self.sender = sender
        self.recipient = recipient
        self.message = message
        self.signature = signature


def post_public_key(server_url, public_key: PublicKey):
    response = requests.post(server_url + "/user", json=public_key.__dict__)
    print(response.text)


def get_public_key(server_url, username):
    key = requests.get(server_url + "/user/" + username).text
    return key


def generate_keys():
    key = RSA.generate(4096)
    with open('privkey.pem', 'wb') as f:
        f.write(key.exportKey('PEM'))
    with open('pubkey.pem', 'wb') as f:
        f.write(key.publickey().exportKey('PEM'))


def sign_message(message):
    try:
        with open('privkey.pem', 'r') as f:
            key = RSA.importKey(f.read())
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    hasher = SHA512.new(message)
    signer = PKCS1_v1_5.new(key)
    return signer.sign(hasher)


def verify_signature(message, signature, server_url, username):
    key = get_public_key(server_url, username)
    hasher = SHA512.new(bytearray.fromhex(message))
    verifier = PKCS1_v1_5.new(RSA.import_key(key))
    if verifier.verify(hasher, bytearray.fromhex(signature)):
        return True
    else:
        return False


def encrypt_message(message, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    return encryptor.encrypt(message)


def decrypt_message(message):
    with open('privkey.pem', 'r') as f:
        key = RSA.importKey(f.read())
    decryptor = PKCS1_OAEP.new(key)
    return decryptor.decrypt(bytearray.fromhex(message))


def send_message(message, sender, recipient, server_url):
    response = str(get_public_key(server_url, recipient))
    key = RSA.import_key(response)
    encrypted_message = encrypt_message(message.encode("utf-8"), key)
    signature = sign_message(encrypted_message)
    chat_message = ChatMessage(sender=sender, recipient=recipient, message=encrypted_message.hex(), signature=signature.hex()).__dict__
    print(chat_message)
    requests.post(server_url + "/chat", json=chat_message)


def receive_messages(server_url, username):
    messages = requests.get(server_url + "/chat/" + username).text
    if messages is None:
        return
    for message in json.loads(messages):
        if verify_signature(message['message'], message['signature'], server_url, message['sender']):
            print(message['sender'] + ":", decrypt_message(message['message']).decode())
        else:
            print(message['sender'] + "[signature verification failed]:", decrypt_message(message['message']).decode())


def write_message(sender, server_url):
    recipient = input("Recipient: ")
    message = input("Message: ")
    send_message(message=message, recipient=recipient, sender=sender, server_url=server_url)


server = "https://chat.digitalhyena.io"
username = input("Username: ")

if not os.path.exists("privkey.pem"):
    print("Generating new keypair...")
    generate_keys()
    print("Uploading keypair...")
    with open("pubkey.pem", "r") as f:
        post_public_key(server, PublicKey(username, str(f.read())))



while True:
    prompt = input("Command(Send, Receive, Exit): ")
    if prompt == "Send" or prompt == "send":
        write_message(username, server)
    elif prompt == "Receive" or prompt == "receive":
        receive_messages(server, username)
    elif prompt == "Exit" or prompt == "exit":
        exit()
    else:
        print("Command not recognized!")
