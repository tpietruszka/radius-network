#!/usr/bin/env python
# encoding: utf-8
import utils
import getpass
from auth.client import Client
from auth import packet, TimeoutError


config_file = "config/client.json"
config_vars = ["hostName", "authPort", "sharedSecret", "retryCount", "socketTimeout"]

config = utils.parseConfig(config_file, config_vars)
    
c = Client(config['hostName'], config['authPort'], config['sharedSecret'],
            config['retryCount'], config['socketTimeout'])


# testy (de)szyfrowania
# password = str("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
# authenticator = c.generate_authenticator()
# secret = "elkaSecret"
# encrypted = packet.encrypt(secret, authenticator, password)
# print encrypted
# decrypted = packet.decrypt(secret, authenticator, encrypted)
# print decrypted

# user_name = raw_input("user name: ")
# password = getpass.getpass("password: ")

user_name  = "User"
password = "Password"

try:
    result = c.authorize(user_name, password)
    print result
except TimeoutError as e:
    print str(e)


