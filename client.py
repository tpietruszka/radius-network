#!/usr/bin/python2.7
# encoding: utf-8
import utils
import getpass
from auth.client import client


config_file = "config/client.json"
config_vars = ["hostName", "authPort", "sharedSecret", "retryCount", "socketTimeout"]

config = utils.parseConfig(config_file, config_vars)
    
c = client(config['hostName'], config['authPort'], config['sharedSecret'],
            config['retryCount'], config['socketTimeout'])


password = str("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
authenticator = c.generate_authenticator()
encrypted = c.encrypt(authenticator, password)
print encrypted
decrypted = c.decrypt(authenticator, encrypted)
print decrypted

# user_name = raw_input("user name: ")
# password = getpass.getpass("password: ")

user_name  = "User"
# password = "PasswordX"

result = c.authorize(user_name, password)
print result

