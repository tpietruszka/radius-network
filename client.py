#!/usr/bin/python2.7
# encoding: utf-8
import utils
import getpass
from auth.client import client


config_file = "config/client.json"
config_vars = ["hostName", "authPort", "sharedSecret", "retryCount", "socketTimeout"]

config = utils.parseConfig(config_file, config_vars)
    
c = client(config['hostName'], config['authPort'], "config['sharedSecret']",
            config['retryCount'], config['socketTimeout'])


user_name = raw_input("user name: ")
password = getpass.getpass("password: ")

result = c.authorize(user_name, password)
print result

