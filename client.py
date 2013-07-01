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

user_name = raw_input("user name: ")
password = getpass.getpass("password: ")

try:
    (authorized, message) = c.authorize(user_name, password)
    if authorized: print "access GRANTED" 
    else: print "access DENIED"
    if(len(message)> 0):
        print message
    
except TimeoutError as e:
    print str(e)


